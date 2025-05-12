import base64
import boto3
import json
import mimetypes
import os
import time

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, EndpointConnectionError
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional


class AWSSessionManager:
    def __init__(self, region_name: str, service_name=None):
        self.region_name = region_name
        self.service_name = service_name
        self.session = None
        self.client = None
        self._initialize_session()

    def _initialize_session(self):
        try:
            self.session = boto3.Session(region_name=self.region_name)
            self.client = self.session.client(self.service_name)
        except (NoCredentialsError, BotoCoreError) as err:
            raise ValueError(f"failed to create AWS session for {self.service_name}: {err}")

    def get_client(self):
        if not self.client:
            raise RuntimeError(f"{self.service_name.upper()} client is not initialized.")

        return self.client


class EKSClusterFetcher(AWSSessionManager):
    def __init__(self, region_name: str):
        super().__init__(region_name, service_name="eks")
        self.eks_client = self.get_client()

    def list_all_clusters(self) -> List[str]:
        clusters = []
        try:
            paginator = self.eks_client.get_paginator('list_clusters')
            for page in paginator.paginate():
                clusters.extend(page.get('clusters', []))
        except (ClientError, EndpointConnectionError, BotoCoreError) as err:
            raise ValueError(f"failed to list EKS clusters: {err}")
        return clusters

    def describe_cluster(self, name: str) -> Dict:
        try:
            response = self.eks_client.describe_cluster(name=name)
            return response.get('cluster', {})
        except self.eks_client.exceptions.ResourceNotFoundException:
            print(f"Cluster '{name}' not found")
            return {"name": name, "status": "NOT_FOUND"}
        except (ClientError, EndpointConnectionError, BotoCoreError) as err:
            print(f"Failed to describe cluster '{name}': {err}")
            return {"name": name, "status": "ERROR"}

    def get_clusters_by_status(self) -> Dict[str, List[str]]:
        cluster_names = self.list_all_clusters()
        status_map = defaultdict(list)

        for name in cluster_names:
            cluster_info = self.describe_cluster(name)
            status = cluster_info.get("status", "UNKNOWN")
            status_map[status].append(name)

        return dict(status_map)

    def print_eks_clusters_by_status(self):
        clusters_by_status = self.get_clusters_by_status().items()
        if not clusters_by_status:
            print("No clusters found")
            return

        for status, clusters in clusters_by_status:
            print(f"Detected EKS cluster with status: {status} - {len(clusters)} clusters")
            for cluster in clusters:
                print(f" - {cluster}")


class EBSVolumeFetcher(AWSSessionManager):
    def __init__(self, region_name: str):
        super().__init__(region_name, service_name="ec2")
        self.ec2_client = self.get_client()

    def list_orphaned_volumes(self) -> List[Dict]:
        try:
            response = self.ec2_client.describe_volumes(
                Filters=[
                    {"Name": "status", "Values": ["available", "error"]}
                ]
            )
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to fetch orphaned volumes: {err}")

        volumes = []
        for vol in response.get("Volumes", []):
            tags = vol.get("Tags", [])
            name_tags = [
                tag["Value"]
                for tag in tags
                if tag["Key"] in ["Name", "kubernetes.io/created-for/pvc/name"]
            ]

            volumes.append({
                "CreateTime": vol.get("CreateTime", datetime.min).isoformat(),
                "AvailabilityZone": vol.get("AvailabilityZone", ""),
                "VolumeId": vol.get("VolumeId", ""),
                "Name": " ".join(name_tags),
                "State": vol.get("State", ""),
                "VolumeType": vol.get("VolumeType", ""),
                "SizeGiB": f"{vol.get('Size', 0)}GiB"
            })

        return volumes

    def print_orphaned_volumes(self):
        volumes = self.list_orphaned_volumes()
        if not volumes:
            print("No orphaned volumes found")
            return

        print("Orphaned volumes detected:")
        for vol in volumes:
            print(
                f"{vol['CreateTime']} | {vol['AvailabilityZone']} | {vol['VolumeId']} "
                f"| {vol['Name']} | {vol['State']} | {vol['VolumeType']} | {vol['SizeGiB']}"
            )


class S3BucketManager(AWSSessionManager):
    def __init__(self, region_name: str):
        super().__init__(region_name, service_name="s3")
        self.s3_client = self.get_client()
        self.s3_resource = boto3.resource('s3', region_name=region_name)

    def create_bucket(self, bucket_name: str):
        try:
            self.s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': self.region_name}
            )
            print(f"S3 bucket '{bucket_name}' created.")
        except self.s3_client.exceptions.BucketAlreadyOwnedByYou:
            print(f"S3 bucket '{bucket_name}' already exists and is owned by you.")
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to create S3 bucket '{bucket_name}': {err}")

    def set_public_block(self, bucket_name: str):
        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"Public access block applied to bucket '{bucket_name}'.")
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to block public access for bucket '{bucket_name}': {err}")

    def apply_lifecycle_policy(self, bucket_name: str, expiration_days: int):
        lifecycle_config = {
            "Rules": [
                {
                    "ID": "auto delete objects",
                    "Filter": {},
                    "Status": "Enabled",
                    "Expiration": {"Days": expiration_days}
                }
            ]
        }

        try:
            self.s3_client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration=lifecycle_config
            )
            print(f"Lifecycle policy applied to bucket '{bucket_name}'.")
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to apply lifecycle policy: {err}")

    def sync_directory_to_bucket(self, local_path: str, bucket_name: str):
        bucket = self.s3_resource.Bucket(bucket_name)

        for root, _, files in os.walk(local_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, start=local_path)
                content_type = mimetypes.guess_type(full_path)[0] or "binary/octet-stream"

                try:
                    bucket.upload_file(
                        Filename=full_path,
                        Key=rel_path,
                        ExtraArgs={'ContentType': content_type}
                    )
                    print(f"Uploaded {rel_path} to bucket '{bucket_name}'.")
                except (ClientError, BotoCoreError) as err:
                    raise RuntimeError(f"failed to upload '{rel_path}': {err}")


class ECRManager(AWSSessionManager):
    IMPORTANT_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "UNDEFINED"}
    IGNORED_SEVERITIES = {"LOW"}

    def __init__(self, region_name: str, public: bool = False):
        """
        Initializes ECRLoginManager.

        Args:
            region_name (str): AWS region name.
            public (bool): If True, connects to AWS ECR Public service instead of private ECR.
        """
        service_name = "ecr-public" if public else "ecr"
        super().__init__(region_name, service_name=service_name)
        self.ecr_client = self.get_client()
        self.public = public

    def get_login_credentials(self) -> Dict[str, str]:
        """
        Retrieves login credentials for Docker to authenticate with AWS ECR.

        Returns:
            A dictionary containing:
                - username: usually "AWS"
                - password: decoded token to be passed to Docker
                - proxy_endpoint: the ECR (private or public) registry URL
        """
        try:
            if self.public:
                # For public ECR
                auth_data = self.ecr_client.get_authorization_token()
                token = auth_data["authorizationData"]["authorizationToken"]
                proxy_endpoint = "https://public.ecr.aws"
            else:
                # For private ECR
                auth_data = self.ecr_client.get_authorization_token()
                token = auth_data["authorizationData"][0]["authorizationToken"]
                proxy_endpoint = auth_data["authorizationData"][0]["proxyEndpoint"]

            # Decode the base64 token ("AWS:<password>")
            decoded_token = base64.b64decode(token).decode("utf-8")
            username, password = decoded_token.split(":", 1)

            return {
                "username": username,
                "password": password,
                "proxy_endpoint": proxy_endpoint
            }
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to get ECR login credentials: {err}")

    def scan_image(self,
                   ecr_repository_name,
                   image_tag: str, skip_cves: Optional[List[str]] = None, sleep_interval: int = 3) -> Dict[str, any] | None:
        """
        Continuously polls ECR image scan status until it's COMPLETE or FAILED.

        Args:
            ecr_repository_name (str): Name of the ECR repository.
            image_tag (str): Docker image tag to scan.
            skip_cves (List[str], optional): List of CVEs to ignore.
            sleep_interval (int): Polling interval in seconds.

        Returns:
            dict with scan results, similar to bash logic.
        """
        if self.public:
            print("Skipping image scan: public ECR does not support scanning.")
            return {
                "status": "SKIPPED",
                "important_count": 0,
                "skipped_cves": [],
                "ignored_count": 0,
                "severity_counts": {},
                "all_findings": [],
            }

        try:
            response = self.ecr_client.describe_repositories(repositoryNames=[ecr_repository_name])
            if not response["repositories"][0]["imageScanningConfiguration"].get("scanOnPush", False):
                print(f"scanOnPush is not enabled for '{ecr_repository_name}'")
                return {
                    "status": "SKIPPED",
                    "important_count": 0,
                    "skipped_cves": [],
                    "ignored_count": 0,
                    "severity_counts": {},
                    "all_findings": [],
                }
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to check scanOnPush configuration: {err}")

        skip_cves = skip_cves or []

        print("Important vulnerabilities to be scanned:", ", ".join(self.IMPORTANT_SEVERITIES))
        print("Ignored vulnerabilities:", ", ".join(self.IGNORED_SEVERITIES))

        while True:
            try:
                response = self.ecr_client.describe_image_scan_findings(
                    repositoryName=ecr_repository_name,
                    imageId={"imageTag": image_tag}
                )
            except self.ecr_client.exceptions.ScanNotFoundException:
                print(f"Scan not yet available for tag '{image_tag}'. Retrying in {sleep_interval} sec...")
                time.sleep(sleep_interval)
                continue
            except (ClientError, BotoCoreError) as err:
                raise RuntimeError(f"failed to describe image scan findings: {err}")

            status = response.get("imageScanStatus", {}).get("status", "UNKNOWN")
            description = response.get("imageScanStatus", {}).get("description")

            print("Current image scan status:", status)
            if description and description != "null":
                print(description)

            if status == "COMPLETE":
                findings = response.get("imageScanFindings", {}).get("findings", [])
                severity_counts = response.get("imageScanFindings", {}).get("findingSeverityCounts", {})

                important = [f for f in findings if f.get("severity") in self.IMPORTANT_SEVERITIES]
                ignored = [f for f in findings if f.get("severity") in self.IGNORED_SEVERITIES]

                # Skip CVEs
                skipped_cves = []
                for cve in skip_cves:
                    if any(f.get("name") == cve and f.get("severity") in self.IMPORTANT_SEVERITIES for f in important):
                        print(f"The {cve} vulnerability is in the skip list. Skipped.")
                        skipped_cves.append(cve)
                    else:
                        print(f"The {cve} vulnerability has already been fixed. You must remove it from the skip list!")

                important_count = len(important) - len(skipped_cves)

                print(f"Important vulnerabilities total: {important_count}")

                if severity_counts:
                    print("All vulnerability severity totals:")
                    print(json.dumps(severity_counts, indent=2))

                if findings:
                    print("All findings:")
                    print(json.dumps(findings, indent=2))

                if important_count <= 0:
                    print("Image has no important vulnerabilities.")
                    return {
                        "status": "PASS",
                        "important_count": 0,
                        "skipped_cves": skipped_cves,
                        "ignored_count": len(ignored),
                        "severity_counts": severity_counts,
                        "all_findings": findings,
                    }
                else:
                    return {
                        "status": "FAIL",
                        "important_count": important_count,
                        "skipped_cves": skipped_cves,
                        "ignored_count": len(ignored),
                        "severity_counts": severity_counts,
                        "all_findings": findings,
                    }
            elif status == "FAILED":
                return {
                    "status": "ERROR",
                    "important_count": -1,
                    "skipped_cves": [],
                    "ignored_count": 0,
                    "severity_counts": {},
                    "all_findings": [],
                }
            else:
                print(f"Waiting {sleep_interval} seconds for scan to complete...")
                time.sleep(sleep_interval)

    def delete_image(self, repository_name: str, image_tag: str) -> None:
        """
        Deletes an image by tag from the given ECR repository.

        Args:
            repository_name (str): Name of the ECR repository.
            image_tag (str): Tag of the Docker image to delete.

        Returns:
            bool: True if image deleted successfully, False if there were deletion failures.

        Raises:
            RuntimeError: If the AWS API call fails completely.
        """
        try:
            response = self.ecr_client.batch_delete_image(
                repositoryName=repository_name,
                imageIds=[{"imageTag": image_tag}]
            )
        except (ClientError, BotoCoreError) as err:
            raise RuntimeError(f"failed to delete image '{image_tag}' from '{repository_name}': {err}")

        failures = response.get("failures", [])
        if failures:
            failure_messages = json.dumps(failures, indent=2)
            raise RuntimeError(f"partial deletion failure for image '{image_tag}': {failure_messages}")
