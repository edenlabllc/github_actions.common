import subprocess


class Kubectl:
    def __init__(self, args):
        self.kubectl_version = args.kubectl_version
        self.kubectl_download_url = args.kubectl_download_url
        self.install_kubectl()

    def install_kubectl(self):
        print("Installing kubectl.")
        try:
            subprocess.run(["bash", "-s", "--", self.kubectl_version, self.kubectl_download_url], check=True, text=True, input="")
        except subprocess.CalledProcessError as err:
            raise Exception(f"installing kubectl:\n{err}")

    def get_secret(self, secret_name: str, namespace: str, secret_path: str) -> str:
        try:
            result = subprocess.run(
                ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "yaml"], check=True, text=True, capture_output=True
            )
            #  kubectl get secret keycloak-cluster-initial-admin --namespace keycloak --output yaml | yq '.data.password | @base64d'

            # parse yaml output and extract the password field, decode it from base64
            result = subprocess.run(
                ["yq", f".data.{secret_path} | @base64d"],
                input=result.stdout,
                check=True,
                text=True,
                capture_output=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as err:
            raise Exception(f"getting secret {secret_name} in namespace {namespace}:\n{err}")
