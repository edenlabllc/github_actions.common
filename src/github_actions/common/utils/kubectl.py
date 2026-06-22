import subprocess


from ..utils.cmd import BaseCommand, CMDInterface


class Kubectl(BaseCommand, CMDInterface):
    def __init__(self, kubectl_download_url="https://dl.k8s.io/release/v1.36.2/bin/linux/amd64/kubectl"):
        self.kubectl_download_url = kubectl_download_url
        self._install_kubectl()

    def get_secret(self, secret_name: str, namespace: str, secret_path: str) -> str:
        try:
            print(f"Getting secret {secret_name} in namespace {namespace}.")
            result = self.run_command(
                f"kubectl get secret {secret_name} --namespace {namespace} --output yaml", check=True, text=True, capture_output=True
            )

            print(f"Secret {secret_name} retrieved successfully. Extracting data.")
            # parse yaml output and extract the password field, decode it from base64
            result = self.run_command(
                f"yq '.data.{secret_path} | @base64d'",
                input=result.stdout,
                check=True,
                text=True,
                capture_output=True,
            )
            return result.stdout
        except subprocess.CalledProcessError as err:
            raise Exception(f"getting secret {secret_name} in namespace {namespace}:\n{err}")

    def _install_kubectl(self):
        print("Installing kubectl.")
        try:
            self.run_command(f"bash -s -- {self.kubectl_download_url}", check=True, text=True, input="")

            version = self.run_command("kubectl version --client", check=True, text=True, capture_output=True)
            print(f"kubectl installed successfully. Version: {version.stdout.strip()}")
        except subprocess.CalledProcessError as err:
            raise Exception(f"installing kubectl:\n{err}")
