from github_actions.common.utils.cmd import BaseCommand, CMDInterface


class Kubectl(BaseCommand, CMDInterface):
    def __init__(self, kubectl_download_url="https://dl.k8s.io/release/v1.36.2/bin/linux/amd64/kubectl"):
        self.kubectl_download_url = kubectl_download_url
        self._install_kubectl()

    def get_secret(self, secret_name: str, namespace: str, secret_path: str) -> str | None:
        try:
            print(f"Getting secret {secret_name} in namespace {namespace}.")
            return self.run_command(
                f"kubectl get secret {secret_name} --namespace {namespace} --output yaml | yq '.data.password'", capture_output=True
            )

        except Exception as err:
            raise Exception(f"getting secret {secret_name} in namespace {namespace}:\n{err}")

    def _install_kubectl(self):
        print("Installing kubectl.")
        try:
            self.run_command(f"bash -s -- {self.kubectl_download_url}")

            version = self.run_command("kubectl version --client", capture_output=True)
            print(f"kubectl installed successfully. Version: {version}")
        except Exception as err:
            raise Exception(f"installing kubectl:\n{err}")
