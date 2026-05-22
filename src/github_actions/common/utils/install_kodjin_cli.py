import subprocess
import requests

from argparse import Namespace
from packaging import version


class KodjinCLIInstaller:
    def __init__(self, args: Namespace):
        self.version = args.kodjin_cli_version
        self.url = args.kodjin_cli_download_url
        self.verify_kodjin_cli_version()
        self.install_kodjin_cli()

    def verify_kodjin_cli_version(self):
        print("Verifying Kodjin CLI installation version...")
        if self.version != "latest":
            if version.parse(self.version) <= version.parse("v0.1.11"):
                raise Exception(
                    f"version {self.version} of Kodjin CLI is not correct, "
                    + "the version for Kodjin CLI must be at least v0.1.11 or greater"
                )

    def install_kodjin_cli(self):
        print("Installing Kodjin CLI.")
        try:
            response = requests.get(self.url)
            response.raise_for_status()
        except requests.RequestException as err:
            raise Exception(f"downloading Kodjin CLI installer file:\n{err}")

        try:
            subprocess.run(
                ["bash", "-s", "--", self.version],
                check=True,
                text=True,
                input=response.text,
            )
        except subprocess.CalledProcessError as err:
            raise Exception(f"installing Kodjin CLI:\n{err}")
