import os
import argparse


class ArgumentParser:
    class EnvDefault(argparse.Action):
        def __init__(self, envvar, required=True, default=None, **kwargs):
            if envvar:
                if envvar in os.environ:
                    default = os.environ.get(envvar, default)
            if required and default:
                required = False
            super(ArgumentParser.EnvDefault, self).__init__(default=default, required=required, metavar=envvar, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values)

    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.setup_arguments()

    def setup_arguments(self):
        self.parser.add_argument("--core-aws-region",
                                 action=self.EnvDefault, envvar="INPUT_CORE_AWS_REGION",
                                 type=str, required=False)

        self.parser.add_argument("--core-aws-access-key-id",
                                 action=self.EnvDefault, envvar="INPUT_CORE_AWS_ACCESS_KEY_ID",
                                 type=str, required=False)

        self.parser.add_argument("--core-aws-secret-access-key",
                                 action=self.EnvDefault, envvar="INPUT_CORE_AWS_SECRET_ACCESS_KEY",
                                 type=str, required=False)

        self.parser.add_argument("--github-token",
                                 action=self.EnvDefault, envvar="INPUT_GITHUB_TOKEN_REPO_FULL_ACCESS",
                                 type=str, required=False)

        self.parser.add_argument("--ecr-public-repository",
                                 action=self.EnvDefault, envvar="INPUT_ECR_PUBLIC_REPOSITORY",
                                 type=str, required=False)

        self.parser.add_argument("--ecr-repository-name-prefix",
                                 action=self.EnvDefault, envvar="INPUT_ECR_REPOSITORY_NAME_PREFIX",
                                 type=str, required=False)

        self.parser.add_argument("--image-build-args",
                                 action=self.EnvDefault, envvar="INPUT_IMAGE_BUILD_ARGS",
                                 type=str, required=False)

        self.parser.add_argument("--image-build-push",
                                 action=self.EnvDefault, envvar="INPUT_IMAGE_BUILD_PUSH",
                                 type=str, required=False)

        self.parser.add_argument("--image-build-target-stages",
                                 action=self.EnvDefault, envvar="INPUT_IMAGE_BUILD_TARGET_STAGES",
                                 type=str, required=False)

        self.parser.add_argument("--image-delete",
                                 action=self.EnvDefault, envvar="INPUT_IMAGE_DELETE",
                                 type=str, required=False)

        self.parser.add_argument("--image-scan",
                                 action=self.EnvDefault, envvar="INPUT_IMAGE_SCAN",
                                 type=str, required=False)

        self.parser.add_argument("--image-scan-skip-cve-list",
                                 action=self.EnvDefault, envvar="INPUT_IMAGE_SCAN_SKIP_CVE_LIST",
                                 type=str, required=False)

        self.parser.add_argument("--major-version-branch",
                                 action=self.EnvDefault, envvar="INPUT_MAJOR_VERSION_BRANCH",
                                 type=str, required=False)

        self.parser.add_argument("--release-update-tenants",
                                 action=self.EnvDefault, envvar="INPUT_RELEASE_UPDATE_TENANTS",
                                 type=str, required=False)

    def parse_args(self):
        return self.parser.parse_args()
