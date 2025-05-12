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
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement the setup_arguments() method to define its specific CLI arguments."
        )

    def parse_args(self):
        return self.parser.parse_args()
