import os
from .import_settings import import_settings
from .parse_arguments import parse_arguments

args = parse_arguments()
settings = import_settings(args)

PROJECT_NAME = os.path.abspath(os.path.expanduser(args.directory)).split(os.sep)[-1]

__all__ = ['import_settings', 'parse_arguments']