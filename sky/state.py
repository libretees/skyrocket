import os
import sys
import logging
from .utils import parse_arguments

logger = logging.getLogger(__name__)

class ReadyObject(dict):

    def __init__(self):
        super(ReadyObject, self).__init__()

    def __getattr__(self, attr):
        try:
            value = self[attr]
        except KeyError as error:
            logger.error('%s is not available.')
        return value

ready = ReadyObject()

CREATION_MODE = None
EPHEMERAL = 'ephemeral'
PERMANENT = 'permanent'

args = parse_arguments()
PROJECT_NAME = os.path.abspath(os.path.expanduser(args.directory)).split(os.sep)[-1].lower()
PROJECT_DIRECTORY = os.path.abspath(os.path.expanduser(args.directory)).lower()
ENVIRONMENT = args.environment.lower()
AWS_ACCOUNT_ID = args.account_id
AWS_ACCESS_KEY_ID = args.key_id
AWS_SECRET_ACCESS_KEY = args.key