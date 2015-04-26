import os
import sys
import logging

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

    def __setattr__(self, key, value):
        self[key] = value

ready = ReadyObject()

CREATION_MODE = None
EPHEMERAL = 'ephemeral'
PERMANENT = 'permanent'

config = {
    'PROJECT_NAME':          None,
    'PROJECT_DIRECTORY':     None,
    'ENVIRONMENT':           None,
    'AWS_ACCOUNT_ID':        None,
    'AWS_ACCESS_KEY_ID':     None,
    'AWS_SECRET_ACCESS_KEY': None,
}