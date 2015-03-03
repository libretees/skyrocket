import sys
import logging
import boto
import core

PROJECT_NAME = core.PROJECT_NAME
DJANGO_ENGINE = core.settings.DATABASES['default']['ENGINE']

logger = logging.getLogger(__name__)

def connect_s3():
    logger.info('Connecting to the Amazon Simple Storage Service (Amazon S3) service.')
    s3 = boto.connect_s3(aws_access_key_id=core.args.key_id,
                         aws_secret_access_key=core.args.key)
    logger.info('Connected to the Amazon S3 service.')

    return s3