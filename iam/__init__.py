import logging
import boto
import core

logger = logging.getLogger(__name__)

def connect_iam():
    logger.info('Connecting to the Amazon Identity and Access Management (Amazon IAM) service.')
    iam = boto.connect_iam(aws_access_key_id=core.args.key_id,
                           aws_secret_access_key=core.args.key)
    logger.info('Connected to Amazon IAM.')

    return iam