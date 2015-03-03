import logging
import boto
import core

logger = logging.getLogger(__name__)

def connect_ec2():
    logger.info('Connecting to the Amazon Elastic Compute Cloud (Amazon EC2) service.')
    ec2 = boto.connect_ec2(aws_access_key_id=core.args.key_id,
                           aws_secret_access_key=core.args.key)
    logger.info('Connected to Amazon EC2.')

    return ec2
