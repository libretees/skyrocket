import logging
import boto
import core

logger = logging.getLogger(__name__)

def connect_vpc():
    logger.info('Connecting to the Amazon Virtual Private Cloud (Amazon VPC) service.')
    vpc = boto.connect_vpc(aws_access_key_id=core.args.key_id,
                           aws_secret_access_key=core.args.key)
    logger.info('Connected to the Amazon VPC service.')
    
    return vpc
