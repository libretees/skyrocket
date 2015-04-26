import os
import tarfile
import random
import logging
import boto
from .state import config

logger = logging.getLogger(__name__)

def connect_s3():
    logger.debug('Connecting to the Amazon Simple Storage Service (Amazon S3).')
    s3 = boto.connect_s3(aws_access_key_id=config['AWS_ACCESS_KEY_ID'],
                         aws_secret_access_key=config['AWS_SECRET_ACCESS_KEY'])
    logger.debug('Connected to Amazon S3.')

    return s3

def create_bucket():
    s3_connection = connect_s3()
    s3_bucket_name = '-'.join(['s3', config['PROJECT_NAME'], config['ENVIRONMENT'], '%x' % random.randrange(2**32)])
    lifecycle_config = boto.s3.lifecycle.Lifecycle()
    lifecycle_config.add_rule(status='Enabled', expiration=1)
    bucket = s3_connection.lookup(s3_bucket_name)
    if not bucket:
        try:
            logger.info('Creating S3 bucket (%s).' % s3_bucket_name)
            bucket = s3_connection.create_bucket(s3_bucket_name, location=boto.s3.connection.Location.DEFAULT, policy='private')
            bucket.configure_lifecycle(lifecycle_config)
            logger.info('Created S3 bucket (%s).' % s3_bucket_name)
        except boto.exception.S3CreateError as error:
            logger.error('Could not create S3 bucket (%s) due to Error %s: %s.' % (s3_bucket_name, error.status, error.reason))
    else:
        bucket = create_bucket()

    return bucket

def add_object(bucket, obj):
    key = bucket.new_key(obj)
    key.set_contents_from_filename(obj, policy='private')

def get_bucket_policy(bucket):
    arns = ['"arn:aws:s3:::'+bucket.name+'/'+key.name+'"' for key in bucket.get_all_keys()]
    policy = """{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [%s]
        }]
    }""" % ','.join(arns)
    return policy
