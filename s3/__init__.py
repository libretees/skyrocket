import os
import tarfile
import logging
import boto
import core

PROJECT_NAME = core.PROJECT_NAME
PROJECT_DIRECTORY = core.PROJECT_DIRECTORY
DJANGO_ENGINE = core.settings.DATABASES['default']['ENGINE']

logger = logging.getLogger(__name__)

def connect_s3():
    logger.info('Connecting to the Amazon Simple Storage Service (Amazon S3).')
    s3 = boto.connect_s3(aws_access_key_id=core.args.key_id,
                         aws_secret_access_key=core.args.key)
    logger.info('Connected to Amazon S3.')

    return s3

def make_tarfile(output_filename, source_dir):
    logger.info('Archiving directory (%s).' % source_dir)
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname='.')
    logger.info('Created gzipped tarball (%s).' % output_filename)
