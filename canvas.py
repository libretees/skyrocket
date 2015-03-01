#!/usr/bin/env python
"""canvas.py: Provision AWS environments for Django projects."""

import os
import sys
import imp
import logging
import argparse
import re
import configparser
import boto

__author__ = 'Jared Contrascere'
__copyright__ = 'Copyright 2015, LibreTees, LLC'
__license__ = 'GPLv3'

PROJECT_NAME = None
logger = logging.getLogger(__name__)

def import_settings(args):
    global PROJECT_NAME
    settings = None
    if os.environ.get('DJANGO_SETTINGS_MODULE'):
        try:
            import_module('settings', os.environ['DJANGO_SETTINGS_MODULE'])
            logger.debug('Django Settings Module loaded (%s).' % os.environ['DJANGO_SETTINGS_MODULE'])
        except:
            logger.debug('Django Settings Module could not be loaded from path given in environment variable.')

    project_directory = os.path.abspath(os.path.expanduser(args.directory))
    PROJECT_NAME = project_directory.split(os.sep)[-1]
    relative_path = os.path.join(os.path.relpath(project_directory, os.getcwd()), PROJECT_NAME, 'settings.py')
    logger.info('Loading (%s).' % relative_path)
    try:
        imp.load_source('settings', relative_path)
        import settings
        logger.debug('Django Settings Module loaded from file (%s).' % relative_path)
    except (FileNotFoundError, ImportError):
        logger.debug('Django Settings Module could not be loaded from file (%s).' % relative_path)

    try:
        assert settings
    except AssertionError:
        logger.error('Django Settings Module failed to import.')
        if __name__ == '__main__':
            logger.error('Exiting...')
            sys.exit(1)

    return settings

def parse_arguments():
    valid_arguments = True
    parser = argparse.ArgumentParser(description='Provision Django application environments.')
    parser.add_argument('-p', '--project', dest='directory', action='store', default=os.getcwd(),
                        help='set Django project directory')
    parser.add_argument('-env', '--environment', dest='environment', action='store', default='STAGING',
                        help='set desired deployment environment [STAGING, PRODUCTION]\n(default: staging)')
    parser.add_argument('-aws', '--account-id', dest='account_id', action='store', default=os.environ.get('AWS_ACCOUNT_ID'),
                        help='set AWS Account ID')
    parser.add_argument('-id', '--key-id', dest='key_id', action='store', default=os.environ.get('AWS_ACCESS_KEY_ID'),
                        help='set AWS Access Key ID')
    parser.add_argument('-k', '--secret', dest='key', action='store', default=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                        help='set AWS Account Secret Access Key')
    parser.add_argument('-d', '--log', dest='loglevel', action='store', default='ERROR',
                        help='set log level [DEBUG, INFO, WARNING, ERROR, CRITICAL] (default: ERROR)')
    parser.add_argument('--dry', dest='dry_run', action='store_true', default=False,
                        help='perform a dry run')
    args = parser.parse_args()

    try:
        assert args.loglevel.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if args.loglevel.upper() == 'DEBUG':
            print('DEBUG:', __name__, ':Log argument validated (%s).' % args.loglevel, sep='')
    except AssertionError:
        print('ERROR:', __name__, ':Invalid log option (%s).' % args.loglevel, file=sys.stderr, sep='')
        valid_arguments = False
    configure_logger(args)

    try:
        assert args.environment.upper() in ['STAGING', 'PROD', 'PRODUCTION']
        if args.environment.upper() == 'PRODUCTION': args.environment = 'PROD'
        logger.debug('Deployment environment argument validated (%s).' % args.environment)
    except AssertionError:
        logger.error('Invalid deployment environment (%s).' % args.environment)
        valid_arguments = False

    try:
        assert os.path.isdir(os.path.expanduser(args.directory))
        logger.debug('Django project directory argument validated (%s).' % args.directory)
    except AssertionError:
        logger.error('Invalid Django project directory (%s).' % args.directory)
        valid_arguments = False

    try:
        assert re.search(r'^\d{12}$', args.account_id)
        logger.debug('AWS Account ID argument validated (%s).' % args.account_id)
    except AssertionError:
        if len(args.account_id):
            logger.error('AWS Account ID must be exactly 12 digits (%s).' % args.account_id)
        else:
            logger.error('AWS Account ID not specified.')
        valid_arguments = False

    config_path = None
    if os.environ.get('BOTO_CONFIG'):
        config_path = os.path.expanduser(os.environ.get('BOTO_CONFIG'))
    elif os.path.exists(os.path.expanduser('~/.boto')):
        config_path = os.path.expanduser('~/.boto')
    elif os.path.exists(os.path.expanduser('~/.aws/credentials')):
        config_path = os.path.expanduser('~/.aws/credentials')
    elif os.path.exists('/etc/boto.cfg'):
        config_path = '/etc/boto.cfg'

    if config_path:
        config = configparser.ConfigParser()
        config.sections()
        try:
            logger.info('Reading configuration file (%s).' % config_path)
            config.read(config_path)
            key_id = config['Credentials']['aws_access_key_id']
            key = config['Credentials']['aws_secret_access_key']
        except:
            logger.error('Could not read configuration file (%s).' % config_path)

    try:
        args.key_id = args.key_id or key_id
        assert re.search(r'^[A-Z0-9]{20}$', args.key_id, re.IGNORECASE)
        logger.debug('AWS Access Key ID argument validated (%s).' % args.key_id)
    except AssertionError:
        if len(args.key_id):
            logger.error('AWS Access Key ID must contain 20 alphanumeric characters (%s).' % args.key_id)
        else:
            logger.error('AWS Access Key ID not specified.')
        valid_arguments = False

    try:
        args.key = args.key or key
        assert re.search(r'^[A-Z0-9/\+]{40}$', args.key, re.IGNORECASE)
        logger.debug('AWS Account Secret Access Key argument validated.')
    except AssertionError:
        if len(args.key):
            logger.error('AWS Account Secret Access Key must contain 40 alphanumeric characters and/or the following: /+ (%s).' \
                         % args.key)
        else:
            logger.error('AWS Account Secret Access Key not specified.')
        valid_arguments = False

    if not valid_arguments:
        logger.error('Invalid arguments given.')
        if __name__ == '__main__':
            logger.error('Exiting...')
            sys.exit(1)

    return args

def configure_logger(args):
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)

def main():
    args = parse_arguments()
    settings = import_settings(args)

    django_engine = settings.DATABASES['default']['ENGINE']

    if django_engine not in ['django.db.backends.postgresql_psycopg2' \
                            ,'django.db.backends.mysql' \
                            ,'django.db.backends.sqlite3' \
                            ,'django.db.backends.oracle']:
        logger.error('Unknown database engine (%s).' % django_engine, exc_info=True)
        sys.exit(1)
    else:
        logger.info('Provisioning RDS instance for Django engine (%s).' % django_engine)

    logger.info('Connecting to the Amazon Elastic Compute Cloud (Amazon EC2) service.')
    ec2 = boto.connect_ec2(aws_access_key_id=args.key_id,
                           aws_secret_access_key=args.key)
    logger.info('Connected to the Amazon EC2 service.')

    logger.info('Connecting to the Amazon Relational Database Service (Amazon RDS) service.')
    rds = boto.connect_rds(aws_access_key_id=args.key_id,
                           aws_secret_access_key=args.key)
    logger.info('Connected to the Amazon RDS service.')

    security_group_name = '-'.join(['gp', PROJECT_NAME.lower(), args.environment.lower(), 'db'])
    sg = rds.create_dbsecurity_group(security_group_name,                           #name
                                     ' '.join([PROJECT_NAME, 'DB Security group'])) #engine

    aws_engines = {
        'django.db.backends.postgresql_psycopg2': 'postgres9.3',
        'django.db.backends.mysql':               'MySQL5.6',
        'django.db.backends.oracle':              'oracle-se1-11.2',
    }
    parameter_group_name = '-'.join(['pg', PROJECT_NAME.lower(), args.environment.lower(), 'db'])
    pg = rds.layer1.create_parameter_group(parameter_group_name,                                     #name
                                           engine=aws_engines[django_engine],                        #engine
                                           description=' '.join([PROJECT_NAME, ' parameter group'])) #description
    pg.get_params()
    for key in pg.keys():
        print(key)

    # inst = rds.create_dbinstance(id='dbinst1', allocated_storage=10,
    #                              instance_class='db.m1.small', master_username='mitch',
    #                              master_password='topsecret', param_group=parameter_group_name,
    #                              security_groups=[security_group_name])

    #rs = rds.get_all_dbinstances()
    #print(rs[0].status)

if __name__ == '__main__':
    main()
