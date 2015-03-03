#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import sys
import logging
import boto
import core
import vpc

__author__ = 'Jared Contrascere'
__copyright__ = 'Copyright 2015, LibreTees, LLC'
__license__ = 'GPLv3'

logger = logging.getLogger(__name__)

def main():
    PROJECT_NAME = core.PROJECT_NAME
    django_engine = core.settings.DATABASES['default']['ENGINE']

    if django_engine not in ['django.db.backends.postgresql_psycopg2' \
                            ,'django.db.backends.mysql' \
                            ,'django.db.backends.sqlite3' \
                            ,'django.db.backends.oracle']:
        logger.error('Unknown database engine (%s).' % django_engine, exc_info=True)
        sys.exit(1)
    else:
        logger.info('Provisioning RDS instance for Django engine (%s).' % django_engine)

    vpc_connection = vpc.connect_vpc()

    vpcs = vpc_connection.get_all_vpcs()
    default_vpc = vpcs[0]

    default_subnets = vpc_connection.get_all_subnets(filters={
                                                         'vpcId': default_vpc.id
                                                     })
    # for subnet in default_subnets:
    #     print(type(subnet), subnet, subnet.id)

    logger.info('Connecting to the Amazon Elastic Compute Cloud (Amazon EC2) service.')
    ec2 = boto.connect_ec2(aws_access_key_id=core.args.key_id,
                           aws_secret_access_key=core.args.key)
    logger.info('Connected to the Amazon EC2 service.')

    logger.info('Connecting to the Amazon Relational Database Service (Amazon RDS) service.')
    rds = boto.connect_rds2(aws_access_key_id=core.args.key_id,
                            aws_secret_access_key=core.args.key)
    logger.info('Connected to the Amazon RDS service.')

    # Not required for Amazon VPC
    # db_security_group_name = '-'.join(['gp', PROJECT_NAME.lower(), core.args.environment.lower(), 'db'])
    # db_security_group_description = ' '.join([PROJECT_NAME, 'DB Security Group'])
    # sg = rds.create_db_security_group(db_security_group_name,        #db_security_group_name
    #                                   db_security_group_description) #db_security_group_description

    # Affected by boto Issue #2677 : https://github.com/boto/boto/issues/2677
    aws_engine = {
        'django.db.backends.postgresql_psycopg2': 'postgres9.3',
        'django.db.backends.mysql':               'MySQL5.6',
        'django.db.backends.oracle':              'oracle-se1-11.2',
    }
    db_parameter_group_name = '-'.join(['pg', PROJECT_NAME.lower(), core.args.environment.lower(), 'db'])
    pg = rds.create_db_parameter_group(db_parameter_group_name,                                 #db_parameter_group_name
                                       aws_engine[django_engine],                               #db_parameter_group_family
                                       description=' '.join([PROJECT_NAME, 'Parameter Group'])) #description

    db_subnet_group_name = '-'.join(['net', PROJECT_NAME.lower(), core.args.environment.lower(), 'db'])
    rds.create_db_subnet_group(db_subnet_group_name,                       #db_subnet_group_name
                              ' '.join([PROJECT_NAME, 'DB Subnet Group']), #db_subnet_group_description
                              [subnet.id for subnet in default_subnets])   #subnet_ids

    aws_engine = {
        'django.db.backends.postgresql_psycopg2': 'postgres',
        'django.db.backends.mysql':               'MySQL',
        'django.db.backends.oracle':              'oracle-se1',
    }
    # inst = rds.create_db_instance('dbinst1',                 #db_instance_identifier
    #                               5,                         #allocated_storage
    #                               'db.t2.micro',             #db_instance_class
    #                               aws_engine[django_engine], #engine
    #                               'username',                #master_username
    #                               'password',                #master_user_password
    #                               #db_security_groups=[db_security_group_name],
    #                               db_subnet_group_name=db_subnet_group_name,
    #                               db_parameter_group_name=db_parameter_group_name)

    rs = rds.describe_db_instances()
    print(type(rs), rs)

if __name__ == '__main__':
    main()
