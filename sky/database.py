import sys
import time
import logging
import boto
from .compute import create_security_group
from .state import config

logger = logging.getLogger(__name__)

ENGINE = {
    'postgresql': 'postgres9.3',
    'mysql':      'MySQL5.6',
    'oracle':     'oracle-se1-11.2',
}

ENGINE_NAME = {
    'postgresql': 'postgres',
    'mysql':      'MySQL',
    'oracle':     'oracle-se1',
}

MAJOR_ENGINE_VERSION = {
    'postgresql': '9.3',
    'mysql':      '5.1.42',
    'oracle':     '11.2.0.2.v2',
}

INBOUND_PORT = {
    'postgresql': 5432,
    'mysql':      3306,
    'oracle':     1520,
}

def connect_rds():
    logger.debug('Connecting to the Amazon Relational Database Service (Amazon RDS).')
    rds = boto.connect_rds2(aws_access_key_id=config['AWS_ACCESS_KEY_ID'],
                            aws_secret_access_key=config['AWS_SECRET_ACCESS_KEY'])
    logger.debug('Connected to Amazon RDS.')
    
    return rds

def create_db_parameter_group(name=None, engine='postgresql'):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Affected by boto Issue #2677 : https://github.com/boto/boto/issues/2677


    # Generate Database Parameter Group name.
    if not name:
        name = '-'.join(['pg',
                         config['PROJECT_NAME'],
                         config['ENVIRONMENT'],])

    # Delete existing Database Parameter Group.
    try:
        rds_connection.delete_db_parameter_group(name)
    except boto.rds2.exceptions.DBParameterGroupNotFound as error:
        pass

    db_parameter_group = rds_connection.create_db_parameter_group(name,                                                    # db_parameter_group_name
                                                                  ENGINE[engine],                                          # db_parameter_group_family
                                                                  description=' '.join([config['PROJECT_NAME'], 'Parameter Group'])) # description

    # Construct Database Parameter Group ARN.
    region = 'us-east-1'
    db_parameter_group_arn = 'arn:aws:rds:%s:%s:pg:%s' % (region, config['AWS_ACCOUNT_ID'], name)

    # Tag Database Subnet Group.
    logger.debug('Tagging Amazon RDS Resource (%s).' % db_parameter_group_arn)
    rds_connection.add_tags_to_resource(db_parameter_group_arn,           # resource_name
                                        [('Name'       , name         ),  # tags
                                         ('Project'    , config['PROJECT_NAME'] ),
                                         ('Environment', config['ENVIRONMENT']  )])
    logger.debug('Tagged Amazon RDS Resource (%s).' % db_parameter_group_arn)

    return db_parameter_group

def create_db_subnet_group(subnets, name=None):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Generate Database Subnet Group name.
    if not name:
        name = '-'.join(['subgrp',
                         config['PROJECT_NAME'],
                         config['ENVIRONMENT'],])

    # Delte existing Database Subnet Group.
    try:
        rds_connection.delete_db_subnet_group(name)
    except boto.exception.JSONResponseError as error:
        if error.code == 'DBSubnetGroupNotFoundFault':
            pass

    # Create Database Subnet Group.
    subnet = None
    try:
        subnet = rds_connection.create_db_subnet_group(name,                                        #db_subnet_group_name
                                                       ' '.join([config['PROJECT_NAME'], 'DB Subnet Group']), #db_subnet_group_description
                                                       [subnet.id for subnet in subnets])           #subnet_ids
    except boto.rds2.exceptions.DBSubnetGroupAlreadyExists as error:
        if error.code == 'DBSubnetGroupAlreadyExists':
            subnet = rds_connection.describe_db_subnet_groups(name)

    # Construct Database Subnet Group ARN.
    region = 'us-east-1'
    db_subnet_group_arn = 'arn:aws:rds:%s:%s:subgrp:%s' % (region, config['AWS_ACCOUNT_ID'], name)

    # Tag Database Subnet Group.
    logger.debug('Tagging Amazon RDS Resource (%s).' % db_subnet_group_arn)
    rds_connection.add_tags_to_resource(db_subnet_group_arn,              # resource_name
                                        [('Name'       , name         ),  # tags
                                         ('Project'    , config['PROJECT_NAME'] ),
                                         ('Environment', config['ENVIRONMENT']  )])
    logger.debug('Tagged Amazon RDS Resource (%s).' % db_subnet_group_arn)

    return subnet

def create_option_group(name=None, engine='postgresql'):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Generate Option Group name.
    if not name:
        name = '-'.join(['og',
                         config['PROJECT_NAME'],
                         config['ENVIRONMENT'],])

    # Delete Option Group.
    try:
        rds_connection.delete_option_group(name)
    except boto.exception.JSONResponseError as error:
        if error.status == 404 and error.reason == 'Not Found' and error.body['Error']['Code'] == 'OptionGroupNotFoundFault':
            pass
        else:
            raise boto.exception.JSONResponseError(error.status, error.reason, body=error.body)

    # Create Option Group.
    option_group = rds_connection.create_option_group(name,                                     # option_group_name
                                                      ENGINE_NAME[engine],                      # engine_name
                                                      MAJOR_ENGINE_VERSION[engine],             # major_engine_version
                                                      ' '.join([config['PROJECT_NAME'], 'Option Group']), # option_group_description
                                                      tags=None)

    # Construct Option Group ARN.
    region = 'us-east-1'
    option_group_arn = 'arn:aws:rds:%s:%s:og:%s' % (region, config['AWS_ACCOUNT_ID'], name)

    # Tag Option Group.
    logger.debug('Tagging Amazon RDS Resource (%s).' % option_group_arn)
    rds_connection.add_tags_to_resource(option_group_arn   ,              # resource_name
                                        [('Name'       , name         ),  # tags
                                         ('Project'    , config['PROJECT_NAME'] ),
                                         ('Environment', config['ENVIRONMENT']  )])
    logger.debug('Tagged Amazon RDS Resource (%s).' % option_group_arn)

    return option_group

def create_database(vpc, subnets, name=None, engine='postgresql', application_instances=None, security_groups=None, publicly_accessible=False, multi_az=False, db_parameter_group=None, option_group=None):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    db_subnet_group = create_db_subnet_group(subnets)

    if not name:
        name = '-'.join(['db',
                         config['PROJECT_NAME'],
                         config['ENVIRONMENT'],])

    if not db_parameter_group:
        db_parameter_group = create_db_parameter_group(engine=engine)

    if not option_group:
        option_group = create_option_group(engine=engine)

    db_parameter_group_name = db_parameter_group['CreateDBParameterGroupResponse']\
                                                ['CreateDBParameterGroupResult']\
                                                ['DBParameterGroup']\
                                                ['DBParameterGroupName']

    db_subnet_group_name = db_subnet_group['CreateDBSubnetGroupResponse']\
                                          ['CreateDBSubnetGroupResult']\
                                          ['DBSubnetGroup']\
                                          ['DBSubnetGroupName']

    option_group_name = option_group['CreateOptionGroupResponse']\
                                    ['CreateOptionGroupResult']\
                                    ['OptionGroup']\
                                    ['OptionGroupName']

    if not security_groups:
        if application_instances:
            # Create rule(s) allowing traffic from application server security group(s).
            application_security_group_ids = set([group.id for instance in application_instances for group in instance.groups])
            inbound_rules = list()
            for application_security_group_id in application_security_group_ids:
                inbound_rule = ('TCP:' + str(INBOUND_PORT[engine]), application_security_group_id)
                inbound_rules.append(inbound_rule)

        sg_name = '-'.join(['gp', config['PROJECT_NAME'], config['ENVIRONMENT'], 'db'])
        security_groups = [create_security_group(vpc, name=sg_name
                                                    , allowed_inbound_traffic=inbound_rules if application_instances else None
                                                    , allowed_outbound_traffic=[('HTTP',  '0.0.0.0/0')
                                                                               ,('HTTPS', '0.0.0.0/0')
                                                                               ,('DNS',   '0.0.0.0/0')])]

    db_instance = rds_connection.create_db_instance(name,                                                     # db_instance_identifier
                                                    5,                                                        # allocated_storage
                                                    'db.t2.micro',                                            # db_instance_class
                                                    ENGINE_NAME[engine],                                      # engine
                                                    'username',                                               # master_username
                                                    'password',                                               # master_user_password
                                                    db_name=None,
                                                    db_security_groups=None,                                  # Used in EC2-Classic.
                                                    vpc_security_group_ids=[sg.id for sg in security_groups],
                                                    availability_zone=None,                                   # Used in EC2-Classic.
                                                    db_subnet_group_name=db_subnet_group_name,                # Required for EC2-VPC Database Instances.
                                                    preferred_maintenance_window=None,
                                                    db_parameter_group_name=db_parameter_group_name,
                                                    backup_retention_period=None,
                                                    preferred_backup_window=None,
                                                    port=None,
                                                    multi_az=multi_az,
                                                    engine_version=None,
                                                    auto_minor_version_upgrade=None,
                                                    license_model=None,
                                                    iops=None,
                                                    option_group_name=option_group_name,
                                                    character_set_name=None,
                                                    publicly_accessible=publicly_accessible,
                                                    tags=None)

    # Construct Database Instance ARN.
    region = 'us-east-1'
    database_arn = 'arn:aws:rds:%s:%s:db:%s' % (region, config['AWS_ACCOUNT_ID'], name)

    # Tag Database Instance.
    logger.debug('Tagging Amazon RDS Resource (%s).' % database_arn)
    rds_connection.add_tags_to_resource(database_arn,                     # resource_name
                                        [('Name'       , name         ),  # tags
                                         ('Project'    , config['PROJECT_NAME'] ),
                                         ('Environment', config['ENVIRONMENT']  )])
    logger.debug('Tagged Amazon RDS Resource (%s).' % database_arn)

    # Get Database Endpoint.
    logger.info('Getting endpoint for database (%s).' % name)
    endpoint = None
    while not endpoint:
        response = rds_connection.describe_db_instances(db_instance_identifier=name,
                                                        filters=None,
                                                        max_records=None,
                                                        marker=None)
        endpoint = response['DescribeDBInstancesResponse']\
                           ['DescribeDBInstancesResult']\
                           ['DBInstances'][-1]\
                           ['Endpoint']
        if not endpoint:
            logger.debug('Waiting for database endpoint...')
            time.sleep(1)
        else:
            logger.info('Got database endpoint (%s).' % endpoint)
    db_instance['endpoint'] = endpoint

    return db_instance
