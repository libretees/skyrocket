import sys
import logging
import boto
import ec2
import core

AWS_ACCOUNT_ID = core.args.account_id

PROJECT_NAME = core.PROJECT_NAME
DJANGO_ENGINE = core.settings.DATABASES['default']['ENGINE']

logger = logging.getLogger(__name__)

def connect_rds():
    logger.debug('Connecting to the Amazon Relational Database Service (Amazon RDS).')
    rds = boto.connect_rds2(aws_access_key_id=core.args.key_id,
                            aws_secret_access_key=core.args.key)
    logger.debug('Connected to Amazon RDS.')
    
    return rds

def create_db_parameter_group(name=None):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Affected by boto Issue #2677 : https://github.com/boto/boto/issues/2677
    aws_engine = {
        'django.db.backends.postgresql_psycopg2': 'postgres9.3',
        'django.db.backends.mysql':               'MySQL5.6',
        'django.db.backends.oracle':              'oracle-se1-11.2',
    }

    db_parameter_group_name = '-'.join(['pg', PROJECT_NAME.lower(), core.args.environment.lower(), 'db'])

    # Delete existing DB Parameter Group.
    try:
        rds_connection.delete_db_parameter_group(db_parameter_group_name)
    except boto.rds2.exceptions.DBParameterGroupNotFound as error:
        pass

    db_parameter_group = rds_connection.create_db_parameter_group(db_parameter_group_name,                                 #db_parameter_group_name
                                                                  aws_engine[DJANGO_ENGINE],                               #db_parameter_group_family
                                                                  description=' '.join([PROJECT_NAME, 'Parameter Group'])) #description

    # Construct Database Parameter Group ARN.
    region = 'us-east-1'
    db_parameter_group_arn = 'arn:aws:rds:%s:%s:pg:%s' % (region, AWS_ACCOUNT_ID, name)

    # Tag Database Subnet Group.
    logger.debug('Tagging Database instance (%s).' % db_parameter_group_arn)
    rds_connection.add_tags_to_resource(db_parameter_group_arn,                           # resource_name
                                        [('Name'       , name                         ),  # tags
                                         ('Project'    , core.PROJECT_NAME.lower()    ),
                                         ('Environment', core.args.environment.lower())])
    logger.debug('Tagged Database instance (%s).' % db_parameter_group_arn)

    return db_parameter_group

def create_db_subnet_group(subnets, name=None):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Generate DB Subnet Group name.
    if not name:
        name = '-'.join(['subgrp',
                         PROJECT_NAME.lower(),
                         core.args.environment.lower(),])

    # Delte existing DB Subnet Group.
    try:
        rds_connection.delete_db_subnet_group(name)
    except boto.exception.JSONResponseError as error:
        if error.code == 'DBSubnetGroupNotFoundFault':
            pass

    # Create Database Subnet Group.
    subnet = rds_connection.create_db_subnet_group(name,                                        #db_subnet_group_name
                                                   ' '.join([PROJECT_NAME, 'DB Subnet Group']), #db_subnet_group_description
                                                   [subnet.id for subnet in subnets])           #subnet_ids

    # Construct Database Subnet Group ARN.
    region = 'us-east-1'
    db_subnet_group_arn = 'arn:aws:rds:%s:%s:subgrp:%s' % (region, AWS_ACCOUNT_ID, name)

    # Tag Database Subnet Group.
    logger.debug('Tagging Database instance (%s).' % db_subnet_group_arn)
    rds_connection.add_tags_to_resource(db_subnet_group_arn,                              # resource_name
                                        [('Name'       , name                         ),  # tags
                                         ('Project'    , core.PROJECT_NAME.lower()    ),
                                         ('Environment', core.args.environment.lower())])
    logger.debug('Tagged Database instance (%s).' % db_subnet_group_arn)

    return subnet

def create_database(vpc, subnets, application_instances=None, security_groups=None, publicly_accessible=False, multi_az=False, db_parameter_group=None):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    if DJANGO_ENGINE not in ['django.db.backends.postgresql_psycopg2' \
                            ,'django.db.backends.mysql' \
                            ,'django.db.backends.sqlite3' \
                            ,'django.db.backends.oracle']:
        logger.error('Unknown database engine (%s).' % DJANGO_ENGINE, exc_info=True)
        sys.exit(1)
    else:
        logger.info('Provisioning RDS instance for Django engine (%s).' % DJANGO_ENGINE)

    engine = {
        'django.db.backends.postgresql_psycopg2': 'postgres',
        'django.db.backends.mysql':               'MySQL',
        'django.db.backends.oracle':              'oracle-se1',
    }

    if not db_parameter_group:
        db_parameter_group = create_db_parameter_group()

    db_subnet_group = create_db_subnet_group(subnets)

    db_parameter_group_name = db_parameter_group['CreateDBParameterGroupResponse']\
                                                ['CreateDBParameterGroupResult']\
                                                ['DBParameterGroup']\
                                                ['DBParameterGroupName']

    db_subnet_group_name = db_subnet_group['CreateDBSubnetGroupResponse']\
                                          ['CreateDBSubnetGroupResult']\
                                          ['DBSubnetGroup']\
                                          ['DBSubnetGroupName']

    inbound_port = {
        'django.db.backends.postgresql_psycopg2': 5432,
        'django.db.backends.mysql':               3306,
        'django.db.backends.oracle':              1520,
    }

    if not security_groups:
        if application_instances:
            # Create rule(s) allowing traffic from application server security group(s).
            application_security_group_ids = set([group.id for instance in application_instances for group in instance.groups])
            inbound_rules = list()
            for application_security_group_id in application_security_group_ids:
                inbound_rule = ('TCP:' + str(inbound_port[DJANGO_ENGINE]), application_security_group_id)
                inbound_rules.append(inbound_rule)

        sg_name = '-'.join(['gp', core.PROJECT_NAME.lower(), core.args.environment.lower(), 'db'])
        security_groups = [ec2.create_security_group(vpc, name=sg_name
                                                        , allowed_inbound_traffic=inbound_rules if application_instances else None
                                                        , allowed_outbound_traffic=[('HTTP',  '0.0.0.0/0')
                                                                                   ,('HTTPS', '0.0.0.0/0')
                                                                                   ,('DNS',   '0.0.0.0/0')])]

    db_instance = rds_connection.create_db_instance('dbinst1',                                                # db_instance_identifier
                                                    5,                                                        # allocated_storage
                                                    'db.t2.micro',                                            # db_instance_class
                                                    engine[DJANGO_ENGINE],                                    # engine
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
                                                    option_group_name=None,
                                                    character_set_name=None,
                                                    publicly_accessible=publicly_accessible,
                                                    tags=None)

    # Construct Database Instance ARN.
    dbinstance_name = 'dbinst1'
    region = 'us-east-1'
    database_arn = 'arn:aws:rds:%s:%s:db:%s' % (region, AWS_ACCOUNT_ID, dbinstance_name)

    # Tag Database Instance.
    logger.debug('Tagging Database instance (%s).' % database_arn)
    rds_connection.add_tags_to_resource(database_arn,                                     # resource_name
                                        [('Name'       , dbinstance_name              ),  # tags
                                         ('Project'    , core.PROJECT_NAME.lower()    ),
                                         ('Environment', core.args.environment.lower())])
    logger.debug('Tagged Database instance (%s).' % database_arn)

    return db_instance
