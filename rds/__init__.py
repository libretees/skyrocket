import sys
import logging
import boto
import core

PROJECT_NAME = core.PROJECT_NAME
DJANGO_ENGINE = core.settings.DATABASES['default']['ENGINE']

logger = logging.getLogger(__name__)

def connect_rds():
    logger.debug('Connecting to the Amazon Relational Database Service (Amazon RDS).')
    rds = boto.connect_rds2(aws_access_key_id=core.args.key_id,
                            aws_secret_access_key=core.args.key)
    logger.debug('Connected to Amazon RDS.')
    
    return rds

def create_db_parameter_group(rds):
    # Affected by boto Issue #2677 : https://github.com/boto/boto/issues/2677
    aws_engine = {
        'django.db.backends.postgresql_psycopg2': 'postgres9.3',
        'django.db.backends.mysql':               'MySQL5.6',
        'django.db.backends.oracle':              'oracle-se1-11.2',
    }
    db_parameter_group_name = '-'.join(['pg', PROJECT_NAME.lower(), core.args.environment.lower(), 'db'])
    pg = rds.create_db_parameter_group(db_parameter_group_name,                                 #db_parameter_group_name
                                       aws_engine[DJANGO_ENGINE],                               #db_parameter_group_family
                                       description=' '.join([PROJECT_NAME, 'Parameter Group'])) #description
    return pg

def create_db_subnet_group(subnets):
    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Generate DB Subnet Group name.
    db_subnet_group_name = '-'.join(['subnetgroup',
                                     PROJECT_NAME.lower(),
                                     core.args.environment.lower(),
                                     'db'])

    # Create DB Subnet Group.
    subnet = rds_connection.create_db_subnet_group(db_subnet_group_name,                        #db_subnet_group_name
                                                   ' '.join([PROJECT_NAME, 'DB Subnet Group']), #db_subnet_group_description
                                                   [subnet.id for subnet in subnets])   #subnet_ids
    return subnet

def create_db_instance(rds, db_parameter_group, db_subnet_group):
    if DJANGO_ENGINE not in ['django.db.backends.postgresql_psycopg2' \
                            ,'django.db.backends.mysql' \
                            ,'django.db.backends.sqlite3' \
                            ,'django.db.backends.oracle']:
        logger.error('Unknown database engine (%s).' % DJANGO_ENGINE, exc_info=True)
        sys.exit(1)
    else:
        logger.info('Provisioning RDS instance for Django engine (%s).' % DJANGO_ENGINE)

    aws_engine = {
        'django.db.backends.postgresql_psycopg2': 'postgres',
        'django.db.backends.mysql':               'MySQL',
        'django.db.backends.oracle':              'oracle-se1',
    }

    db_parameter_group_name = db_parameter_group['CreateDBParameterGroupResponse']\
                                                ['CreateDBParameterGroupResult']\
                                                ['DBParameterGroup']\
                                                ['DBParameterGroupName']

    db_subnet_group_name = db_subnet_group['CreateDBSubnetGroupResponse']\
                                          ['CreateDBSubnetGroupResult']\
                                          ['DBSubnetGroup']\
                                          ['DBSubnetGroupName']

    instance = rds.create_db_instance('dbinst1',                 #db_instance_identifier
                                      5,                         #allocated_storage
                                      'db.t2.micro',             #db_instance_class
                                      aws_engine[DJANGO_ENGINE], #engine
                                      'username',                #master_username
                                      'password',                #master_user_password
                                      #db_security_groups=[db_security_group_name],
                                      db_subnet_group_name=db_subnet_group_name,
                                      db_parameter_group_name=db_parameter_group_name)
    return instance