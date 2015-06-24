import sys
import time
import logging
import boto
from .compute import connect_ec2, create_security_group
from .networking import connect_vpc
from .state import config, mode

logger = logging.getLogger(__name__)

ENGINE = {
    'postgresql': 'postgres9.4',
    'mysql':      'MySQL5.6',
    'oracle':     'oracle-se1-11.2',
}

ENGINE_NAME = {
    'postgresql': 'postgres',
    'mysql':      'MySQL',
    'oracle':     'oracle-se1',
}

MAJOR_ENGINE_VERSION = {
    'postgresql': '9.4',
    'mysql':      '5.1.42',
    'oracle':     '11.2.0.2.v2',
}

INBOUND_PORT = {
    'postgresql': 5432,
    'mysql':      3306,
    'oracle':     1520,
}

def connect_rds():
    """
    Connect to the Amazon Relational Database Service (Amazon RDS) service.

    :rtype: :class:`boto.rds.RDSConnection`
    :return: An :class:`~boto.rds.RDSConnection` object.
    """

    logger.debug('Connecting to the Amazon Relational Database Service (Amazon RDS).')
    rds = boto.connect_rds2(aws_access_key_id=config['AWS_ACCESS_KEY_ID'],
                            aws_secret_access_key=config['AWS_SECRET_ACCESS_KEY'])
    logger.debug('Connected to Amazon RDS.')
    
    return rds


def create_db_parameter_group(name=None, engine='postgresql'):
    """
    Create a DB Parameter Group.

    :type name: str
    :param name: An *optional* name for the DB Parameter Group. A name will
        be generated from the current project name, if one is not specified.

    :type engine: string
    :param engine: The database engine that is configured by the DB Parameter
        Group. This is set to ``postgresql``, by default.

        * Supported database engines: ``postgresql``, ``mysql``, and ``oracle``.

    :rtype: dict
    :return: A dictionary containing the elements of the AWS API ``CreateDBParameterGroupResponse`` response.
    """

    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

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

    # Affected by boto Issue #2677 : https://github.com/boto/boto/issues/2677
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
    """
    Create a DB Subnet Group.

    :type subnets: list
    :param subnets: A list of at least two :class:`~boto.vpc.subnet.Subnet`
        objects that are located in different Availablity Zones (AZs) of the
        same Region.

        For Multi-AZ deployments, these define where the database
        will be created and where the database will be replicated . For
        Single-AZ deployments, these are defined so that it is possible to
        convert the database to Multi-AZ at a later point.

        * See also: :func:`sky.networking.create_subnets`.

    :type name: str
    :param name: An *optional* name for the DB Subnet Group. A name will
        be generated from the current project name, if one is not specified.

    :rtype: dict
    :return: A dictionary containing the elements of the AWS API ``CreateDBSubnetGroupResponse`` response.
    """

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
        subnet = rds_connection.create_db_subnet_group(name,                                                  #db_subnet_group_name
                                                       ' '.join([config['PROJECT_NAME'], 'DB Subnet Group']), #db_subnet_group_description
                                                       [subnet.id for subnet in subnets])                     #subnet_ids
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
    """
    Create an Option Group.

    An option group can specify features, called options, that are available
    for a particular Amazon RDS DB instance. Options can have settings that
    specify how the option works.

    :type name: str
    :param name: An *optional* name for the Option Group. A name will be
        generated from the current project name, if one is not specified.

    :type engine: string
    :param engine: The database engine that is configured by the Option Group.
        This is set to ``postgresql``, by default.

        * Supported database engines: ``postgresql``, ``mysql``, and ``oracle``.

    :rtype: dict
    :return: A dictionary containing the elements of the AWS API ``CreateOptionGroupResponse`` response.
    """

    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Generate Option Group name.
    if not name:
        name = '-'.join(['og',
                         config['PROJECT_NAME'],
                         config['ENVIRONMENT'],])

    # Check for existing Option Group.
    if config['CREATION_MODE'] in [mode.PERMANENT, mode.EPHEMERAL]:
        try:
            response = rds_connection.describe_option_groups(option_group_name=name)
            if response:
                option_group = response['DescribeOptionGroupsResponse']\
                                       ['DescribeOptionGroupsResult']\
                                       ['OptionGroupsList'][-1]
                logger.info('Found existing Option Group (%s).' % option_group['OptionGroupName'])
                if config['CREATION_MODE'] == mode.EPHEMERAL:
                    # Delete Option Group.
                    rds_connection.delete_option_group(name)
                else:
                    return option_group
        except boto.exception.JSONResponseError as error:
            if error.body['Error']['Code'] == 'OptionGroupNotFoundFault':
                pass

    # Create Option Group.
    logger.info('Creating Option Group (%s).' % name)
    option_group = rds_connection.create_option_group(name,                                     # option_group_name
                                                      ENGINE_NAME[engine],                      # engine_name
                                                      MAJOR_ENGINE_VERSION[engine],             # major_engine_version
                                                      ' '.join([config['PROJECT_NAME'], 'Option Group']), # option_group_description
                                                      tags=None)
    logger.info('Created Option Group (%s).' % name)

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

    option_group = option_group['CreateOptionGroupResponse']\
                               ['CreateOptionGroupResult']\
                               ['OptionGroup']

    return option_group


def create_database(subnets, name=None, engine='postgresql', storage=5, application_instances=None, application_security_groups=None, security_groups=None, publicly_accessible=False, multi_az=False, db_parameter_group=None, option_group=None):
    """
    Create a Database Instance.

    :type subnets: list
    :param subnets: A list of at least two :class:`~boto.vpc.subnet.Subnet`
        objects that are located in different Availablity Zones (AZs) of the
        same Region. These :class:`~boto.vpc.subnet.Subnet` objects will be used
        to create a DB Subnet Group.

        * See also: :func:`sky.database.create_db_subnet_group`

    :type name: str
    :param name: An *optional* name for the RDS Instance. A name will be
        generated from the current project name, if one is not specified.

    :type engine: string
    :param engine: The desired database engine. This is set to ``postgresql``,
        by default.

        * Supported database engines: ``postgresql``, ``mysql``, and ``oracle``.

    :type storage: int
    :param storage: The amount of storage (in gigabytes) to be initially
        allocated for the database instance.

    :type application_instances: list
    :param application_instances: An *optional* list of EC2
        :class:`~boto.ec2.instance.Instance` objects that the DB Instance will
        be permitted to receive traffic from.

    :type application_security_groups: list
    :param application_security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the DB
        Instance will be permitted to receive traffic from.

    :type security_groups: :class:`boto.ec2.securitygroup.SecurityGroup`
    :param security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the DB
        Instance will join.

    :type publicly_accessible: bool
    :param publicly_accessible: Whether to alllow devices outside of the VPC
        hosting the DB Instance to connect to the DB Instance. If True, a Public
        IP address is allocated for the DB Instance. By default, this is set to
        ``False`` and a DB Instance is not publicly accessible.

    :type multi_az: bool
    :param multi_az: Whether to provision and maintain a synchronous standby
        replica DB Instance in a different Availability Zone (AZ). By default,
        this is set to ``False`` and a DB Instance will be deployed to a single
        AZ.

    :type db_parameter_group: :class:`boto.jsonresponse.Element`
    :param db_parameter_group: An *optional* DB Parameter Group that specifies
        features and configuration applicable to many database engines.

    :type option_group: :class:`boto.jsonresponse.Element`
    :param option_group: An *optional* Option Group that specifies
         features and configuration specific to the chosen database engine.

    :rtype: dict
    :return: A dictionary containing the elements of the AWS API ``CreateDBInstanceResponse`` response.
    """

    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    # Create a DB Subnet Group.
    db_subnet_group = create_db_subnet_group(subnets)

    if not name:
        name = '-'.join(['db',
                         config['PROJECT_NAME'],
                         config['ENVIRONMENT'],])

    # Check for existing Database.
    if config['CREATION_MODE'] in [mode.PERMANENT, mode.EPHEMERAL]:
        try:
            response = rds_connection.describe_db_instances(db_instance_identifier=name)
            if response:
                db_instance = response['DescribeDBInstancesResponse']\
                                      ['DescribeDBInstancesResult']\
                                      ['DBInstances'][-1]
                endpoint = db_instance['Endpoint']
                db_instance['endpoint'] = endpoint
                logger.info('Found existing Database (%s) at (%s:%s).' % (name, endpoint['Address'], endpoint['Port']))
                if config['CREATION_MODE'] == mode.EPHEMERAL:
                    delete_database(name)
                else:
                    return db_instance
        except boto.rds2.exceptions.DBInstanceNotFound as error:
            if error.code == 'DBInstanceNotFound': # The requested Database doesn't exist.
                pass

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

    option_group_name = option_group['OptionGroupName']

    if not security_groups:
        # Connect to the Amazon Virtual Private Cloud (Amazon VPC) service.
        vpc_connection = connect_vpc()

        # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
        ec2_connection = connect_ec2()

        # Get VPC from Subnets.
        vpc_id = set([subnet.vpc_id for subnet in subnets])
        if not len(vpc_id) == 1:
            raise RuntimeError('The specified subnets (%s) must be parts of the same network.' % ', '.join([subnet.tags['Name'] for subnet in subnets]))
        else:
            vpc_id = next(iter(vpc_id))
        vpc = vpc_connection.get_all_vpcs(vpc_ids=[vpc_id])[-1]

        application_security_group_ids = set()

        # Get ingress Security Group IDs from Instance objects.
        if application_instances:
            # Create rule(s) allowing traffic from application server security group(s).
            application_security_group_ids |= set([group.id for instance in application_instances for group in instance.groups])

        # Get ingress Security Group IDs.
        if application_security_groups:
            # Create rule(s) allowing traffic from application security group(s).
            application_security_group_ids |= set([group.id for group in application_security_groups])

        # Create ingress rules.
        inbound_rules = list()
        for application_security_group_id in application_security_group_ids:
            inbound_rule = ('TCP:' + str(INBOUND_PORT[engine]), application_security_group_id)
            inbound_rules.append(inbound_rule)

        # Create Security Group.
        sg_name = '-'.join(['gp', config['PROJECT_NAME'], config['ENVIRONMENT'], 'db'])
        database_security_group = create_security_group(vpc,
                                                        name=sg_name,
                                                        allowed_inbound_traffic=inbound_rules if application_security_groups else [],
                                                        allowed_outbound_traffic=[]) # Outbound rules do not apply to RDS instances (per http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html).

        for application_security_group_id in application_security_group_ids:
            ec2_connection.authorize_security_group_egress(application_security_group_id,
                                                           'tcp',
                                                           from_port=INBOUND_PORT[engine],
                                                           to_port=INBOUND_PORT[engine],
                                                           src_group_id=database_security_group.id,
                                                           cidr_ip=None)

        security_groups = [database_security_group]

    logger.info('Creating Database Instance (%s)' % name)
    db_instance = rds_connection.create_db_instance(name,                                                     # db_instance_identifier
                                                    storage,                                                  # allocated_storage
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
                                                    engine_version=MAJOR_ENGINE_VERSION[engine],
                                                    auto_minor_version_upgrade=None,
                                                    license_model=None,
                                                    iops=None,
                                                    option_group_name=option_group_name,
                                                    character_set_name=None,
                                                    publicly_accessible=publicly_accessible,
                                                    tags=None)
    logger.info('Created Database Instance (%s)' % name)

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
    logger.info('Getting Endpoint for Database Instance (%s).' % name)
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
            logger.debug('Waiting for Database Endpoint...')
            time.sleep(1)
        else:
            logger.info('Got Database Endpoint (%s).' % endpoint)
    db_instance['endpoint'] = endpoint

    return db_instance


def delete_database(name):
    """
    Delete a Database Instance.

    :type name: str
    :param name: The name of the Database Instance to delete.

    :rtype: bool
    :return: ``True`` if the Database Instance was successfully deleted.
        Otherwise, ``False``.
    """

    # Connect to the Amazon Relational Database Service (Amazon RDS).
    rds_connection = connect_rds()

    response = rds_connection.describe_db_instances(db_instance_identifier=name)

    if response:
        db_instance = response['DescribeDBInstancesResponse']\
                      ['DescribeDBInstancesResult']\
                      ['DBInstances'][-1]
        db_instance_identifier = db_instance['DBInstanceIdentifier']
        logger.info('Initiating Database Instance (%s) deletion.' % name)
        rds_connection.delete_db_instance(db_instance_identifier, skip_final_snapshot=True)
        logger.info('Initiated Database Instance (%s) deletion.' % name)

        while response:
            try:
                response = rds_connection.describe_db_instances(db_instance_identifier=name)
                logger.info('Deleting Database Instance (%s)...' % name)
                time.sleep(60)
            except boto.rds2.exceptions.DBInstanceNotFound as error:
                if error.code == 'DBInstanceNotFound':
                    pass

        logger.info('Deleted Database Instance (%s).' % name)

    return True if not response else False
