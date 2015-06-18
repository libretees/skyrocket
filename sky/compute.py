import re
import time
import random
import logging
from operator import itemgetter
import boto
from .networking import connect_vpc, create_route_table
from .state import config, mode

logger = logging.getLogger(__name__)

def connect_ec2():
    """
    Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.

    :rtype: :class:`boto.ec2.connection.EC2Connection`
    :return: An :class:`~boto.ec2.connection.EC2Connection` object.
    """

    logger.debug('Connecting to the Amazon Elastic Compute Cloud (Amazon EC2) service.')
    ec2 = boto.connect_ec2(aws_access_key_id=config['AWS_ACCESS_KEY_ID'],
                           aws_secret_access_key=config['AWS_SECRET_ACCESS_KEY'])
    logger.debug('Connected to Amazon EC2.')

    return ec2

def create_security_group(vpc, name=None, database_backend=None, allowed_inbound_traffic=[], allowed_outbound_traffic=[]):
    """
    Create an Amazon EC2-VPC Security Group.

    :type vpc: :class:`boto.vpc.vpc.VPC`
    :param vpc: The :class:`~boto.vpc.vpc.VPC` that the Security Group will
        join.

    :type name: str
    :param name: An *optional* name for the EC2-VPC security group. A name will
        be generated from the current project name, if one is not specified.

    :type database_backend: string
    :param database_backend: An *optional* database backend. This is intended to
        be used with application security groups that require outbound traffic
        to a database.

        * Supported database backends: ``postgresql``, ``mysql``, and ``oracle``.

    :type allowed_inbound_traffic: list
    :param allowed_inbound_traffic: A list of tuples in the format:
        ``(protocol, cidr_block)`` or ``(protocol, security_group)``.

        * **protocol** (*string*):

            * Supported inbound protocols: ``HTTP``, ``HTTPS``, ``TCP:Port`` (e.g., ``TCP:80``), and ``UDP:Port`` (e.g., ``UDP:1337``).

        * **cidr_block** (*string*):

            * A range of IP addresses from which inbound traffic is allowed.

        * **security_group** (:class:`~boto.ec2.securitygroup.SecurityGroup`)

            * A :class:`~boto.ec2.securitygroup.SecurityGroup` that the inbound traffic originates from.

    :type allowed_outbound_traffic: list
    :param allowed_outbound_traffic: A list of tuples in the format:
        ``(protocol, cidr_block)`` or ``(protocol, security_group)``.

        * **protocol** (*string*):

            * Supported outbound protocols: ``HTTP``, ``HTTPS``, ``DNS``, ``TCP:Port`` (e.g., ``TCP:80``), and ``UDP:Port`` (e.g., ``UDP:1337``).

        * **cidr_block** (*string*):

            * A range of IP addresses to which outbound traffic is allowed.

        * **security_group** (:class:`~boto.ec2.securitygroup.SecurityGroup`)

            * A :class:`~boto.ec2.securitygroup.SecurityGroup` that the outbound traffic is destined to.

    :rtype: :class:`boto.ec2.securitygroup.SecurityGroup`
    :return: An Amazon EC2-VPC Security Group.
    """

    # Defer import to resolve interdependency between .database and .compute modules.
    from .database import INBOUND_PORT

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Generate Security Group name.
    if not name:
        name = '-'.join(['gp', config['PROJECT_NAME'], config['ENVIRONMENT']])

    # Check for existing Security Group.
    if config['CREATION_MODE'] in [mode.PERMANENT, mode.EPHEMERAL]:
        try:
            existing_security_group = ec2_connection.get_all_security_groups(filters={'group-name': name,})
            if len(existing_security_group):
                existing_security_group = existing_security_group[-1]
                logger.info('Found existing Security Group (%s).' % name)
                if config['CREATION_MODE'] == mode.EPHEMERAL:
                    delete_security_group(existing_security_group)
                else:
                    return existing_security_group
        except boto.exception.EC2ResponseError as error:
            if error.code == 'InvalidGroup.NotFound': # The requested Security Group doesn't exist.
                pass

    if database_backend:
        allowed_outbound_traffic.append(('TCP:%d' % INBOUND_PORT[database_backend], '0.0.0.0/0'))

    # Create Security Group.
    logger.info('Creating Security Group (%s).' % name)
    security_group = ec2_connection.create_security_group(name, 'Security Group Description', vpc_id=vpc.id)
    logger.info('Created Security Group (%s).' % name)

    # Set up inbound/outbound rules.
    ec2_connection.revoke_security_group_egress(security_group.id, -1, from_port=0, to_port=65535, cidr_ip='0.0.0.0/0')
    for (protocol, target, rule_type) in [(traffic[0].upper(), traffic[1], 'inbound') for traffic in allowed_inbound_traffic] + \
                                         [(traffic[0].upper(), traffic[1], 'outbound') for traffic in allowed_outbound_traffic]:

        # Determine whether target is a CIDR block or a Security Group.
        is_cidr_ip = re.search('^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'+      # A in A.B.C.D
                               '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.' +      # B in A.B.C.D
                               '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.' +      # C in A.B.C.D
                               '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'   +      # D in A.B.C.D
                               '(/(([1-2]?[0-9])|(3[0-2])))$', str(target)) # /0 through /32
        target_cidr_ip = target if is_cidr_ip else None
        target_group = ec2_connection.get_all_security_groups(group_ids=[target])[-1] if not is_cidr_ip else None

        # Determine port range for TCP and UDP rules.
        port = None
        if protocol[:3] in ['TCP', 'UDP']:
            protocol, port = itemgetter(0, 1)(protocol.split(':'))
            if re.search(r'^\d+\-\d+$', port):
                from_port, to_port = itemgetter(0, 1)(port.split('-'))
            else:
                from_port, to_port = port, port

        # Create inbound rules.
        if rule_type == 'inbound':
            if protocol == 'HTTP':
                security_group.authorize(ip_protocol='tcp', from_port=80, to_port=80, src_group=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'HTTPS':
                security_group.authorize(ip_protocol='tcp', from_port=443, to_port=443, src_group=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'TCP':
                security_group.authorize(ip_protocol='tcp', from_port=int(from_port), to_port=int(to_port), src_group=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'UDP':
                security_group.authorize(ip_protocol='udp', from_port=int(from_port), to_port=int(to_port), src_group=target_group, cidr_ip=target_cidr_ip)
            logger.info('Security Group (%s) allowed inbound %s traffic from %s.' % (name, protocol + (' Port %s' % port if port else ''), target))

        # Create outbound rules.
        if rule_type == 'outbound':
            if protocol == 'HTTP':
                ec2_connection.authorize_security_group_egress(security_group.id, 'tcp', from_port=80, to_port=80, src_group_id=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'HTTPS':
                ec2_connection.authorize_security_group_egress(security_group.id, 'tcp', from_port=443, to_port=443, src_group_id=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'DNS':
                ec2_connection.authorize_security_group_egress(security_group.id, 'tcp', from_port=53, to_port=53, src_group_id=target_group, cidr_ip=target_cidr_ip)
                ec2_connection.authorize_security_group_egress(security_group.id, 'udp', from_port=53, to_port=53, src_group_id=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'TCP':
                 ec2_connection.authorize_security_group_egress(security_group.id, 'tcp', from_port=int(from_port), to_port=int(to_port), src_group_id=target_group, cidr_ip=target_cidr_ip)
            elif protocol == 'UDP':
                 ec2_connection.authorize_security_group_egress(security_group.id, 'udp', from_port=int(from_port), to_port=int(to_port), src_group_id=target_group, cidr_ip=target_cidr_ip)
            logger.info('Security Group (%s) allowed outbound %s traffic to %s.' % (name, protocol + (' Port %s' % port if port else ''), target))

    # Tag Security Group.
    tagged = False
    while not tagged:
        try:
            tagged = ec2_connection.create_tags(security_group.id, {'Name': name,
                                                                    'Project': config['PROJECT_NAME'],
                                                                    'Environment': config['ENVIRONMENT'],})
        except boto.exception.EC2ResponseError as error:
            if error.code == 'InvalidID': # Security Group hasn't registered with EC2 service yet.
                pass
            else:
                raise boto.exception.EC2ResponseError

    return security_group


def delete_security_group(security_group):
    """
    Delete a Security Group.

    :type security_group: :class:`boto.ec2.securitygroup.SecurityGroup`
    :param security_group: The :class:`~boto.ec2.securitygroup.SecurityGroup`
        that will be deleted.

        * See also: :func:`sky.compute.create_security_group`.

    :rtype: bool
    :return: ``True`` if the :class:`~boto.ec2.securitygroup.SecurityGroup`
        was successfully deleted. Otherwise, ``False``.
    """

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Get Security Group name.
    sg_name = security_group.tags['Name']

    # Delete Security Group.
    logger.info('Deleting Security Group (%s).' % sg_name)
    result = False
    try:
        result = ec2_connection.delete_security_group(group_id=security_group.id)
        logger.info('Deleted Security Group (%s).' % sg_name)
    except boto.exception.EC2ResponseError as error:
        logger.info('Could not delete Security Group (%s).' % sg_name)
        if error.code == 'DependencyViolation':
            pass

    return result


def create_load_balancer(subnets, name=None, security_groups=None, ssl_certificate=None):
    """
    Create an Elastic Load Balancer (ELB).

    :type subnets: list
    :param subnets: A list of :class:`~boto.vpc.subnet.Subnet` objects that
        will share inbound traffic.

        * See also: :func:`sky.networking.create_subnets`.

    :type name: string
    :param name: An *optional* name for the Load Balancer. A name will be
        generated from the current project name, if one is not specified.

    :type security_groups: list
    :param security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the Load
        Balancer will join.

        * See also: :func:`sky.compute.create_security_group`.

    :type ssl_certificate: string
    :param ssl_certificate: The Amazon Resource Name (ARN) of an uploaded SSL
        Certificate. This is required only if HTTPS/SSL load balancer listeners
        are desired.

        * See also: :func:`sky.security.upload_ssl_certificate`.

    :rtype: :class:`boto.ec2.elb.loadbalancer.LoadBalancer`
    :return: An Elastic Load Balancer (ELB).
    """

    # Connect to the Amazon EC2 Load Balancing (Amazon ELB) service.
    logger.debug('Connecting to the Amazon EC2 Load Balancing (Amazon ELB) service.')
    elb_connection = boto.connect_elb()
    logger.debug('Connected to the Amazon EC2 Load Balancing (Amazon ELB) service.')

    # Generate Elastic Load Balancer (ELB) name.
    if not name:
        name = '-'.join(['elb', config['PROJECT_NAME'], config['ENVIRONMENT']])

    # Check for existing Load Balancer.
    if config['CREATION_MODE'] in [mode.PERMANENT, mode.EPHEMERAL]:
        try:
            existing_load_balancer = elb_connection.get_all_load_balancers(load_balancer_names=[name])
            if len(existing_load_balancer):
                existing_load_balancer = existing_load_balancer[-1]
                logger.info('Found existing Load Balancer (%s) at (%s).' % (existing_load_balancer.name, existing_load_balancer.dns_name))
                if config['CREATION_MODE'] == mode.EPHEMERAL:
                    delete_load_balancer(existing_load_balancer)
                else:
                    return existing_load_balancer
        except boto.exception.BotoServerError as error:
            if error.code == 'LoadBalancerNotFound': # The requested Load Balancer doesn't exist.
                pass

    # Set up default security group, if necessary
    if not security_groups:
        # Connect to the Amazon Virtual Private Cloud (Amazon VPC) service.
        vpc_connection = connect_vpc()

        # Get VPC from Subnets.
        vpc_id = subnets[-1].vpc_id
        vpc = vpc_connection.get_all_vpcs(vpc_ids=[vpc_id])[-1]

        security_group_name = '-'.join(['gp', config['PROJECT_NAME'], config['ENVIRONMENT'], 'elb'])
        security_groups = [create_security_group(vpc,
                                                 name=security_group_name,
                                                 allowed_inbound_traffic=[('HTTP',   '0.0.0.0/0')
                                                                         ,('HTTPS',  '0.0.0.0/0')],
                                                 allowed_outbound_traffic=[('HTTP',  '0.0.0.0/0')
                                                                          ,('HTTPS', '0.0.0.0/0')
                                                                          ,('DNS',   '0.0.0.0/0')])]

    # Set up basic HTTP listener.
    complex_listeners = [(80, 80, 'HTTP', 'HTTP')]

    # Add HTTPS listener if a SSL certificate was specified.
    if ssl_certificate:
        complex_listeners.append((443, 443, 'HTTPS', 'HTTPS', ssl_certificate))

    # Create Elastic Load Balancer (ELB).
    logger.info('Creating Elastic Load Balancer (%s).' % name)
    load_balancer = elb_connection.create_load_balancer(name, # name
                                                        None, # zones             # Valid only for load balancers in EC2-Classic.
                                                        listeners=None,
                                                        subnets=[subnet.id for subnet in subnets],
                                                        security_groups=[security_group.id for security_group in security_groups],
                                                        scheme='internet-facing', # Valid only for load balancers in EC2-VPC.
                                                        complex_listeners=complex_listeners)
    logger.info('Created Elastic Load Balancer (%s).' % name)

    return load_balancer


def delete_load_balancer(load_balancer):
    """
    Delete a Load Balancer.

    :type load_balancer: :class:`boto.ec2.elb.loadbalancer.LoadBalancer`
    :param load_balancer: The :class:`~boto.ec2.elb.loadbalancer.LoadBalancer`
        that will be deleted

        * See also: :func:`sky.compute.create_load_balancer`.

    :rtype: bool
    :return: ``True`` if the :class:`~boto.ec2.elb.loadbalancer.LoadBalancer`
        was successfully deleted. Otherwise, ``False``.
    """

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    logger.debug('Connecting to the Amazon EC2 Load Balancing (Amazon ELB) service.')
    elb_connection = boto.connect_elb()
    logger.debug('Connected to the Amazon EC2 Load Balancing (Amazon ELB) service.')

    # Delete existing Elastic Load Balancer (ELB).
    logger.info('Deleting Elastic Load Balancer (%s).' % load_balancer.name)
    result = False
    try:
        result = elb_connection.delete_load_balancer(load_balancer.name)
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t delete Elastic Load Balancer (%s) due to a malformed request %s: %s.' % (load_balancer.name, error.status, error.reason))
        if error.status == 404: # Not Found
            logger.error('Elastic Load Balancer (%s) was not found. Error %s: %s.' % (load_balancer.name, error.status, error.reason))
    logger.info('Deleted Elastic Load Balancer (%s).' % load_balancer.name)

    # Get Load Balancer Security Group ID(s).
    group_ids = [group for group in load_balancer.security_groups]

    # Delete Network Interface(s).
    for group_id in group_ids:
        network_interfaces = ec2_connection.get_all_network_interfaces(filters={'group-id': group_id,})
        for network_interface in network_interfaces:
            ec2_connection.delete_network_interface(network_interface_id=network_interface.id)

    # Clean up orphaned Security Group(s).
    security_groups = ec2_connection.get_all_security_groups(group_ids=group_ids)
    if len(security_groups):
        for security_group in security_groups:
            delete_security_group(security_group)

    return result


def create_nat_instances(public_subnets, private_subnets, security_groups=None, image_id=None):
    '''
    Create NAT (Network Address Translation) Instances.

    :type public_subnets: list
    :param public_subnets: A list of :class:`~boto.vpc.subnet.Subnet` objects
        that the NAT Instances will route traffic from.

        * See also: :func:`sky.networking.create_subnets`.

    :type private_subnets: list
    :param private_subnets: A list of :class:`~boto.vpc.subnet.Subnet` objects
        that the NAT Instances will route traffic to.

        * See also: :func:`sky.networking.create_subnets`.

    :type security_groups: list
    :param security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the NAT
        Instances will join.

        * See also: :func:`sky.compute.create_security_group`.

    :type image_id: string
    :param image_id: An *optional* AMI (Amazon Machine Image) ID that determines
        the OS and Virtualization Type that the NAT Instances will use. By
        default, this is the AMI ID returned by :func:`sky.compute.get_nat_image`.

    :rtype: list
    :return: A list of NAT :class:`~boto.ec2.instance.Instance` objects.
    '''

    # Ensure that there is a one-to-one match between Public Subnets and Private Subnets.
    if not len(public_subnets) == len(private_subnets):
        raise RuntimeError('The number of Public/Private Subnets must match (Public: %d Private: %d).' % (len(public_subnets), len(private_subnets)))

    # Pair Public and Private Subnets together by availability zone.
    subnet_pairs = list(zip(sorted(public_subnets, key=lambda x: x.availability_zone), sorted(private_subnets, key=lambda x: x.availability_zone)))

    # Create NAT instances.
    nat_instances = list()
    for (public_subnet, private_subnet) in subnet_pairs:
        nat_instance = create_nat_instance(public_subnet, private_subnet, name=None, security_groups=None, image_id=None)
        nat_instances.append(nat_instance)

    return nat_instances


def create_nat_instance(public_subnet, private_subnet, name=None, security_groups=None, image_id=None):
    '''
    Create a NAT (Network Address Translation) Instance.

    :type public_subnet: :class:`boto.vpc.subnet.Subnet`
    :param public_subnet: The subnet that the NAT Instance will route traffic
        from.

        * See also: :func:`sky.networking.create_subnet`.

    :type private_subnet: :class:`boto.vpc.subnet.Subnet`
    :param private_subnet: The subnet that the NAT Instance will route traffic
        to.

        * See also: :func:`sky.networking.create_subnet`.

    :type name: str
    :param name: An *optional* name for the NAT Instance. A name will be
        generated from the current project name, if one is not specified.

    :type security_groups: list
    :param security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the NAT
        Instance will join.

        * See also: :func:`sky.compute.create_security_group`.

    :type image_id: string
    :param image_id: An *optional* AMI (Amazon Machine Image) ID that determines
        the OS and Virtualization Type that the NAT Instance will use. By
        default, this is the AMI ID returned by
        :func:`sky.compute.get_nat_image`.

    :rtype: :class:`boto.ec2.instance.Instance`
    :return: A NAT Instance.
    '''

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Connect to the Amazon Virtual Private Cloud (Amazon VPC) service.
    vpc_connection = connect_vpc()

    # Generate name, if one was not specified.
    if not name:
        name = '-'.join(['ec2', config['PROJECT_NAME'], config['ENVIRONMENT'], public_subnet.availability_zone, 'nat'])

    # Check for existing NAT Server.
    if config['CREATION_MODE'] == mode.PERMANENT:
         nat_instances = get_instances(name=name, role='nat')
         if len(nat_instances):
             logger.info('Found existing NAT Server (%s).' % name)
             return nat_instances

    # Get VPC from Subnets.
    vpc_id = set([subnet.vpc_id for subnet in [public_subnet, private_subnet]])
    if not len(vpc_id) == 1:
        raise RuntimeError('The specified subnets (%s, %s) must be parts of the same network.' % (public_subnet.tags['Name'], private_subnet.tags['Name']))
    else:
        vpc_id = next(iter(vpc_id))
    vpc = vpc_connection.get_all_vpcs(vpc_ids=[vpc_id])[-1]

    # Create Security Group, if one was not specified.
    if not security_groups:
        sg_name = '-'.join(['gp', config['PROJECT_NAME'], config['ENVIRONMENT'], public_subnet.availability_zone, 'nat'])
        security_groups = [create_security_group(vpc, name=sg_name
                                                    , allowed_inbound_traffic=[('HTTP',   private_subnet.cidr_block)
                                                                              ,('HTTPS',  private_subnet.cidr_block)]
                                                    , allowed_outbound_traffic=[('HTTP',  '0.0.0.0/0')
                                                                               ,('HTTPS', '0.0.0.0/0')
                                                                               ,('DNS',   '0.0.0.0/0')])]

    # Get Amazon Linux VPC NAT AMI, if one was not specified.
    if not image_id:
        image = get_nat_image()
        image_id = image.id

    # Create NAT Instance.
    nat_instance = create_instance(public_subnet,
                                   name=name,
                                   role='nat',
                                   security_groups=security_groups,
                                   image_id=image_id,
                                   internet_addressable=True)

    # Disable source/destination checking.
    ec2_connection.modify_instance_attribute(nat_instance.id, attribute='sourceDestCheck', value=False, dry_run=False)

    # Create Route table.
    route_table_name = '-'.join(['rtb', config['PROJECT_NAME'], config['ENVIRONMENT'], public_subnet.availability_zone, 'private'])
    route_table = create_route_table(vpc, name=route_table_name, internet_access=False)

    # Wait for NAT instance to run.
    while (nat_instance.state == 'pending'):
        logger.debug('Waiting for NAT instance to run (%s)...' % nat_instance.id)
        time.sleep(1)
        nat_instance.update()

    # Add route to NAT Instance to Route Table.
    vpc_connection.create_route(route_table.id,    # route_table_id
                                '0.0.0.0/0',       # destination_cidr_block
                                gateway_id=None,
                                instance_id=nat_instance.id,
                                interface_id=None,
                                vpc_peering_connection_id=None,
                                dry_run=False)

    # Check for existing Route Table association.
    route_tables = vpc_connection.get_all_route_tables(filters={'vpc-id': vpc.id,})
    existing_association = [association.id for route_table in route_tables for association in route_table.associations if association.subnet_id == private_subnet.id]
    existing_association = existing_association[0] if existing_association else None

    # Associate Private Subnet to Route Table.
    if existing_association:
        association = vpc_connection.replace_route_table_association_with_assoc(existing_association, # association_id
                                                                                route_table.id,       # route_table_id
                                                                                dry_run=False)
    else:
        association = vpc_connection.associate_route_table(route_table.id,    # route_table_id
                                                           private_subnet.id, # subnet_id
                                                           dry_run=False)
    if len(association):
        logger.debug('Subnet (%s) associated to (%s).' % (private_subnet.id, route_table.tags['Name']))
    else:
        logger.error('Subnet (%s) not associated to (%s).' % (private_subnet.id, route_table.tags['Name']))

    # Clean up unused/orphaned Route Tables.
    route_tables = vpc_connection.get_all_route_tables(filters={'vpc-id': vpc.id,})
    main_route_table = vpc_connection.get_all_route_tables(filters={'vpc-id': vpc.id,
                                                                    'association.main': 'true'})[0] # Affected by boto Issue #1742 : https://github.com/boto/boto/issues/1742
    empty_route_tables = [route_table for route_table in route_tables if not len(route_table.associations) and not route_table.id == main_route_table.id]
    for route_table in empty_route_tables:
        try:
            vpc_connection.delete_route_table(route_table.id, dry_run=False)
        except boto.exception.EC2ResponseError as error:
            if error.code == 'DependencyViolation': # Route Table was not actually empty.
                pass

    return nat_instance


def create_instances(subnets, role=None, security_groups=None, script=None, instance_profile=None, os='ubuntu', image_id=None, key_name=None, internet_addressable=False):
    '''
    Create EC2 Instances across subnets.

    :type subnets: list
    :param subnets: A list of :class:`~boto.vpc.subnet.Subnet` objects
        that the EC2 Instances will be created in.

        * See also: :func:`sky.networking.create_subnets`.

    :type role: str
    :param role: An *optional* role for the EC2 Instance. This string will be
        added to the EC2 Instance's tags, if specified.

    :type security_groups: list
    :param security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the EC2
        Instances will join.

        * See also: :func:`sky.compute.create_security_group`.

    :type script: str
    :param script: An *optional* user-data script that is executed when the EC2
        Instance is run for the first time.

        * See also: :func:`sky.utils.get_script`.

    :type instance_profile: :class:`boto.jsonresponse.Element`
    :param instance_profile: An *optional* IAM Instance Profile for the EC2
        Instance. This grants permission for an EC2 Instance to perform
        interactions with other AWS resources.

        * See also: :func:`sky.security.create_role`.

    :type os: str
    :param os: The OS that will run on the EC2 Instance. For convenience,
        ``amazon-linux``, ``redhat``, ``suse``, and ``ubuntu`` are available.

    :type image_id: str
    :param image_id: The Amazon Machine Image (AMI) that will run on the EC2
        Instance. Note that if both the ``os`` and ``image_id`` parameters are
        specified, the ``image_id`` parameter will take precedence.

    :type key_name: str
    :param key_name: An *optional* Amazon EC2 Key Pair name. This should be
        specified if remote access to the server is desired.

    :type internet_addressable: bool
    :param internet_addressable: Specifies whether the EC2 Instances will be
        accessible via the Internet. If set to ``True``, a Public IP address
        will be associated to the EC2 Instances. By default, the EC2 Instances
        are *not* Internet-addressable.

    :rtype: list
    :return: A list of EC2 :class:`~boto.ec2.instance.Instance` objects.
    '''

    # Create a security group, if a security group was not specified.
    if not security_groups:
        # Connect to the Amazon Virtual Private Cloud (Amazon VPC) service.
        vpc_connection = connect_vpc()

        # Get VPC from Subnets.
        vpc_id = set([subnet.vpc_id for subnet in subnets])
        if not len(vpc_id) == 1:
            raise RuntimeError('The specified subnets (%s) must be parts of the same network.' % ', '.join([subnet.tags['Name'] for subnet in subnets]))
        else:
            vpc_id = next(iter(vpc_id))
        vpc = vpc_connection.get_all_vpcs(vpc_ids=[vpc_id])[-1]

        # Create a default security group.
        security_groups = [create_security_group(vpc, allowed_inbound_traffic=[('HTTP',   '0.0.0.0/0')
                                                                              ,('HTTPS',  '0.0.0.0/0')]
                                                    , allowed_outbound_traffic=[('HTTP',  '0.0.0.0/0')
                                                                               ,('HTTPS', '0.0.0.0/0')
                                                                               ,('DNS',   '0.0.0.0/0')])]

    # Create EC2 instances.
    instances = list()
    for subnet in subnets:
        instance = create_instance(subnet, role=role, security_groups=security_groups, script=script, instance_profile=instance_profile, os=os, image_id=image_id, key_name=key_name, internet_addressable=internet_addressable)
        instances = instances.append(instance)
    return instances


def create_instance(subnet, name=None, role=None, security_groups=None, script=None, instance_profile=None, os='ubuntu', image_id=None, key_name=None, internet_addressable=False):
    '''
    Create an EC2 Instance.

    :type subnet: :class:`boto.vpc.subnet.Subnet`
    :param subnet: The Subnet that the EC2 Instance will be created in.

        * See also: :func:`sky.networking.create_subnet`.

    :type name: str
    :param name: An *optional* name for the EC2 Instance. A name will be
        generated from the current project name, if one is not specified.

    :type role: str
    :param role: An *optional* role for the EC2 Instance. This string will be
        added to the EC2 Instance's tags, if specified.

    :type security_groups: list
    :param security_groups: An *optional* list of
        :class:`~boto.ec2.securitygroup.SecurityGroup` objects that the EC2
        Instance will join.

        * See also: :func:`sky.compute.create_security_group`.

    :type script: str
    :param script: An *optional* user-data script that is executed when the EC2
        Instance is run for the first time.

        * See also: :func:`sky.utils.get_script`.

    :type instance_profile: :class:`boto.jsonresponse.Element`
    :param instance_profile: An *optional* IAM Instance Profile for the EC2
        Instance. This grants permission for an EC2 Instance to perform
        interactions with other AWS resources.

        * See also: :func:`sky.security.create_role`.

    :type os: str
    :param os: The OS that will run on the EC2 Instance. For convenience,
        ``amazon-linux``, ``redhat``, ``suse``, and ``ubuntu`` are available.

    :type image_id: str
    :param image_id: The Amazon Machine Image (AMI) that will run on the EC2
        Instance. Note that if both the ``os`` and ``image_id`` parameters are
        specified, the ``image_id`` parameter will take precedence.

    :type key_name: str
    :param key_name: An *optional* Amazon EC2 Key Pair name. This should be
        specified if remote access to the server is desired.

    :type internet_addressable: bool
    :param internet_addressable: Specifies whether the EC2 Instance will be
        accessible via the Internet. If set to ``True``, a Public IP address
        will be associated to the EC2 Instance. By default, an EC2 Instance is
        *not* Internet-addressable.

    :rtype: :class:`boto.ec2.instance.Instance`
    :return: An EC2 Instance.
    '''

    # Set up dictionary of OSes and their associated quick-start Amazon Machine Images (AMIs).
    ami = {
        'amazon-linux': 'ami-146e2a7c',
        'redhat':       'ami-12663b7a',
        'suse':         'ami-aeb532c6',
        'ubuntu':       'ami-9a562df2',
    }

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Determine whether to use a start-up AMI or a specific AMI.
    if image_id:
        image = ec2_connection.get_image(image_id)
        if not image:
            raise RuntimeError('The specified Amazon Machine Image (AMI) could not be found (%s).' % image_id)
    else:
        image_id = ami[os]

    # Generate EC2 Instance name, if one was not specified.
    if not name:
        random_id = '{:08x}'.format(random.randrange(2**32))
        name = '-'.join(['ec2', config['PROJECT_NAME'], config['ENVIRONMENT'], random_id])

    # Generate Elastic Network Interface (ENI) name.
    eni_name = '-'.join(['eni', name.replace('ec2-', '')])

    # Create Elastic Network Interface (ENI) specification.
    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet.id,
                                                                        groups=[security_group.id for security_group in security_groups],
                                                                        associate_public_ip_address=internet_addressable)
    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

    # Create EC2 Reservation.
    logger.info('Creating EC2 Instance (%s) in %s.' % (name, subnet.availability_zone))
    reservation = ec2_connection.run_instances(image_id,                 # image_id
                                               key_name=key_name,
                                               instance_type='t2.micro',
                                               instance_profile_name=instance_profile['role_name'] if instance_profile else None,
                                               network_interfaces=interfaces,
                                               user_data=script)
    logger.info('Created EC2 Instance (%s).' % name)

    # Get EC2 Instances.
    instances = [instances for instances in reservation.instances]

    # Tag EC2 Instances.
    tagged = False
    while not tagged:
        try:
            # Set up tags.
            tags = {'Name': name,
                    'Project': config['PROJECT_NAME'],
                    'Environment': config['ENVIRONMENT'],}
            if role:
                tags['Role'] = role

            # Tag EC2 Instance.
            tagged = ec2_connection.create_tags([instance.id for instance in instances], tags)
        except boto.exception.EC2ResponseError as error:
            if error.code == 'InvalidInstanceID.NotFound': # Instance hasn't registered with EC2 service yet.
                pass
            else:
                raise boto.exception.EC2ResponseError

    # Get Elastic Network Interface (ENI) attached to instances.
    interfaces = None
    while not interfaces:
        try:
            interfaces = ec2_connection.get_all_network_interfaces(filters={'attachment.instance-id': [instance.id for instance in instances]})
        except boto.exception.EC2ResponseError as error:
            if error.code == 'InvalidInstanceID.NotFound': # Instance hasn't registered with EC2 service yet.
                pass
            else:
                raise boto.exception.EC2ResponseError

    # Tag Elastic Network Interface (ENI).
    tagged = False
    while not tagged:
        try:
            tagged = ec2_connection.create_tags([interface.id for interface in interfaces], {'Name': eni_name,
                                                                                             'Project': config['PROJECT_NAME'],
                                                                                             'Environment': config['ENVIRONMENT']})
        except boto.exception.EC2ResponseError as error:
            if error.code == 'InvalidNetworkInterfaceID.NotFound': # ENI hasn't registered with EC2 service yet.
                pass
            else:
                raise boto.exception.EC2ResponseError

    # Refresh EC2 instance objects.
    reservations = ec2_connection.get_all_instances(instance_ids=[instance.id for instance in instances])
    instance = next(instance for reservation in reservations for instance in reservation.instances)

    return instance


def get_nat_image(paravirtual=False):
    '''
    Retrieve the most-recent Amazon Linux NAT AMI from the AWS Marketplace.

    :type paravirtual: bool
    :param paravirtual: Specifies whether the NAT AMI virtualization type is
        paravirtual or (PV) or hardware virtual machine (HVM). By default, a NAT
        HVM image will be retrieved.

    :rtype: :class:`boto.ec2.image.Image`
    :return: A NAT :class:`~boto.ec2.image.Image`.
    '''

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Get paravirtual (PV) or hardware virtual machine (HVM) Amazon Linux VPC NAT AMIs.
    images = ec2_connection.get_all_images(filters={'owner-alias': 'amazon',
                                                    'name': 'amzn-ami-vpc-nat-' + ('pv' if paravirtual else 'hvm') + '*',})

    # Return the most recent AMI.
    image = sorted(images, key=lambda x: x.name.split('-')[5])[-1]

    return image


def register_instances(load_balancer, instances):
    '''
    Register EC2 Instances with an Elastic Load Balancer (ELB).

    * See also: :func:`sky.compute.deregister_instances` and :func:`sky.compute.rotate_instances`.

    :type load_balancer: :class:`boto.ec2.elb.loadbalancer.LoadBalancer`
    :param load_balancer: The :class:`~boto.ec2.elb.loadbalancer.LoadBalancer`
        that the EC2 Instances will be registered to.

        * See also: :func:`sky.compute.create_load_balancer`.

    :type instances: list
    :param instances: A list of EC2 :class:`~boto.ec2.instance.Instance` objects
        that will be registered to the Elastic Load Balancer (ELB).

        * See also: :func:`sky.compute.create_instances`.
    '''

    # Connect to the Amazon EC2 Load Balancing (Amazon ELB) service.
    logger.debug('Connecting to the Amazon EC2 Load Balancing (Amazon ELB) service.')
    elb_connection = boto.connect_elb()
    logger.debug('Connected to the Amazon EC2 Load Balancing (Amazon ELB) service.')

    logger.info('Registering (%s) with Load Balancer (%s).' % (', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                                                               else instances[-1].tags['Name'], \
                                                               load_balancer.name))
    elb_connection.register_instances(load_balancer.name, [instance.id for instance in instances])
    logger.info('Registered (%s) with Load Balancer (%s).' % (', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                                                              else instances[-1].tags['Name'], \
                                                              load_balancer.name))


def deregister_instances(load_balancer, instances):
    '''
    Deregister EC2 Instances from an Elastic Load Balancer (ELB).

    * See also: :func:`sky.compute.register_instances` and :func:`sky.compute.rotate_instances`.

    :type load_balancer: :class:`boto.ec2.elb.loadbalancer.LoadBalancer`
    :param load_balancer: The :class:`~boto.ec2.elb.loadbalancer.LoadBalancer`
        that the EC2 Instances will be removed from.

        * See also: :func:`sky.compute.create_load_balancer`.

    :type instances: list
    :param instances: A list of EC2 :class:`~boto.ec2.instance.Instance` objects
        that will be deregistered from the Elastic Load Balancer (ELB).

        * See also: :func:`sky.compute.create_instances`.
    '''

    # Connect to the Amazon EC2 Load Balancing (Amazon ELB) service.
    logger.debug('Connecting to the Amazon EC2 Load Balancing (Amazon ELB) service.')
    elb_connection = boto.connect_elb()
    logger.debug('Connected to the Amazon EC2 Load Balancing (Amazon ELB) service.')

    logger.info('Deregistering (%s) from Load Balancer (%s).' % (', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                                                                 else instances[-1].tags['Name'], \
                                                                 load_balancer.name))
    elb_connection.deregister_instances(load_balancer.name, [instance.id for instance in instances])
    logger.info('Deregistered (%s) from Load Balancer (%s).' % (', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                                                                else instances[-1].tags['Name'], \
                                                                load_balancer.name))


def get_instances(name=None, role=None, state='running'):
    '''
    Query EC2 Instances.

    * See also: :func:`sky.compute.create_instances`.

    :type name: str
    :param name: *Optional*. The name of the EC2 Instance that is being queried.
    
    :type role: str
    :param role: *Optional*. The role of the EC2 Instance that is being queried.

    :type state: str
    :param state: An *optional* EC2 Instance state. Valid values are
        ``pending``, ``running``, ``shutting-down``, ``terminated``,
        ``stopping``, and ``stopped``. By default, EC2 Instances in the
        ``running`` state are returned.

    :rtype: list
    :return: A list of EC2 :class:`~boto.ec2.instance.Instance` objects.
   '''

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Set up filters.
    filters = {}
    filters['instance-state-name'] = state
    filters['tag:Project'] = config['PROJECT_NAME']
    filters['tag:Environment'] = config['ENVIRONMENT']

    if name:
        filters['tag:Name'] = name

    if role:
        filters['tag:Role'] = role

    # Get reservations by tag.
    reservations = ec2_connection.get_all_instances(filters=filters)
    
    # Get instances from reservations.
    instances = [instance for reservation in reservations for instance in reservation.instances]
    
    return instances


def terminate_instances(instances):
    '''
    Terminate EC2 Instances.

    **Warning: On an EBS-backed instance, the default action is for the root EBS volume to be deleted when the instance is terminated. Storage on any local drives will be lost.**

    :type instances: list
    :param instances: A list of EC2 :class:`~boto.ec2.instance.Instance` objects
        that will be terminated.

        * See also: :func:`sky.compute.create_instances`.
    '''

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()
    
    # Terminate EC2 instances.
    if instances:
        logger.info('Terminating (%s).' % (', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                                                     else instances[-1].tags['Name']))
        ec2_connection.terminate_instances(instance_ids=[instance.id for instance in instances])
        logger.info('Terminated (%s).' % (', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                                                    else instances[-1].tags['Name']))


def rotate_instances(load_balancer, instances, terminate_outgoing_instances=True):
    '''
    Replace old EC2 Instances with new EC2 Instances from behind an Elastic Load Balancer (ELB).

    This can be used to carry out seamless (blue-green) deployments. If EC2 Instances are currently registered to the ELB, they will be deregistered *and optionally terminated* only after incoming EC2 Instances pass a Health Check.

    :type load_balancer: :class:`boto.ec2.elb.loadbalancer.LoadBalancer`
    :param load_balancer: The :class:`~boto.ec2.elb.loadbalancer.LoadBalancer`
        that the EC2 Instances will be registered to or removed from.

        * See also: :func:`sky.compute.create_load_balancer`.

    :type instances: list
    :param instances: A list of EC2 :class:`~boto.ec2.instance.Instance` objects
        that will be registered to the Elastic Load Balancer (ELB).

        * See also: :func:`sky.compute.create_instances`.

    :type terminate_outgoing_instances: bool
    :param terminate_outgoing_instances: Specifies whether outgoing EC2
        Instances will be terminated. By default, EC2 Instances will be
        terminated after they have been deregistered from the Elastic Load
        Balancer (ELB).

        * See also: :func:`sky.compute.terminate_instances`.
    '''

    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = connect_ec2()

    # Retrieve outgoing EC2 instances.
    old_reservations = ec2_connection.get_all_instances(instance_ids=[old_instance.id for old_instance in load_balancer.instances]) if load_balancer.instances else None
    old_instances = [instance for reservation in old_reservations for instance in reservation.instances] if load_balancer.instances else None

    # Register incoming EC2 instances with the Load Balancer.
    register_instances(load_balancer, instances)

    # Rotate EC2 instances.
    if old_instances:
        new_instance_names = ', '.join([instance.tags['Name'] for instance in instances]) if len(instances) > 1 \
                             else instances[-1].tags['Name']
        old_instance_names = ', '.join([instance.tags['Name'] for instance in old_instances]) if len(old_instances) > 1 \
                             else old_instances[-1].tags['Name']
        logger.info('Rotating incoming EC2 Instances (%s) and outgoing EC2 instances (%s) under Load Balancer (%s).' % (new_instance_names,
                                                                                                                        old_instance_names,
                                                                                                                        load_balancer.name))
        # Determine incoming EC2 instance states with respect to the Load Balancer.
        instance_states = load_balancer.get_instance_health(instances=[instance.id for instance in instances])

        # Rotate EC2 instances with a new EC2. instance has come into service.
        while 'OutOfService' in [instance_state.state for instance_state in instance_states]:
            # Refresh incoming EC2 instance states with respect to the Load Balancer.
            instance_states = load_balancer.get_instance_health(instances=[instance.id for instance in instances])

            # Terminate outgoing EC2 instance when an incoming EC2 instance has come into service.
            for instance_id in [instance_state.instance_id for instance_state in instance_states if instance_state.state == 'InService']:
                # Get incoming instance.
                instance = next(instance for instance in instances if instance.id == instance_id)
                logger.info('EC2 Instance (%s) has come into service.' % instance.tags['Name'])

                # Get outgoing EC2 instance.
                old_instance = next(old_instance for old_instance in old_instances if old_instance.subnet_id == instance.subnet_id)

                # Deregister outgoing EC2 instance from Load Balancer.
                deregister_instances(load_balancer, [old_instance])

                if terminate_outgoing_instances:
                    # Terminate outgoing EC2 instance.
                    terminate_instances([old_instance])

                # Remove incoming EC2 instance from list.
                instances.remove(instance)

            # Throttle EC2 instance rotation.
            time.sleep(5)

        logger.info('Rotated incoming EC2 Instances (%s) and outgoing EC2 instances (%s) under Load Balancer (%s).' % (new_instance_names,
                                                                                                                       old_instance_names,
                                                                                                                       load_balancer.name))
