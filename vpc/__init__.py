import time
import re
import ipaddress
import logging
from operator import itemgetter
import boto
import ec2
import core

logger = logging.getLogger(__name__)

def connect_vpc():
    logger.info('Connecting to the Amazon Virtual Private Cloud (Amazon VPC) service.')
    vpc = boto.connect_vpc(aws_access_key_id=core.args.key_id,
                           aws_secret_access_key=core.args.key)
    logger.info('Connected to Amazon VPC.')
    
    return vpc

def validate_cidr_block(cidr_block):
    try:
        logger.debug('Validating CIDR block (%s).' % cidr_block)

        # Split CIDR block into Network IP and Netmask components.
        network_ip, netmask = itemgetter(0, 1)(cidr_block.split('/'))
        netmask = int(netmask)

        # Ensure that CIDR block conforms to RFC 1918.
        assert (re.search(r'^10\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])$', network_ip) or \
                re.search(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])$', network_ip) or \
                re.search(r'^192\.168\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])$', network_ip)) and \
               (re.search(r'(^[1-2]?[0-9]$)|(^3[0-2]$)', str(netmask)))

        # Validate netmask.
        if re.search(r'^10\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])$', network_ip):
            assert netmask >= 8
            logger.debug('Valid Class A Private Network CIDR block given (%s).' % cidr_block)
        elif re.search(r'^172\.(1[6-9]|2[0-9]|3[0-1|)\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])$', network_ip):
            assert netmask >= 12
            logger.debug('Valid Class B Private Network CIDR block given (%s).' % cidr_block)
        elif re.search(r'^192\.168\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])\.([0-9]|[1-9][0-9]|[1-2][0-5][0-5])$', network_ip):
            assert netmask >= 16
            logger.debug('Valid Class C Private Network CIDR block given (%s).' % cidr_block)

        # Ensure that netmask is compatible with Amazon VPC.
        if not (netmask >= 16 and netmask <= 28):
            logger.error('Amazon VPC service requires CIDR block sizes between a /16 netmask and /28 netmask.')
            assert False

        logger.debug('CIDR block validated (%s).' % cidr_block)
        return True
    except AssertionError as error:
        logger.error('Invalid CIDR block given (%s).' % cidr_block)
        return False

def create_public_vpc(vpc_connection, cidr_block):
    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = ec2.connect_ec2()

    # Generate Virtual Private Cloud (VPC) name.
    vpc_name = '-'.join(['vpc', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    new_vpc = None
    try:
        logger.info('Creating Virtual Private Cloud (VPC) (%s) with CIDR block (%s).' % (vpc_name, cidr_block))
        new_vpc = vpc_connection.create_vpc(cidr_block,                 # cidr_block
                                            instance_tenancy='default',
                                            dry_run=False)
        logger.info('Created Virtual Private Cloud (VPC) (%s).' % vpc_name)

        # Tag Virtual Private Cloud (VPC).
        tagged = False
        while not tagged:
            try:
                tagged = ec2_connection.create_tags([new_vpc.id], {'Name': vpc_name,
                                                                   'Project': core.PROJECT_NAME.lower(),
                                                                   'Environment': core.args.environment.lower()})
            except boto.exception.EC2ResponseError as error:
                if error.code == 'InvalidVpcID.NotFound': # VPC hasn't registered with Virtual Private Cloud (VPC) service yet.
                    pass
                else:
                    raise boto.exception.EC2ResponseError

    except boto.exception.EC2ResponseError as error:
        if error.status == 400: # Bad Request
            logger.error('Error %s: %s. Could not create VPC (%s). %s' % (error.status, error.reason, vpc_name, error.message))

    if new_vpc:
        igw_name = '-'.join(['igw', core.PROJECT_NAME.lower(), core.args.environment.lower()])
        logger.info('Creating Internet Gateway (%s).' % igw_name)
        igw = vpc_connection.create_internet_gateway(dry_run=False)
        logger.info('Created Internet Gateway (%s).' % igw_name)

        # Tag Internet Gateway.
        tagged = False
        while not tagged:
            try:
                tagged = ec2_connection.create_tags([igw.id], {'Name': vpc_name,
                                                               'Project': core.PROJECT_NAME.lower(),
                                                               'Environment': core.args.environment.lower()})
            except boto.exception.EC2ResponseError as error:
                if error.code == 'InvalidID': # IGW hasn't registered with Virtual Private Cloud (VPC) service yet.
                    pass
                else:
                    raise boto.exception.EC2ResponseError

        logger.info('Attaching Internet Gateway (%s) to VPC (%s).' % (igw_name, vpc_name))
        vpc_connection.attach_internet_gateway(igw.id,     # internet_gateway_id
                                               new_vpc.id, # vpc_id
                                               dry_run=False)
        logger.info('Attached Internet Gateway (%s).' % igw_name)

        # Get Access Control Lists (ACLs) associated to VPC.
        acls = vpc_connection.get_all_network_acls(filters={'vpc_id': new_vpc.id})

        # Generate Access Control List (ACL) name.
        acl_name = '-'.join(['acl', core.PROJECT_NAME.lower(), core.args.environment.lower()])

        # Tag Access Control Lists (ACLs).
        for acl in acls:
            tagged = False
            while not tagged:
                try:
                    tagged = ec2_connection.create_tags([acl.id], {'Name': acl_name,
                                                                   'Project': core.PROJECT_NAME.lower(),
                                                                   'Environment': core.args.environment.lower()})
                except boto.exception.EC2ResponseError as error:
                    if error.code == 'InvalidNetworkAclID.NotFound': # ACL hasn't registered with Virtual Private Cloud (VPC) service yet.
                        pass
                    else:
                        raise boto.exception.EC2ResponseError

        # Get Route Tables associated to VPC.
        route_tables = vpc_connection.get_all_route_tables(filters={'vpc_id': new_vpc.id})

        # Generate Route Table name.
        rtb_name = '-'.join(['rtb', core.PROJECT_NAME.lower(), core.args.environment.lower()])

        # Tag Route Tables.
        for route_table in route_tables:
            tagged = False
            while not tagged:
                try:
                    tagged = ec2_connection.create_tags([route_table.id], {'Name': rtb_name,
                                                                           'Project': core.PROJECT_NAME.lower(),
                                                                           'Environment': core.args.environment.lower()})
                except boto.exception.EC2ResponseError as error:
                    if error.code == 'InvalidID': # Route Table hasn't registered with Virtual Private Cloud (VPC) service yet.
                        pass
                    else:
                        raise boto.exception.EC2ResponseError

        vpc_connection.create_route(route_table.id,    # route_table_id
                                    '0.0.0.0/0',       # destination_cidr_block
                                    gateway_id=igw.id,
                                    instance_id=None,
                                    interface_id=None,
                                    vpc_peering_connection_id=None,
                                    dry_run=False)
    return new_vpc

def create_subnets(ec2_connection, vpc_connection, vpc, cidr_block):
    # Connect to the Amazon Elastic Compute Cloud (Amazon EC2) service.
    ec2_connection = ec2.connect_ec2()

    network_ip, netmask = itemgetter(0, 1)(cidr_block.split('/'))
    network_ip = int(ipaddress.IPv4Address(network_ip))
    netmask = int(netmask)

    zones = ec2_connection.get_all_zones()
    subnet_netmask = netmask+len(bin(len(zones)))-2

    if subnet_netmask > 28:
        logger.warning('The CIDR block specified will not support the creation of subnets in all availability zones.' % cidr_block)

    subnets = list()
    for i, zone in enumerate(zones):
        subnet_name = '-'.join(['subnet', core.PROJECT_NAME.lower(), core.args.environment.lower(), zone.name])

        subnet_network_ip = (network_ip | (i << 32-subnet_netmask))
        subnet_cidr_block = str(subnet_network_ip >> 24) + '.' + \
                            str((subnet_network_ip >> 16) & 255) + '.' + \
                            str((subnet_network_ip >> 8) & 255) + '.' + \
                            str(subnet_network_ip & 255) + '/' + \
                            str(subnet_netmask)
        available_ips = (0xffffffff ^ (0xffffffff << 32-subnet_netmask & 0xffffffff))-4 # 4 addresses are reserved by Amazon
                                                                                        # for IP networking purposes.
                                                                                        # .0 for the network, .1 for the gateway,
                                                                                        # .3 for DHCP services, and .255 for broadcast.
        # Create Subnet.
        try:
            logger.info('Creating Subnet (%s) with %s available IP addresses.' % (subnet_name, '{:,}'.format(available_ips)))
            subnet = vpc_connection.create_subnet(vpc.id,                      # vpc_id
                                                  subnet_cidr_block,           # cidr_block
                                                  availability_zone=zone.name,
                                                  dry_run=False)
        except boto.exception.BotoServerError as error:
            if error.status == 400: # Bad Request
                logger.error('Error %s: %s. Couldn\'t create Subnet (%s).' % (error.status, error.reason, subnet_name))

        # Tag Subnet.
        tagged = False
        while not tagged:
            try:
                tagged = ec2_connection.create_tags([subnet.id], {'Name': subnet_name,
                                                                  'Project': core.PROJECT_NAME.lower(),
                                                                  'Environment': core.args.environment.lower()})
            except boto.exception.EC2ResponseError as error:
                if error.code == 'InvalidID': # Subnet hasn't registered with Virtual Private Cloud (VPC) service yet.
                    pass
                else:
                    raise boto.exception.EC2ResponseError

        time.sleep(1) # required 1-second sleep
        subnet.add_tag('Name', subnet_name)
        subnets.append(subnet)
        logger.info('Created subnet (%s).' % subnet_name)

    return subnets
