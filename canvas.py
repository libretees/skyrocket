#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import time
import re
import sys
import ipaddress
import random
from string import Template
from operator import itemgetter
import logging
import core
import vpc
import ec2
import rds
import s3
import iam
import boto

__author__ = 'Jared Contrascere'
__copyright__ = 'Copyright 2015, LibreTees, LLC'
__license__ = 'GPLv3'

logger = logging.getLogger(__name__)

def get_script(region, s3bucket, s3object, s3object2, filename='user-data.sh'):
    template = open(filename).read()
    return Template(template).substitute(
        region=region,
        s3bucket=s3bucket,
        s3object=s3object,
        s3object2=s3object2
    )

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
    vpc_name = '-'.join(['vpc', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    new_vpc = None
    try:
        logger.info('Creating Virtual Private Cloud (VPC) (%s) with CIDR block (%s).' % (vpc_name, cidr_block))
        new_vpc = vpc_connection.create_vpc(cidr_block,                 # cidr_block
                                            instance_tenancy='default',
                                            dry_run=False)
        logger.info('Created Virtual Private Cloud (VPC) (%s).' % vpc_name)
        new_vpc.add_tag('Name', vpc_name)
    except boto.exception.EC2ResponseError as error:
        if error.status == 400: # Bad Request
            logger.error('Could not create VPC (%s). Error %s: %s.' % (vpc_name, error.status, error.reason))

    if new_vpc:
        igw_name = '-'.join(['igw', core.PROJECT_NAME.lower(), core.args.environment.lower()])
        logger.info('Creating Internet Gateway (%s).' % igw_name)
        igw = vpc_connection.create_internet_gateway(dry_run=False)
        logger.info('Created Internet Gateway (%s).' % igw_name)
        igw.add_tag('Name', igw_name)

        logger.info('Attaching Internet Gateway (%s) to VPC (%s).' % (igw_name, vpc_name))
        vpc_connection.attach_internet_gateway(igw.id,     # internet_gateway_id
                                               new_vpc.id, # vpc_id
                                               dry_run=False)
        logger.info('Attached Internet Gateway (%s).' % igw_name)

        acl_name = '-'.join(['acl', core.PROJECT_NAME.lower(), core.args.environment.lower()])
        acl = vpc_connection.get_all_network_acls(filters={'vpc_id': new_vpc.id})[0]
        acl.add_tag('Name', acl_name)

        rtb_name = '-'.join(['rtb', core.PROJECT_NAME.lower(), core.args.environment.lower()])
        rtb = vpc_connection.get_all_route_tables(filters={'vpc_id': new_vpc.id})[0]
        rtb.add_tag('Name', rtb_name)
        vpc_connection.create_route(rtb.id,         # route_table_id
                                    '0.0.0.0/0',    # destination_cidr_block
                                    gateway_id=igw.id,
                                    instance_id=None,
                                    interface_id=None,
                                    vpc_peering_connection_id=None,
                                    dry_run=False)
    return new_vpc

def create_subnets(ec2_connection, vpc_connection, vpc, cidr_block):
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
        try:
            logger.info('Creating subnet (%s) with %d available IP addresses.' % (subnet_name, available_ips))
            subnet = vpc_connection.create_subnet(vpc.id,                      # vpc_id
                                                  subnet_cidr_block,           # cidr_block
                                                  availability_zone=zone.name,
                                                  dry_run=False)
        except boto.exception.BotoServerError as error:
            if error.status == 400: # Bad Request
                logger.error('Error %s: %s. Couldn\'t create subnet (%s).' % (error.status, error.reason, subnet_name))

        time.sleep(1) # required 1 second sleep
        subnet.add_tag('Name', subnet_name)
        subnets.append(subnet)
        logger.info('Created subnet (%s).' % subnet_name)

    return subnets

def main():

    vpc_connection = vpc.connect_vpc()
    ec2_connection = ec2.connect_ec2()
    rds_connection = rds.connect_rds()
    s3_connection = s3.connect_s3()

    cidr_block = '10.0.0.0/16'

    if not validate_cidr_block(cidr_block):
        sys.exit(1)

    public_vpc = create_public_vpc(vpc_connection, cidr_block)
    subnets = create_subnets(ec2_connection, vpc_connection, public_vpc, cidr_block)

    archive_name = '.'.join([s3.PROJECT_NAME, 'tar', 'gz'])
    logger.info('Creating deployment archive (%s).' % archive_name)
    s3.make_tarfile(archive_name, s3.PROJECT_DIRECTORY)
    logger.info('Created deployment archive (%s).' % archive_name)

    bootstrap_archive_name = '.'.join(['configure', s3.PROJECT_NAME, 'tar', 'gz'])
    s3.make_tarfile(bootstrap_archive_name, 'deploy')

    s3_bucket_name = '-'.join(['s3', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
    lifecycle_config = boto.s3.lifecycle.Lifecycle()
    lifecycle_config.add_rule(status='Enabled', expiration=1)
    bucket = s3_connection.lookup(s3_bucket_name)
    if not bucket:
        try:
            logger.info('Creating S3 bucket (%s).' % s3_bucket_name)
            bucket = s3_connection.create_bucket(s3_bucket_name, location=boto.s3.connection.Location.DEFAULT, policy='private')
            bucket = s3_connection.create_bucket(s3_bucket_name, location=boto.s3.connection.Location.DEFAULT, policy='private')
            bucket.configure_lifecycle(lifecycle_config)
            logger.info('Created S3 bucket (%s).' % s3_bucket_name)
            key = bucket.new_key(archive_name)
            key.set_contents_from_filename(archive_name, policy='private')
            key = bucket.new_key(bootstrap_archive_name)
            key.set_contents_from_filename(bootstrap_archive_name, policy='private')
        except boto.exception.S3CreateError as error:
            logger.error('Could not create S3 bucket (%s) due to Error %s: %s.' % (s3_bucket_name, error.status, error.reason))

    iam_connection = iam.connect_iam()

    cert_name = '-'.join(['crt', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    with open('public-key.crt', 'r') as cert_file:
        cert_body=cert_file.read()
    with open('private-key.pem', 'r') as private_key_file:
        private_key=private_key_file.read()
    with open('certificate-chain.pem', 'r') as cert_chain_file:
        cert_chain=cert_chain_file.read()

    try:
        logger.info('Deleting server certificate (%s).' % cert_name)
        iam_connection.delete_server_cert(cert_name)
        logger.info('Deleted server certificate (%s).' % cert_name)
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t delete server certificate (%s) due to an incompatible filename Error %s: %s.' % (cert_name, error.status, error.reason))
        if error.status == 404: # Not Found
            logger.error('Couldn\'t delete server certificate (%s) due to Error %s: %s.' % (cert_name, error.status, error.reason))

    try:
        logger.info('Uploading server certificate (%s).' % cert_name)
        response = iam_connection.upload_server_cert(cert_name, cert_body, private_key, cert_chain)
        logger.info('Uploaded server certificate (%s).' % cert_name)
        server_certificate_id = response['upload_server_certificate_response']\
                                        ['upload_server_certificate_result']\
                                        ['server_certificate_metadata']\
                                        ['server_certificate_id']
        cert_arn = response['upload_server_certificate_response']\
                           ['upload_server_certificate_result']\
                           ['server_certificate_metadata']\
                           ['arn']
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t upload server certificate (%s) due to an issue with its contents and/or formatting Error %s: %s.' % (cert_name, error.status, error.reason))
        if error.status == 409: # Conflict
            logger.error('Couldn\'t upload server certificate (%s) due to Error %s: %s.' % (cert_name, error.status, error.reason))

    time.sleep(5) # required 5 second sleep

    logger.info('Connecting to the Amazon EC2 Load Balancing (Amazon ELB) service.')
    elb_connection = boto.connect_elb()
    logger.info('Connected to the Amazon EC2 Load Balancing (Amazon ELB) service.')

    sg_name = '-'.join(['gp', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    logger.info('Creating security group (%s).' % sg_name)
    sg = ec2_connection.create_security_group(sg_name, 'Security Group Description', vpc_id=public_vpc.id)
    logger.info('Created security group (%s).' % sg_name)

    sg.authorize('tcp', from_port=80, to_port=80, cidr_ip='0.0.0.0/0')
    sg.authorize('tcp', from_port=443, to_port=443, cidr_ip='0.0.0.0/0')
    ec2_connection.revoke_security_group_egress(sg.id, -1, from_port=0, to_port=65535, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'tcp', from_port=53, to_port=53, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'udp', from_port=53, to_port=53, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'tcp', from_port=80, to_port=80, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'tcp', from_port=443, to_port=443, cidr_ip='0.0.0.0/0')

    elb_name = '-'.join(['elb', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    logger.info('Deleting Elastic Load Balancer (%s).' % elb_name)
    try:
        elb_connection.delete_load_balancer(elb_name)
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t delete Elastic Load Balancer (%s) due to a malformed request %s: %s.' % (elb_name, error.status, error.reason))
        if error.status == 404: # Not Found
            logger.error('Elastic Load Balancer (%s) was not found. Error %s: %s.' % (elb_name, error.status, error.reason))
    logger.info('Deleted Elastic Load Balancer (%s).' % elb_name)

    logger.info('Creating Elastic Load Balancer (%s).' % elb_name)
    elb_connection.create_load_balancer(elb_name, # name
                                        None,     # zones         - Valid only for load balancers in EC2-Classic.
                                        listeners=[(80,80,'HTTP'),
                                                   (443,443,'HTTPS',cert_arn)],
                                        subnets=[subnet.id for subnet in subnets],
                                        security_groups=[sg.id],
                                        scheme='internet-facing', # Valid only for load balancers in EC2-VPC.
                                        complex_listeners=None)
    logger.info('Created Elastic Load Balancer (%s).' % elb_name)

    policy = """{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": ["arn:aws:s3:::%s/%s",
                         "arn:aws:s3:::%s/%s"]
        }]
    }""" % (s3_bucket_name, archive_name, s3_bucket_name, bootstrap_archive_name)


    instance_profile_name = '-'.join(['profile', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    policy_name = '-'.join(['policy', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    role_name = '-'.join(['role', core.PROJECT_NAME.lower(), core.args.environment.lower()])

    logger.info('Deleting instance profile (%s).' % instance_profile_name)
    try:
        iam_connection.remove_role_from_instance_profile(instance_profile_name, role_name)
        iam_connection.delete_instance_profile(instance_profile_name)
        iam_connection.delete_role_policy(role_name, policy_name)
        iam_connection.delete_role(role_name)
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t delete instance profile (%s) due to a malformed request %s: %s.' % (instance_profile_name, error.status, error.reason))
        if error.status == 404: # Not Found
            logger.error('Instance profile (%s) was not found. Error %s: %s.' % (instance_profile_name, error.status, error.reason))
    logger.info('Deleted instance profile (%s).' % instance_profile_name)

    logger.info('Creating instance profile (%s).' % instance_profile_name)
    instance_profile = iam_connection.create_instance_profile(instance_profile_name)
    role = iam_connection.create_role(role_name)
    iam_connection.add_role_to_instance_profile(instance_profile_name, role_name)
    iam_connection.put_role_policy(role_name, policy_name, policy)
    logger.info('Created instance profile (%s).' % instance_profile_name)

    time.sleep(5) # required 5 second sleep

    instances = list()
    for subnet in subnets:
        logger.info('Creating Elastic Network Interface (ENI).')
        interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet.id,
                                                                            groups=[sg.id],
                                                                            associate_public_ip_address=True)
        logger.info('Created Elastic Network Interface (ENI).')
        interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)

        ec2_instance_name = '-'.join(['ec2', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
        logger.info('Creating EC2 Instance (%s) in %s.' % (ec2_instance_name, subnet.availability_zone))
        reservation = ec2_connection.run_instances('ami-9a562df2',
                                                   instance_type='t2.micro',
                                                   #security_group_ids=[sg.id], - Not required when an ENI is specified.
                                                   #subnet_id=subnet.id,        - Not required when an ENI is specified.
                                                   instance_profile_name=instance_profile_name,
                                                   network_interfaces=interfaces,
                                                   user_data=get_script('us-east-1', s3_bucket_name, archive_name, bootstrap_archive_name))
        instance = reservation.instances[-1]
        instances.append(instance)
        time.sleep(1) # required 1 second sleep
        ec2_connection.create_tags([instance.id], {"Name": ec2_instance_name})
        logger.info('Created EC2 Instance (%s).' % ec2_instance_name)

    logger.info('Registering EC2 Instances with Elastic Load Balancer (%s).' % elb_name)
    elb_connection.register_instances(elb_name, [instance.id for instance in instances])
    logger.info('Registered EC2 Instances with Elastic Load Balancer (%s).' % elb_name)

    # curl http://169.254.169.254/latest/meta-data/iam/security-credentials/myrole
    # aws s3 cp --region us-east-1 s3://s3-gossamer-staging-faddde2b/gossamer.tar.gz gossamer.tar.gz

    # pg = rds.create_db_parameter_group(rds_connection)
    # subnet = rds.create_db_subnet_group(rds_connection, default_subnets)

    # db = rds.create_db_instance(rds_connection,
    #                             pg,
    #                             subnet)

    # rs = rds_connection.describe_db_instances()
    # print(type(rs), rs)

if __name__ == '__main__':
    main()
