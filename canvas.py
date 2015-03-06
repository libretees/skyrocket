#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import time
import random
from string import Template
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

def main():

    vpc_connection = vpc.connect_vpc()
    ec2_connection = ec2.connect_ec2()
    rds_connection = rds.connect_rds()
    s3_connection = s3.connect_s3()

    vpcs = vpc_connection.get_all_vpcs()
    default_vpc = vpcs[0]
    default_subnets = vpc_connection.get_all_subnets(filters={
                                                         'vpcId': default_vpc.id
                                                     })

    archive_name = '.'.join([s3.PROJECT_NAME, 'tar', 'gz'])
    s3.make_tarfile(archive_name, s3.PROJECT_DIRECTORY)

    bootstrap_archive_name = '.'.join(['configure', s3.PROJECT_NAME, 'tar', 'gz'])
    s3.make_tarfile(bootstrap_archive_name, 'deploy')

    s3_bucket_name = '-'.join(['s3', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
    lifecycle_config = boto.s3.lifecycle.Lifecycle()
    lifecycle_config.add_rule(status='Enabled', expiration=1)
    bucket = s3_connection.lookup(s3_bucket_name)
    if not bucket:
        try:
            logger.info('Creating bucket (%s).' % s3_bucket_name)
            bucket = s3_connection.create_bucket(s3_bucket_name, location=boto.s3.connection.Location.DEFAULT, policy='private')
            bucket.configure_lifecycle(lifecycle_config)
            logger.info('Created bucket (%s).' % s3_bucket_name)
            key = bucket.new_key(archive_name)
            key.set_contents_from_filename(archive_name, policy='private')
            key = bucket.new_key(bootstrap_archive_name)
            key.set_contents_from_filename(bootstrap_archive_name, policy='private')
        except:
            print(e)

    iam_connection = iam.connect_iam()
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

    logger.info('Creating instance profile (%s).' % 'myinstanceprofile')

    iam_connection.remove_role_from_instance_profile('myinstanceprofile', 'myrole')
    iam_connection.delete_instance_profile('myinstanceprofile')
    iam_connection.delete_role_policy('myrole', 'mypolicy')
    iam_connection.delete_role('myrole')
    instance_profile = iam_connection.create_instance_profile('myinstanceprofile')
    role = iam_connection.create_role('myrole')
    iam_connection.add_role_to_instance_profile('myinstanceprofile', 'myrole')
    iam_connection.put_role_policy('myrole', 'mypolicy', policy)

    logger.info('Created instance profile (%s).' % 'myinstanceprofile')
    time.sleep(5) # required 5 second sleep

    sg_name = '-'.join(['gp', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    logger.info('Creating security group (%s).' % sg_name)
    sg = ec2_connection.create_security_group(sg_name, 'Security Group Description', vpc_id=default_vpc.id)
    logger.info('Created security group (%s).' % sg_name)

    sg.authorize('tcp', from_port=80, to_port=80, cidr_ip='0.0.0.0/0')
    sg.authorize('tcp', from_port=443, to_port=443, cidr_ip='0.0.0.0/0')
    ec2_connection.revoke_security_group_egress(sg.id, -1, from_port=0, to_port=65535, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'tcp', from_port=53, to_port=53, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'udp', from_port=53, to_port=53, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'tcp', from_port=80, to_port=80, cidr_ip='0.0.0.0/0')
    ec2_connection.authorize_security_group_egress(sg.id, 'tcp', from_port=443, to_port=443, cidr_ip='0.0.0.0/0')

    ec2_instance_name = '-'.join(['ec2', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
    logger.info('Creating EC2 Instance (%s).' % ec2_instance_name)
    reservation = ec2_connection.run_instances('ami-9a562df2',
                                               instance_type='t2.micro',
                                               security_group_ids = [sg.id],
                                               subnet_id=default_subnets[0].id,
                                               instance_profile_name='myinstanceprofile',
                                               #key_name='kp-com-libretees-dev',
                                               user_data=get_script('us-east-1', s3_bucket_name, archive_name, bootstrap_archive_name))

    instance = reservation.instances[-1]
    ec2_connection.create_tags([instance.id], {"Name": ec2_instance_name})
    logger.info('Created EC2 Instance (%s).' % ec2_instance_name)

    #curl http://169.254.169.254/latest/meta-data/iam/security-credentials/myrole
    #aws s3 cp --region us-east-1 s3://s3-gossamer-staging-faddde2b/gossamer.tar.gz gossamer.tar.gz

    # pg = rds.create_db_parameter_group(rds_connection)
    # subnet = rds.create_db_subnet_group(rds_connection, default_subnets)

    # db = rds.create_db_instance(rds_connection,
    #                             pg,
    #                             subnet)

    # rs = rds_connection.describe_db_instances()
    # print(type(rs), rs)

if __name__ == '__main__':
    main()
