#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import sys
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
    elb_connection = boto.connect_elb()

    cidr_block = '10.0.0.0/16'

    if not vpc.validate_cidr_block(cidr_block):
        sys.exit(1)

    public_vpc = vpc.create_public_vpc(vpc_connection, cidr_block)
    subnets = vpc.create_subnets(ec2_connection, vpc_connection, public_vpc, cidr_block)

    archive_name = '.'.join([s3.PROJECT_NAME, 'tar', 'gz'])
    logger.info('Creating deployment archive (%s).' % archive_name)
    s3.make_tarfile(archive_name, s3.PROJECT_DIRECTORY)
    logger.info('Created deployment archive (%s).' % archive_name)

    bootstrap_archive_name = '.'.join(['configure', s3.PROJECT_NAME, 'tar', 'gz'])
    s3.make_tarfile(bootstrap_archive_name, 'deploy')

    bucket = s3.create_bucket()
    s3.add_object(bucket, archive_name)
    s3.add_object(bucket, bootstrap_archive_name)
    policy = s3.get_bucket_policy(bucket)

    cert_arn = iam.upload_ssl_certificate()

    sg = ec2.create_security_group(public_vpc)

    load_balancer = ec2.create_elb(sg, subnets, cert_arn)

    script = get_script('us-east-1', bucket.name, archive_name, bootstrap_archive_name)
    instance_profile_name = iam.create_role([policy])

    instances = ec2.create_ec2_instances([sg], subnets, script, instance_profile_name)

    logger.info('Registering EC2 Instances with Elastic Load Balancer (%s).' % load_balancer.name)
    elb_connection.register_instances(load_balancer.name, [instance.id for instance in instances])
    logger.info('Registered EC2 Instances with Elastic Load Balancer (%s).' % load_balancer.name)

    # Get created EC2 instances.
    reservations = ec2_connection.get_all_instances(filters={'tag:Project': core.PROJECT_NAME.lower(),
                                                             'tag:Environment': core.args.environment.lower()})
    instances = [i for r in reservations for i in r.instances]
    print(instances)

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
