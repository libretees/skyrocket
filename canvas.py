#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import random
import logging
import core
import vpc
import ec2
import rds
import s3
from boto.s3.connection import Location
from boto.s3.key import Key

__author__ = 'Jared Contrascere'
__copyright__ = 'Copyright 2015, LibreTees, LLC'
__license__ = 'GPLv3'

logger = logging.getLogger(__name__)

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

    # ec2_instance_name = '-'.join(['ec2', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
    # reservation = ec2_connection.run_instances('ami-9a562df2',
    #                                           instance_type='t2.micro',
    #                                           subnet_id=default_subnets[0].id)

    # instance = reservation.instances[-1]
    # ec2_connection.create_tags([instance.id], {"Name": ec2_instance_name})

    archive_name = '.'.join([s3.PROJECT_NAME, 'tar', 'gz'])
    s3.make_tarfile(archive_name, s3.PROJECT_DIRECTORY)

    s3_bucket_name = '-'.join(['s3', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
    bucket = s3_connection.lookup(s3_bucket_name)
    if not bucket:
        try:
            logger.info('Creating bucket (%s).' % s3_bucket_name)
            bucket = s3_connection.create_bucket(s3_bucket_name, location=Location.DEFAULT)
        except:
            pass

    k = Key(bucket)
    k.key = 'archive'
    k.set_contents_from_filename(archive_name)
    print(bucket)

    # pg = rds.create_db_parameter_group(rds_connection)
    # subnet = rds.create_db_subnet_group(rds_connection, default_subnets)

    # db = rds.create_db_instance(rds_connection,
    #                             pg,
    #                             subnet)

    # rs = rds_connection.describe_db_instances()
    # print(type(rs), rs)

if __name__ == '__main__':
    main()
