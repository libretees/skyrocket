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

    ec2_instance_name = '-'.join(['ec2', core.PROJECT_NAME.lower(), core.args.environment.lower(), '%x' % random.randrange(2**32)])
    reservation = ec2_connection.run_instances('ami-9a562df2',
                                               instance_type='t2.micro',
                                               subnet_id=default_subnets[0].id)

    instance = reservation.instances[-1]
    ec2_connection.create_tags([instance.id], {"Name": ec2_instance_name})

    # s3.make_tarfile('.'.join([s3.PROJECT_NAME, 'tar', 'gz']), s3.PROJECT_DIRECTORY)

    # pg = rds.create_db_parameter_group(rds_connection)
    # subnet = rds.create_db_subnet_group(rds_connection, default_subnets)

    # db = rds.create_db_instance(rds_connection,
    #                             pg,
    #                             subnet)

    # rs = rds_connection.describe_db_instances()
    # print(type(rs), rs)

if __name__ == '__main__':
    main()
