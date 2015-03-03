#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import logging
import vpc
import ec2
import rds

__author__ = 'Jared Contrascere'
__copyright__ = 'Copyright 2015, LibreTees, LLC'
__license__ = 'GPLv3'

logger = logging.getLogger(__name__)

def main():

    vpc_connection = vpc.connect_vpc()
    ec2_connection = ec2.connect_ec2()
    rds_connection = rds.connect_rds()

    vpcs = vpc_connection.get_all_vpcs()
    default_vpc = vpcs[0]
    default_subnets = vpc_connection.get_all_subnets(filters={
                                                         'vpcId': default_vpc.id
                                                     })

    pg = rds.create_db_parameter_group(rds_connection)
    subnet = rds.create_db_subnet_group(rds_connection, default_subnets)

    db = rds.create_db_instance(rds_connection,
                                pg,
                                subnet)

    rs = rds_connection.describe_db_instances()
    print(type(rs), rs)

if __name__ == '__main__':
    main()
