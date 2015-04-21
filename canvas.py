#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""canvas.py: Provision AWS environments for Django projects."""

import os
import sys
import importlib
import types
from string import Template
import logging
from sky.infrastructure import Infrastructure
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

def load_skyfile(path='./skyfile.py', module_name='skyfile'):
    # Import Skyfile (Only works in Python 3.3+).
    loader = importlib.machinery.SourceFileLoader(module_name, path)
    module = loader.load_module()
    logger.info('Loaded (%s) module from (%s).' % (module_name, path))

    return module

def load_infrastructure(module):

    infrastructure_objects = []

    imported_symbols = vars(module)

    if '__all__' in imported_symbols:
        # Obey the use of <module>.__all__, if it is present.
        imported_symbols = [(name, imported_symbols[name]) for name in \
                            imported_symbols if name in imported_symbols['__all__']]
    else:
        imported_symbols = imported_symbols.items()

    for symbol in imported_symbols:
        name, obj = symbol
        if isinstance(obj, Infrastructure):
            logger.info('\'%s\' is a %s object imported from the \'%s\' module.' % (name, type(obj), module.__name__))
            infrastructure_objects.append(obj)
        elif isinstance(obj, types.ModuleType):
            logger.info('\'%s\' module imported from the \'%s\' module.' % (name, module.__name__))
            infrastructure_objects += load_infrastructure(obj)

    return infrastructure_objects

def main():

    module = load_skyfile()
    i = load_infrastructure(module)

    for a in i:
        print(a.depends)
        a()

    # cidr_block = '10.0.0.0/16'

    # if not vpc.validate_cidr_block(cidr_block):
    #     sys.exit(1)

    #public_vpc = vpc.create_network(cidr_block, internet_connected=True, ephemeral=True)

    #http://chimera.labs.oreilly.com/books/1230000000393/ch09.html#_problem_152
    #infrastructure()

    # public_subnets = vpc.create_subnets(public_vpc, zones=['us-east-1b', 'us-east-1c'], byte_aligned=True, public=True)
    # private_subnets = vpc.create_subnets(public_vpc, zones=['us-east-1b', 'us-east-1c'], byte_aligned=True)

    # instances = ec2.create_ec2_instances(public_vpc, public_subnets, role='application', internet_addressable=True)
    # nat_instances = ec2.create_nat_instances(public_vpc, public_subnets, private_subnets)

    # database = rds.create_database(public_vpc, private_subnets, application_instances=instances, publicly_accessible=False, multi_az=True)
    # print('Database Endpoint:', database['Endpoint'])

    # ssl_certificate = iam.upload_ssl_certificate('public-key.crt',
    #                                              'private-key.pem',
    #                                              certificate_chain='certificate-chain.pem')

    # instance_security_groups = [group for instance in instances for group in instance.groups]
    # load_balancer = ec2.create_elb(public_vpc, public_subnets, ssl_certificate=ssl_certificate, security_groups=instance_security_groups)

    # logger.info('Registering EC2 Instances with Elastic Load Balancer (%s).' % load_balancer.name)
    # elb_connection.register_instances(load_balancer.name, [instance.id for instance in instances])
    # logger.info('Registered EC2 Instances with Elastic Load Balancer (%s).' % load_balancer.name)

    # archive_name = '.'.join([s3.PROJECT_NAME, 'tar', 'gz'])
    # logger.info('Creating deployment archive (%s).' % archive_name)
    # s3.make_tarfile(archive_name, s3.PROJECT_DIRECTORY)
    # logger.info('Created deployment archive (%s).' % archive_name)

    # bootstrap_archive_name = '.'.join(['configure', s3.PROJECT_NAME, 'tar', 'gz'])
    # s3.make_tarfile(bootstrap_archive_name, 'deploy')

    # bucket = s3.create_bucket()
    # s3.add_object(bucket, archive_name)
    # s3.add_object(bucket, bootstrap_archive_name)
    # policy = s3.get_bucket_policy(bucket)

    # script = get_script('us-east-1', bucket.name, archive_name, bootstrap_archive_name)
    # script = ec2.install_package(script, 'python3-pip')
    # script = ec2.run(script, 'pip3 install virtualenv')
    # script = ec2.run(script, 'pip3 install virtualenvwrapper')

    # instance_profile_name = iam.create_role(policy)

    # # Get created EC2 instances.
    # reservations = ec2_connection.get_all_instances(filters={'tag:Project': core.PROJECT_NAME.lower(),
    #                                                          'tag:Environment': core.args.environment.lower()})
    # instances = [instances for reservation in reservations for instances in reservation.instances]

    # # Terminate EC2 instances.
    # ec2_connection.terminate_instances(instance_ids=[instance.id for instance in instances])

    # curl http://169.254.169.254/latest/meta-data/iam/security-credentials/myrole
    # aws s3 cp --region us-east-1 s3://s3-gossamer-staging-faddde2b/gossamer.tar.gz gossamer.tar.gz



if __name__ == '__main__':
    main()
