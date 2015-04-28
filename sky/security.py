import time
import random
import logging
import boto
from .state import config

logger = logging.getLogger(__name__)

def connect_iam():
    logger.debug('Connecting to the Amazon Identity and Access Management (Amazon IAM) service.')
    iam = boto.connect_iam(aws_access_key_id=config['AWS_ACCESS_KEY_ID'],
                           aws_secret_access_key=config['AWS_SECRET_ACCESS_KEY'])
    logger.debug('Connected to Amazon IAM.')

    return iam

def delete_role(role_name):
    # Connect to the Amazon Identity and Access Management (Amazon IAM) service.
    iam_connection = connect_iam()

    # Get a list of all Instance Profiles associated to the Role.
    instance_profiles = None
    try:
        response = iam_connection.list_instance_profiles_for_role(role_name)
        instance_profiles = response['list_instance_profiles_for_role_response']\
                                    ['list_instance_profiles_for_role_result']\
                                    ['instance_profiles']
    except boto.exception.BotoServerError as error:
        if error.status == 404: # Not Found
            logger.error('Error %s: %s. Role (%s) was not found. ' % (error.status, error.reason, role_name))

    # Get a list of all Role Policies associated to the Role.
    role_policies = None
    try:
        response = iam_connection.list_role_policies(role_name)
        role_policies = response['list_role_policies_response']\
                                ['list_role_policies_result']\
                                ['policy_names']
    except boto.exception.BotoServerError as error:
        if error.status == 404: # Not Found
            logger.error('Error %s: %s. Role (%s) was not found. ' % (error.status, error.reason, role_name))

    # Remove Role from Instance Profiles.
    if instance_profiles:
        instance_profile_names = [instance_profile['instance_profile_name'] for instance_profile in instance_profiles]
        for instance_profile_name in instance_profile_names:
            logger.info('Removing Role (%s) from Instance Profile (%s).' % (role_name, instance_profile_name))
            try:
                iam_connection.remove_role_from_instance_profile(instance_profile_name, role_name)
                logger.info('Removed Role (%s) from Instance Profile (%s).' % (role_name, instance_profile_name))
            except boto.exception.BotoServerError as error:
                if error.status == 400: # Bad Request
                    logger.error('Error %s: %s. Couldn\'t remove Role (%s) Instance Profile (%s).' % (error.status, error.reason, role_name, instance_profile_name))
                if error.status == 404: # Not Found
                    logger.error('Error %s: %s. Instance Profile (%s) was not found. ' % (error.status, error.reason, instance_profile_name))

            # Delete Instance Profile.
            logger.info('Deleting Instance Profile (%s).' % instance_profile_name)
            try:
                iam_connection.delete_instance_profile(instance_profile_name)
                logger.info('Deleted Instance Profile (%s).' % instance_profile_name)
            except boto.exception.BotoServerError as error:
                if error.status == 400: # Bad Request
                    logger.error('Error %s: %s. Couldn\'t delete Instance Profile (%s).' % (error.status, error.reason, instance_profile_name))
                if error.status == 404: # Not Found
                    logger.error('Error %s: %s. Instance Profile (%s) was not found. ' % (error.status, error.reason, instance_profile_name))

    # Delete Role Policies from Role.
    if role_policies:
        for role_policy in role_policies:
            logger.info('Deleting Role Policy (%s) from Role (%s).' % (role_policy, role_name))
            try:
                iam_connection.delete_role_policy(role_name, role_policy)
                logger.info('Deleted Role Policy (%s) from Role (%s).' % (role_policy, role_name))
            except boto.exception.BotoServerError as error:
                if error.status == 400: # Bad Request
                    logger.error('Error %s: %s. Couldn\'t delete Policy (%s) Role (%s).' % (error.status, error.reason, role_policy, role_name))
                if error.status == 404: # Not Found
                    logger.error('Error %s: %s. Role (%s) was not found. ' % (error.status, error.reason, role_name))

    # Delete Role.
    logger.info('Deleting Role (%s).' % role_name)
    try:
        iam_connection.delete_role(role_name)
        logger.info('Deleted Role (%s).' % role_name)
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Error %s: %s. Couldn\'t delete Role (%s).' % (error.status, error.reason, role_name))
        if error.status == 404: # Not Found
            logger.error('Error %s: %s. Role (%s) was not found. ' % (error.status, error.reason, role_name))

def create_role(inline_policies):
    # Connect to the Amazon Identity and Access Management (Amazon IAM) service.
    iam_connection = connect_iam()

    # Convert Inline Policies parameter to list, if necessary.
    if isinstance(inline_policies, str):
        inline_policies = [inline_policies]

    # Create Role.
    role_name = '-'.join(['role', config['PROJECT_NAME'], config['ENVIRONMENT']])
    delete_role(role_name)
    logger.info('Creating Role (%s).' % role_name)
    role = iam_connection.create_role(role_name)
    logger.info('Created Role (%s).' % role_name)

    # Set up Instance Profile.
    instance_profile_name = '-'.join(['role', config['PROJECT_NAME'], config['ENVIRONMENT']])
    instance_profile = iam_connection.create_instance_profile(instance_profile_name)
    instance_profile.name = instance_profile_name
    iam_connection.add_role_to_instance_profile(instance_profile_name, role_name)


    # Attach Inline Policies to Role.
    for inline_policy in inline_policies:
        role_policy_name = '-'.join(['policy', config['PROJECT_NAME'], config['ENVIRONMENT'], '{:08x}'.format(random.randrange(2**32))])
        iam_connection.put_role_policy(role_name, role_policy_name, inline_policy)

    # Allow time for Role to register with Amazon IAM service.
    time.sleep(5) # Required 5-second sleep.
    return instance_profile

def upload_ssl_certificate(public_key, private_key, certificate_chain=None, name=None):
    # Connect to the Amazon Identity and Access Management (Amazon IAM) service.
    iam_connection = connect_iam()

    # Generate Certificate name.
    if not name:
        name = '-'.join(['crt', config['PROJECT_NAME'], config['ENVIRONMENT']])

    # Read SSL Public Key.
    with open(public_key, 'r') as public_key_file:
        public_key = public_key_file.read()

    # Read SSL Private Key.
    with open(private_key, 'r') as private_key_file:
        private_key = private_key_file.read()

    # Read SSL Certificate Chain, if it was specified.
    if certificate_chain:
        with open(certificate_chain, 'r') as certificate_chain_file:
            certificate_chain = certificate_chain_file.read()

    # Delete Server Certificate, if one exists.
    try:
        logger.info('Deleting Server Certificate (%s).' % name)
        iam_connection.delete_server_cert(name)
        logger.info('Deleted Server Certificate (%s).' % name)
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t delete Server Certificate (%s) due to an incompatible filename Error %s: %s.' % (name, error.status, error.reason))
        if error.status == 404: # Not Found
            logger.error('Couldn\'t delete Server Certificate (%s) due to Error %s: %s.' % (name, error.status, error.reason))

    # Upload the SSL Certificate to Amazon IAM.
    cert_arn = None
    try:
        logger.info('Uploading server certificate (%s).' % name)
        response = iam_connection.upload_server_cert(name, public_key, private_key, certificate_chain)
        logger.info('Uploaded server certificate (%s).' % name)
        server_certificate_id = response['upload_server_certificate_response']\
                                        ['upload_server_certificate_result']\
                                        ['server_certificate_metadata']\
                                        ['server_certificate_id']
        cert_arn = response['upload_server_certificate_response']\
                           ['upload_server_certificate_result']\
                           ['server_certificate_metadata']\
                           ['arn']
        time.sleep(5) # required 5-second sleep
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t upload server certificate (%s) due to an issue with its contents and/or formatting Error %s: %s.' % (name, error.status, error.reason))
        if error.status == 409: # Conflict
            logger.error('Couldn\'t upload server certificate (%s) due to Error %s: %s.' % (name, error.status, error.reason))

    return cert_arn
