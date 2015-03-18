import time
import random
import logging
import boto
import core

logger = logging.getLogger(__name__)

def connect_iam():
    logger.info('Connecting to the Amazon Identity and Access Management (Amazon IAM) service.')
    iam = boto.connect_iam(aws_access_key_id=core.args.key_id,
                           aws_secret_access_key=core.args.key)
    logger.info('Connected to Amazon IAM.')

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

    # Create Role.
    role_name = '-'.join(['role', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    delete_role(role_name)
    logger.info('Creating Role (%s).' % role_name)
    role = iam_connection.create_role(role_name)
    logger.info('Created Role (%s).' % role_name)

    # Set up Instance Profile.
    instance_profile_name = '-'.join(['role', core.PROJECT_NAME.lower(), core.args.environment.lower()])
    instance_profile = iam_connection.create_instance_profile(instance_profile_name)
    iam_connection.add_role_to_instance_profile(instance_profile_name, role_name)

    # Attach Inline Policies to Role.
    for inline_policy in inline_policies:
        role_policy_name = '-'.join(['policy', core.PROJECT_NAME.lower(), core.args.environment.lower(), '{:08x}'.format(random.randrange(2**32))])
        iam_connection.put_role_policy(role_name, role_policy_name, inline_policy)

    # Allow time for Role to register with Amazon IAM service.
    time.sleep(5) # Required 5-second sleep.
    return role_name

def upload_ssl_certificate():
    cert_arn = None
    iam_connection = connect_iam()

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
        time.sleep(5) # required 5-second sleep
    except boto.exception.BotoServerError as error:
        if error.status == 400: # Bad Request
            logger.error('Couldn\'t upload server certificate (%s) due to an issue with its contents and/or formatting Error %s: %s.' % (cert_name, error.status, error.reason))
        if error.status == 409: # Conflict
            logger.error('Couldn\'t upload server certificate (%s) due to Error %s: %s.' % (cert_name, error.status, error.reason))

    return cert_arn
