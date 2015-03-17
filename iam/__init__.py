import time
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
