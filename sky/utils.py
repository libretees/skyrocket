import os
import sys
import tarfile
import logging
from string import Template
from re import search, IGNORECASE
from argparse import ArgumentParser
from configparser import ConfigParser
from timeit import Timer
from boto import regioninfo
from .state import config

logger = logging.getLogger(__name__)

def get_script(region, s3bucket, s3object, filename='user-data.sh'):
    """
    Gets a User-Data script that instructs an EC2 instance to copy an object from an S3 Bucket and run a command afterwards.

    :type region: str
    :param region: The region that the :class:`~boto.s3.bucket.Bucket` is located in.

        * Note: If the S3 Bucket is located in the ``boto.s3.connection.Location.DEFAULT`` (US Standard) S3 region, specify ``us-east-1``.

    :type bucket: :class:`boto.s3.bucket.Bucket`
    :param bucket: The :class:`~boto.s3.bucket.Bucket` to copy the object from.

    :type s3object: str
    :param s3object: The name of the object to download.

    :type filename: str
    :param filename: The path to a template user-data script.
    """

    template = open(filename).read()
    return Template(template).substitute(
        region=region,
        s3bucket=s3bucket,
        s3object=s3object
    )


def get_closest_region(service='ec2', repetitions=1):
    """
    Get the closest region for a particular service based on its average response time.

    :type service: str
    :param service: The service to attempt a connection to. By default, this is ``ec2``.

    :type repetitions: int
    :param repetitions: The number of measurements to take before calculating an average.
    """

    regions = [region.name for region in regioninfo.get_regions(service) if 'gov' not in region.name and 'cn' not in region.name]

    latency = {}
    for region in regions:
        connection = Timer("h.request('GET', '/')",
                           "from http.client import HTTPSConnection; h=HTTPSConnection('%s.%s.amazonaws.com')" % (service, region))
        times = connection.repeat(repetitions, 1)
        avg_latency = sum(times)/float(len(times))
        latency[region] = avg_latency
        logger.info('Average latency to Amazon %s %s is %s' % (service.upper(), region, latency[region]))

    region = min(latency, key=latency.get)

    return region


def make_tarfile(output_filename, source_dir):
    """
    Create a tarfile that extracts cleanly to a specified directory.

    """

    logger.info('Archiving directory (%s).' % source_dir)
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname='.')
    logger.info('Created gzipped tarball (%s).' % output_filename)


def configure_logger(args):
    """
    Configure the application/package logger. (This is used internally.)

    """

    # Restrict the boto logger to the WARNING log level.
    if args.loglevel.upper() in ['DEBUG', 'INFO', 'WARNING']:
        logging.getLogger('boto').setLevel(logging.WARNING)

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.loglevel.upper())
    logging.basicConfig(level=numeric_level)


def parse_arguments():
    """
    Parse command line arguments. (This is used internally.)

    """

    global config
    
    valid_arguments = True
    parser = ArgumentParser(description='Provision Django application environments.')
    parser.add_argument('command', metavar='<command>', action='store', help='Valid commands are [deploy]')
    parser.add_argument('targets', metavar='<targets>', action='store', nargs='*', default=['all'], help='Skyfile Targets')
    parser.add_argument('-p', '--project', dest='directory', action='store', default=os.getcwd(),
                        help='set Django project directory')
    parser.add_argument('-env', '--environment', dest='environment', action='store', default='STAGING',
                        help='set desired deployment environment [STAGING, PRODUCTION]\n(default: staging)')
    parser.add_argument('-aws', '--account-id', dest='account_id', action='store', default=os.environ.get('AWS_ACCOUNT_ID'),
                        help='set AWS Account ID')
    parser.add_argument('-id', '--key-id', dest='key_id', action='store', default=os.environ.get('AWS_ACCESS_KEY_ID'),
                        help='set AWS Access Key ID')
    parser.add_argument('-k', '--secret', dest='key', action='store', default=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                        help='set AWS Account Secret Access Key')
    parser.add_argument('-d', '--log', dest='loglevel', action='store', default='ERROR',
                        help='set log level [DEBUG, INFO, WARNING, ERROR, CRITICAL] (default: ERROR)')
    parser.add_argument('--dry', dest='dry_run', action='store_true', default=False,
                        help='perform a dry run')

    # Display help, if no command was supplied.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    try:
        assert args.loglevel.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if args.loglevel.upper() == 'DEBUG':
            print('DEBUG:', __name__, ':Log argument validated (%s).' % args.loglevel, sep='')
    except AssertionError:
        print('ERROR:', __name__, ':Invalid log option (%s).' % args.loglevel, file=sys.stderr, sep='')
        valid_arguments = False

    configure_logger(args)

    try:
        assert args.command.upper() in ['DEPLOY']
        logger.debug('Command argument validated (%s).' % args.command)
    except AssertionError:
        logger.error('Invalid command (%s).' % args.command)
        valid_arguments = False

    try:
        assert args.environment.upper() in ['STAGING', 'PROD', 'PRODUCTION']
        if args.environment.upper() == 'PRODUCTION': args.environment = 'PROD'
        logger.debug('Deployment environment argument validated (%s).' % args.environment)
    except AssertionError:
        logger.error('Invalid deployment environment (%s).' % args.environment)
        valid_arguments = False

    try:
        assert os.path.isdir(os.path.expanduser(args.directory))
        logger.debug('Django project directory argument validated (%s).' % args.directory)
    except AssertionError:
        logger.error('Invalid Django project directory (%s).' % args.directory)
        valid_arguments = False

    try:
        assert args.account_id and search(r'^\d{12}$', args.account_id)
        logger.debug('AWS Account ID argument validated (%s).' % args.account_id)
    except AssertionError:
        if args.account_id:
            logger.error('AWS Account ID must be exactly 12 digits (%s).' % args.account_id)
        else:
            logger.error('AWS Account ID not specified.')
        valid_arguments = False

    config_path = None
    if os.environ.get('BOTO_CONFIG'):
        config_path = os.path.expanduser(os.environ.get('BOTO_CONFIG'))
    elif os.path.exists(os.path.expanduser('~/.boto')):
        config_path = os.path.expanduser('~/.boto')
    elif os.path.exists(os.path.expanduser('~/.aws/credentials')):
        config_path = os.path.expanduser('~/.aws/credentials')
    elif os.path.exists('/etc/boto.cfg'):
        config_path = '/etc/boto.cfg'

    key_id = None
    key = None
    if config_path:
        config = ConfigParser()
        config.sections()
        try:
            logger.info('Reading configuration file (%s).' % config_path)
            config.read(config_path)
            key_id = config['Credentials']['aws_access_key_id']
            key = config['Credentials']['aws_secret_access_key']
        except:
            logger.error('Could not read configuration file (%s).' % config_path)

    try:
        args.key_id = args.key_id or key_id
        assert args.key_id and search(r'^[A-Z0-9]{20}$', args.key_id, IGNORECASE)
        logger.debug('AWS Access Key ID argument validated (%s).' % args.key_id)
    except AssertionError:
        if args.key_id:
            logger.error('AWS Access Key ID must contain 20 alphanumeric characters (%s).' % args.key_id)
        else:
            logger.error('AWS Access Key ID not specified.')
        valid_arguments = False

    try:
        args.key = args.key or key
        assert args.key and search(r'^[A-Z0-9/\+]{40}$', args.key, IGNORECASE)
        logger.debug('AWS Account Secret Access Key argument validated.')
    except AssertionError:
        if args.key:
            logger.error('AWS Account Secret Access Key must contain 40 alphanumeric characters and/or the following: /+ (%s).' \
                         % args.key)
        else:
            logger.error('AWS Account Secret Access Key not specified.')
        valid_arguments = False

    if not valid_arguments:
        logger.error('Invalid arguments given.')
        logger.error('Exiting...')
        sys.exit(1)

    config['TARGETS'] = args.targets
    config['PROJECT_NAME'] = os.path.abspath(os.path.expanduser(args.directory)).split(os.sep)[-1].lower()
    config['PROJECT_DIRECTORY'] = os.path.abspath(os.path.expanduser(args.directory)).lower()
    config['ENVIRONMENT'] = args.environment.lower()
    config['AWS_ACCOUNT_ID'] = args.account_id
    config['AWS_ACCESS_KEY_ID'] = args.key_id
    config['AWS_SECRET_ACCESS_KEY'] = args.key

    return args
