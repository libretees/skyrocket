import os
import sys
import logging
import argparse
from importlib import import_module

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')

DIRNAME = os.path.dirname(os.path.realpath(__file__)).split(os.sep)[-1]
DJANGO_SETTINGS_MODULE = DIRNAME + '.settings'

logger = logging.getLogger(__name__)

def import_settings():
    if DJANGO_SETTINGS_MODULE:
        try:
            settings = import_module(DJANGO_SETTINGS_MODULE)
            logger.debug('Loaded module (%s).' % DJANGO_SETTINGS_MODULE)
        except ImportError:
            logger.error('Django Settings Module failed to import.', exc_info=True)
    return settings

def parse_arguements():
    parser = argparse.ArgumentParser(description='Provision Django application environments.')
    parser.add_argument('--log', dest='loglevel', action='store', default='ERROR',
                        help='set log level [DEBUG, INFO, WARNING, ERROR, CRITICAL] (default: ERROR)')
    args = parser.parse_args()
    try:
        assert args.loglevel.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    except AssertionError:
        print('Invalid log option (%s).' % args.loglevel, file=sys.stderr)
        sys.exit(1)
    return args

def configure_logger(args):
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)

def main():
    args = parse_arguements()
    configure_logger(args)
    settings = import_settings()
    
    engine = settings.DATABASES['default']['ENGINE']
    
    if engine not in ['django.db.backends.postgresql_psycopg2' \
                     ,'django.db.backends.mysql' \
                     ,'django.db.backends.sqlite3' \
                     ,'django.db.backends.oracle']:
        logger.error('Unknown database engine (%s)' % engine, exc_info=True)
        sys.exit(1)
    else:
        logger.info('Provisioning database for engine (%s)' % engine)



if __name__ == "__main__":
    main()