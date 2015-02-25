import os
import sys
import imp
import logging
import argparse
#from importlib import import_module

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID')
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')

logger = logging.getLogger(__name__)

def import_settings(args):
    settings = None
    try:
        import_module('settings', os.environ['DJANGO_SETTINGS_MODULE'])
        logger.debug('Django Settings Module loaded (%s)' % os.environ['DJANGO_SETTINGS_MODULE'])
    except:
        logger.debug('Django Settings Module could not be loaded from environment variable.')

    project_directory = os.path.abspath(args.directory)
    project_name = project_directory.split(os.sep)[-1]
    relative_path = os.path.join(os.path.relpath(project_directory, os.getcwd()), project_name, 'settings.py')
    logger.info('Loading (%s)' % relative_path)
    try:
        imp.load_source('settings', relative_path)
        import settings
        logger.debug('Django Settings Module loaded from file (%s)' % relative_path)
    except (FileNotFoundError, ImportError):
        logger.debug('Django Settings Module could not be loaded from file (%s)' % relative_path)
    
    try:
        assert settings
    except AssertionError:
        logger.error('Django Settings Module failed to import.')
        sys.exit(1)

    return settings

def parse_arguments():
    valid_arguments = True
    parser = argparse.ArgumentParser(description='Provision Django application environments.')
    parser.add_argument('--log', dest='loglevel', action='store', default='ERROR',
                        help='set log level [DEBUG, INFO, WARNING, ERROR, CRITICAL] (default: ERROR)')
    parser.add_argument('--project', dest='directory', action='store', default=os.getcwd(),
                        help='set Django project directory')
    args = parser.parse_args()
    
    try:
        assert args.loglevel.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    except AssertionError:
        print('Invalid log option (%s).' % args.loglevel, file=sys.stderr)
        valid_arguments = False
        
    try:
        assert os.path.isdir(args.directory)
    except AssertionError:
        print('Invalid Django project directory (%s).' % args.directory, file=sys.stderr)
        valid_arguments = False
        
    if not valid_arguments:
        sys.exit(1)
        
    return args

def configure_logger(args):
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)
    logging.basicConfig(level=numeric_level)

def main():
    args = parse_arguments()
    configure_logger(args)
    settings = import_settings(args)
    
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