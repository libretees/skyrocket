import os
import imp
import logging

logger = logging.getLogger(__name__)

def import_settings(args):
    settings = None
    if os.environ.get('DJANGO_SETTINGS_MODULE'):
        try:
            import_module('settings', os.environ['DJANGO_SETTINGS_MODULE'])
            logger.debug('Django Settings Module loaded (%s).' % os.environ['DJANGO_SETTINGS_MODULE'])
        except:
            logger.debug('Django Settings Module could not be loaded from path given in environment variable.')

    project_directory = os.path.abspath(os.path.expanduser(args.directory))
    project_name = project_directory.split(os.sep)[-1]
    relative_path = os.path.join(os.path.relpath(project_directory, os.getcwd()), project_name, 'settings.py')
    logger.info('Loading (%s).' % relative_path)
    try:
        imp.load_source('settings', relative_path)
        import settings
        logger.debug('Django Settings Module loaded from file (%s).' % relative_path)
    except (FileNotFoundError, ImportError):
        logger.debug('Django Settings Module could not be loaded from file (%s).' % relative_path)

    try:
        assert settings
    except AssertionError:
        logger.error('Django Settings Module failed to import.')
        if __name__ == '__main__':
            logger.error('Exiting...')
            sys.exit(1)

    return settings