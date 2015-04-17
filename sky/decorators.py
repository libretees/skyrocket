import functools
import logging
import core

logger = logging.getLogger(__name__)

def ephemeral(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        core.CREATION_MODE = core.EPHEMERAL
        return func(*args, **kwargs)
    logging.info('Decorated (%s) as an \'Ephemeral\' Creation Mode function.' % func.__name__)
    return decorator

def permanent(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        core.CREATION_MODE = core.PERMANENT
        return func(*args, **kwargs)
    logging.info('Decorated (%s) as a \'Permanent\' Creation Mode function.' % func.__name__)
    return decorator
