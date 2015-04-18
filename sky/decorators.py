import functools
import logging
from .infrastructure import Infrastructure
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

def infrastructure(*args, **kwargs):

    invoked = bool(not args or kwargs)
    if not invoked:
        func, args = args[0], ()

    def decorator(func):
        return Infrastructure(func, *args, **kwargs)

    return decorator if invoked else decorator(func)
