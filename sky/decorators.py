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

    # Determine whether or not the decorator was invoked.
    invoked = bool(args and not callable(args[0]) or kwargs)
    if not invoked:
        function, args = args[0], ()

    # Define decorator function.
    def decorator(function):
        return Infrastructure(function, *args, **kwargs)

    # If invoked, return the decorator function, which will then be called. Otherwise, return the decorated function.
    return decorator if invoked else decorator(function)
