import functools
import logging
from .infrastructure import Infrastructure
import core

logger = logging.getLogger(__name__)

EPHEMERAL = core.EPHEMERAL
PERMANENT = core.PERMANENT

def ephemeral(*args, **kwargs):
    # Determine whether or not the decorator was invoked.
    invoked = bool(args and not callable(args[0]) or kwargs)

    if not invoked:
        # Wrap the function in a decorator that sets the infrastructure creation mode to EPHEMERAL.

        function, args = args[0], ()
        @functools.wraps(function)
        def decorator(*args, **kwargs):
            core.CREATION_MODE = EPHEMERAL
            return function(*args, **kwargs)
        logging.info('Decorated (%s) as a \'Ephemeral\' Creation Mode function.' % function.__name__)
    else:
        # Define a decorator that will wrap a function in an Ephemeral Infrastructure object.

        def decorator(function):
            infrastructure = Infrastructure(function, *args, **kwargs)
            infrastructure.category = EPHEMERAL
            logging.info('Decorated (%s) as an Ephemeral Infrastructure object.' % function.__name__)
            return infrastructure

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
