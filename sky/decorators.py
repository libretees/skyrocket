import functools
import logging
from .infrastructure import Infrastructure
from .state import config, mode

logger = logging.getLogger(__name__)

def ephemeral(*args, **kwargs):
    # Determine whether or not the decorator was invoked.
    invoked = bool(not args or args and not callable(args[0]) or kwargs)
    logger.debug('@ephemeral Decorator was invoked.' if invoked else '@ephemeral Decorator was not invoked.')

    if not invoked:
        if isinstance(args[0], Infrastructure):
            # Set a wrapped Infractructure object to EPHEMERAL creation mode.
            infrastructure = args[0]
            infrastructure.category = mode.EPHEMERAL
            decorator = infrastructure
        else:
            # Wrap a function in a decorator that sets the infrastructure creation mode to mode.EPHEMERAL.
            function, args = args[0], ()
            @functools.wraps(function)
            def decorator(*args, **kwargs):
                config['CREATION_MODE'] = mode.EPHEMERAL
                return function(*args, **kwargs)
            logging.info('Decorated (%s) as an \'Ephemeral\' Creation Mode function.' % function.__name__)
    else:
        # Define a decorator that will wrap a function in an Ephemeral Infrastructure object.
        def decorator(function):
            infrastructure = Infrastructure(function, *args, **kwargs)
            infrastructure.category = mode.EPHEMERAL
            logging.info('Decorated (%s) as an Ephemeral Infrastructure object.' % function.__name__)
            return infrastructure

    return decorator

def permanent(*args, **kwargs):
    # Determine whether or not the decorator was invoked.
    invoked = bool(not args or args and not callable(args[0]) or kwargs)
    logger.debug('@permanent Decorator was invoked.' if invoked else '@permanent Decorator was not invoked.')

    if not invoked:
        if isinstance(args[0], Infrastructure):
            # Set a wrapped Infractructure object to PERMANENT creation mode.
            infrastructure = args[0]
            infrastructure.category = mode.PERMANENT
            decorator = infrastructure
        else:
            # Wrap the function in a decorator that sets the infrastructure creation mode to mode.PERMANENT.
            function, args = args[0], ()
            @functools.wraps(function)
            def decorator(*args, **kwargs):
                config['CREATION_MODE'] = mode.PERMANENT
                return function(*args, **kwargs)
            logging.info('Decorated (%s) as a \'Permanent\' Creation Mode function.' % function.__name__)
    else:
        # Define a decorator that will wrap a function in an Permanent Infrastructure object.
        def decorator(function):
            infrastructure = Infrastructure(function, *args, **kwargs)
            infrastructure.category = mode.PERMANENT
            logging.info('Decorated (%s) as an Permanent Infrastructure object.' % function.__name__)
            return infrastructure

    return decorator

def infrastructure(*args, **kwargs):
    # Determine whether or not the decorator was invoked.
    invoked = bool(not args or args and not callable(args[0]) or kwargs)
    logger.debug('@infrastructure Decorator was invoked.' if invoked else '@infrastructure Decorator was not invoked.')

    if not invoked:
        function, args = args[0], ()

    # Define decorator function.
    def decorator(function):
        return Infrastructure(function, *args, **kwargs)

    # If invoked, return the decorator function, which be called immediately. Otherwise, return the decorated function.
    return decorator if invoked else decorator(function)
