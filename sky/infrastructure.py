import sys
import logging
from .state import CREATION_MODE

logger = logging.getLogger(__name__)

class Infrastructure(object):

    _wrapped = None
    _dependencies = None
    _category = None
    _original_creation_mode = None
    _locals = None
    _result = None

    def __init__(self, callable_, *args, **kwargs):
        self.__name__ = callable_.__name__ if hasattr(callable_, '__name__') else 'undefined'
        self.__doc__ = callable_.__doc__ if hasattr(callable_, '__doc__') else None
        self.__module__ = callable_.__module__ if hasattr(callable_, '__module__') else None

        self._wrapped = callable_
        self.environment = kwargs.get('environment', None)
        self.dependencies = kwargs.get('requires', None)

    def __repr__(self):
        return 'Infrastructure:' + self.__name__

    def __call__(self, *args, **kwargs):

        # Set the creation mode, if the object specifies one.
        self._set_creation_mode()

        # Define a source code profiler.
        def profiler(frame, event, arg):
            if event == 'return':
                self._locals = frame.f_locals.copy()

        # Activate the profiler on the next call, return or exception.
        sys.setprofile(profiler)
        try:
            # Trace the function call.
            self._result = self._wrapped(*args, **kwargs)
        finally:
            # Disable the source code profiler.
            sys.setprofile(None)

        # Reset the creation mode, if the object specifies one.
        self._reset_creation_mode()

        return self._result

    def __getattr__(self, attr):
            return self._locals[attr]

    def _set_creation_mode(self):
        global CREATION_MODE
        if self.category:
            self._original_creation_mode = CREATION_MODE
            CREATION_MODE = self.category
            logger.debug('Set CREATION_MODE to \'%s\'.' % self.category.title())

    def _reset_creation_mode(self):
        global CREATION_MODE
        if self.category:
            CREATION_MODE = self._original_creation_mode
            logger.debug('Set CREATION_MODE to \'%s\'.' % (self._original_creation_mode.title() \
                                                           if isinstance(self._original_creation_mode, str) \
                                                           else self._original_creation_mode))

    @property
    def dependencies(self):
        return self._dependencies

    @dependencies.setter
    def dependencies(self, dependencies):
        if dependencies:
            self._dependencies = set(dependencies)
            logger.debug('Set (%s) dependencies to (%s).' % (self, ', '.join(list(dependencies))))

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, category):
        self._category = category
        logger.debug('Set (%s) to \'%s\' Creation Mode.' % (self, category.title()))

    @property
    def resources(self):
        return self._locals

    @property
    def result(self):
        return self._result
