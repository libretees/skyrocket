import sys
import logging
import core

logger = logging.getLogger(__name__)

class Infrastructure(object):

    wrapped = None
    environment = None
    dependencies = None
    _category = None
    _original_creation_mode = None
    _resource = {}
    _result = None

    def __init__(self, callable_, *args, **kwargs):
        self.wrapped = callable_
        self.environment = kwargs.get('environment', None)
        self.dependencies = kwargs.get('requires', None)
        if self.dependencies:
            self.dependencies = set(self.dependencies)
        self._locals = {}

        self.__name__ = callable_.__name__ if hasattr(callable, '__name__') else 'undefined'
        self.__doc__ = callable_.__doc__ if hasattr(callable, '__doc__') else None
        self.__module__ = callable_.__module__ if hasattr(callable, '__module__') else None

    def __call__(self, *args, **kwargs):

        # Set the creation mode, if the object specifies one.
        self._set_creation_mode()

        # Define a source code profiler.
        def profiler(frame, event, arg):
            if event == 'return':
                self._resource = frame.f_locals.copy()

        # Activate the profiler on the next call, return or exception.
        sys.setprofile(profiler)
        try:
            # Trace the function call.
            self._result = self.wrapped(*args, **kwargs)
        finally:
            # Disable the source code profiler.
            sys.setprofile(None)

        # Reset the creation mode, if the object specifies one.
        self._reset_creation_mode()

        return self._result

    def _set_creation_mode(self):
        if self.category:
            self._original_creation_mode = core.CREATION_MODE
            core.CREATION_MODE = self.category
            logger.debug('Set CREATION_MODE to \'%s\'.' % self.category.title())

    def _reset_creation_mode(self):
        if self.category:
            core.CREATION_MODE = self._original_creation_mode
            logger.debug('Set CREATION_MODE to \'%s\'.' % self._original_creation_mode)

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, category):
        self._category = category
        logger.debug('Set Infrastructure object (%s) at (0x%x) to \'%s\' Creation Mode.' % (self.__name__, id(self), category.title()))

    @property
    def result(self):
        return self._result

    @property
    def resource(self):
        return self._resource
