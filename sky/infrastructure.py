import logging

logger = logging.getLogger(__name__)

class Infrastructure(object):

     wrapped = None
     environment = None
     dependencies = None
     _category = None

     def __init__(self, callable, *args, **kwargs):
          self.wrapped = callable
          self.environment = kwargs.get('environment', None)

          self.dependencies = kwargs.get('requires', None)
          if self.dependencies:
               self.dependencies = set(self.dependencies)

          self.__name__ = callable.__name__ if hasattr(callable, '__name__') else 'undefined'
          self.__doc__ = callable.__doc__ if hasattr(callable, '__doc__') else None
          self.__module__ = callable.__module__ if hasattr(callable, '__module__') else None

     def __call__(self, *args, **kwargs):
        return self.run(*args, **kwargs)

     def run(self, *args, **kwargs):
        return self.wrapped(*args, **kwargs)

     @property
     def category(self):
          return self._category

     @category.setter
     def category(self, category):
          self._category = category
          logger.debug('Set Infrastructure object (%s) at (0x%x) to \'%s\' Creation Mode.' % (self.__name__, id(self), category.title()))
