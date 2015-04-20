import logging

logger = logging.getLogger(__name__)

class Infrastructure(object):

     _category = None

     def __init__(self, callable, environment=None):
          self.wrapped = callable

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
          logger.info('Set Infrastructure object at (%d) to \'%s\' Creation Mode.' % (id(self), category.title()))