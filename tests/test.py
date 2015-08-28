#!/usr/bin/env python
# -*- coding: utf-8 -*-
from compat import unittest

if __name__ == '__main__':
    # Use the basic test runner that outputs to sys.stderr.
    test_runner = unittest.TextTestRunner()

    # Compile the test suite from the current working directory.
    test_suite = unittest.defaultTestLoader.discover('.')

    # Run unit tests.
    test_runner.run(test_suite)
