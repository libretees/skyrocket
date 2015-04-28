#!/usr/bin/env python
from distutils.core import setup

setup(
    name = 'skyman',
    packages = ['sky'],
    version = '0.1',
    description = 'Sky is a tool that allows quick and repeatable deployment and management of cloud environments.',
    author = 'Jared Contrascere',
    author_email = 'jcontra@gmail.com',
    url = 'https://github.com/libretees/sky',

    install_requires=['boto==2.36.0'],
    entry_points={
        'console_scripts': [
            'sky = sky.main:main',
        ]
    },
    classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Unix',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Programming Language :: Python :: 3.4',
          'Topic :: Software Development',
          'Topic :: Software Development :: Build Tools',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Software Distribution',
          'Topic :: System :: Systems Administration',
    ],
)
