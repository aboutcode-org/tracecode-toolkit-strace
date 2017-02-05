#!/usr/bin/env python
# -*- encoding: utf-8 -*-

#
# Copyright (c) 2017 nexB Inc. http://www.nexb.com/ - All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

from glob import glob
from os.path import basename
from os.path import splitext
import sys

from setuptools import find_packages
from setuptools import setup


setup(
    name='tracecode-build',
    version='0.9.0',
    license='Apache-2.0 with Tracecode acknowledgment',
    long_description='TraceCode Dynamic build tracer',
    author='nexB Inc.',
    author_email='info@aboutcode.org',
    url='https://github.com/nexB/tracecode-build',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Utilities',
    ],
    keywords=[
        'tracecode', 'strace', 'tracing', 'build',
    ],

    install_requires=[
        'altgraph',
        'docopt',
    ],


    entry_points={
        'console_scripts': [
            'tracecode = tracecode.tracecode:cli',
        ],
    },
)
