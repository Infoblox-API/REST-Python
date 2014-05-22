from setuptools import setup, find_packages
import sys
import os

long_description = 'IBConn is a library for working with the infoblox rest api'
version = '0.0.2'

setup(
    name='ibconn',
    version=version,
    description="infoblox client library",
    long_description=long_description,
    url='http://github.com/huit/python-ibconn',
    keywords='infoblox',
    author='Luke Sullivan',
    author_email='luke_sullivan@harvard.edu',
    license='MIT',
    packages=['ibconn'],
    install_requires=[
        # -*- Extra requirements: -*-
    ],
    entry_points= {
    },
    tests_require = [
        'flake8>=2.1.0',
        'nose>=1.3.0',
        'coverage>=3.7',
    ],
)
