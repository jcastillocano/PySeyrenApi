
import sys
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = ['--cov=seyren', '-vvv']

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

setup(
    name='PySeyrenApi',
    license='BSD',
    author='Nikolay Denev',
    author_email='ndenev@gmail.com',
    install_requires=['requests', 'cerberus'],
    tests_require=['pytest', 'pytest-cov'],
    #test_suite="tests",
    cmdclass = {'test': PyTest},
    version='0.0.1',
    packages=find_packages(),
    description='PySeyrenApi is a Python client for the Seyren\'s alerting dashboard REST API. (https://github.com/scobal/seyren)',
    long_description=''
)
