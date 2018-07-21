from setuptools import find_packages
from setuptools import setup
import os
import pip

try: # for pip >= 10
    from pip._internal.req import parse_requirements
    from pip._internal.download import PipSession
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements
    from pip.download import PipSession

_here = os.path.dirname(__file__)
_install_requirements = parse_requirements(
    'requirements.txt', session=PipSession())


setup(
    name='airlock',
    version=open(os.path.join(_here, 'airlock', 'VERSION')).read().strip(),
    description=(
        'A lightweight wrapper providing Google OAuth2 integration, sessions, '
        'XSRF validators, and user management for App Engine apps.'
    ),
    url='https://github.com/grow/airlock',
    license='MIT',
    author='Grow SDK Authors',
    author_email='hello@grow.io',
    include_package_data=True,
    install_requires=[str(ir.req) for ir in _install_requirements],
    packages=find_packages(),
    keywords=[
        'cloud endpoints',
        'google app engine',
        'oauth2',
    ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ])
