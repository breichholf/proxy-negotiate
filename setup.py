"""
proxy-negotiate
===============

Runs a small transparent proxy on localhost:8080 that serves as connection
for tools that can use a proxy, but not proxy negotiate (eg python requests!)

Author: Brian Reichholf
"""
from setuptools import setup, find_packages


setup(
    name='Proxy-Negotiate',
    author='Brian Reichholf',
    author_email='brian.reichholf@gmail.com',
    url='https://github.com/breichholf/proxy-negotiate',
    license='MIT',
    setup_requires=[
        'gevent',
        'gssapi',
        'winkerberos; sys_platform == "win32"',
    ],
    use_scm_version={
        'write_to': 'src/proxy-negotiate/_version.py',
        'write_to_template': '__version__ = "{version}"',
        'tag_regex': r'^(?P<prefix>v)?(?P<version>[^\+]+)(?P<suffix>.*)?$',
    },
    python_requires='>3.7',
    entry_points={
        'console_scripts': [
            'nc-negotiate = proxy_negotiate._netcat:main',
            'proxy-negotiate = proxy_negotiate._proxy:main',
        ]
    },
    packages=find_packages(where='src'),
    package_dir={
        '': 'src'
    },
    description='HTTP Negotiate proxy authentication support for applications.',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Security',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Utilities',
    ]
)
