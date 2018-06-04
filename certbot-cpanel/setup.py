from setuptools import setup

setup(
    name='certbot-cpanel',
    version='0.0.1',
    package='cpanel.py',
    install_requires=[
        'certbot',
        'zope.interface',
        'requests',
    ],
    entry_points={
        'certbot.plugins': [
            'cpanel = cpanel:Configurator',
        ],
    },
)
