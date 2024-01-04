import os

from setuptools import find_packages, setup

from src import singbox_converter


def read(fname):
    # file read function copied from sorl.django-documents project
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    'requests',
    'ruamel.yaml',
]

setup(
    name='PySingBoxConverter',
    version=singbox_converter.__version__,
    description="SingBox converter, Python",
    long_description_content_type="text/markdown",
    long_description=read('README.md'),
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='singbox converter clash subconverter',
    author='',
    author_email='',
    url='',
    license='MIT',
    packages=find_packages("src"),
    include_package_data=True,
    zip_safe=True,
    install_requires=install_requires,
    package_dir={"": "src"},
    entry_points={'console_scripts': [
        'singbox_convert=singbox_converter.main:main',
    ],
    },
    package_data={
        "singbox_converter": [
            "providers-example.json", "config_template/*.json"]
    }
)
