import os
from setuptools import setup, find_packages

__package_name__ = "jarm"
__version__ = ""
__author_name__ = ""
__author_email__ = ""
__description__ = "JARM hashing library and tool"

this_directory = os.path.abspath(os.path.dirname(__file__))
readme_path = os.path.join(this_directory, "README.md")
with open(readme_path, encoding="utf-8") as handle:
    long_description = handle.read()

setup(
    name=__package_name__,
    version=__version__,
    author=__author_name__,
    author_email=__author_email__,
    description=__description__,
    long_description=long_description,
    scripts = ["bin/jarm"],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
    ],
)
