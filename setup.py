import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "awsheet",
    version = "0.0.4",
    author = "Mike Adler",
    author_email = "adler@stuntbeard.com",
    description = ("build repeatable stacks of AWS resources across prod and dev"),
    license = "Apache 2.0",
    #keywords = ""
    url = "http://github.com/adler/awsheet",
    packages=['awsheet', 'awsheet/helpers'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
    ],
    # install_requires is good for install via pip
    install_requires = ['boto', 'awscli'],
)
