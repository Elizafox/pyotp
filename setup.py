#!/usr/bin/env python3

from setuptools import setup, find_packages

# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pyotp",
    version="0.0.1",
    description="Utilities for using HOTP and TOTP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Elizafox/pyotp",
    author="Elizabeth Myers",
    author_email="elizabeth@interlinked.me",
    license="WTFPL version 2",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "License :: Public Domain",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    python_requires="~=3.4",
    keywords="hotp totp development",
    packages=find_packages(exclude=["docs", "tests"]),
    project_urls={
        "Bug Reports": "https://github.com/Elizafox/pyotp/issues",
        "Funding": "https://patreon.com/Elizafox",
        "Source": "https://github.com/Elizafox/pyotp",
    },
)
