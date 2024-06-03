#!/usr/bin/env python

"""The setup script."""

from setuptools import find_packages, setup

requirements = []

test_requirements = []

setup(
    author="Signals Corps",
    author_email="hq@signalscorps.com",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    description="",
    entry_points={
        "console_scripts": [
            "cwe2stix=cwe2stix.cli:main",
        ],
    },
    install_requires=requirements,
    license="Apache License",
    include_package_data=True,
    keywords="cwe2stix",
    name="cwe2stix",
    packages=find_packages(include=["cwe2stix", "cwe2stix.*"]),
    tests_require=test_requirements,
    url="https://github.com/signalscorps/cwe2stix",
    version="0.1.0",
    zip_safe=False,
)
