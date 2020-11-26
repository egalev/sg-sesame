#!/usr/bin/env python

from setuptools import setup, find_packages  # type: ignore

with open("README.md") as readme_file:
    readme = readme_file.read()

with open("requirements.txt") as req_file:
    requirements = req_file.readlines()

with open("src/sg_sesame/_version.py") as ver_file:
    version = ver_file.read().split(" = ")[1].strip().replace("'", "")

cmd_name = "sg-sesame"

setup(
    author="Yigal Lazarev",
    author_email="yigal@lazarev.co",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
    ],
    description="Open ports in Security Groups for your current IP address",
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme,
    long_description_content_type="text/markdown",
    package_data={"sg_sesame": ["py.typed"]},
    include_package_data=True,
    keywords="sg_sesame",
    name="sg-sesame",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    entry_points={
        "console_scripts": ["{}=sg_sesame.sg_sesame:sg_sesame".format(cmd_name)]
    },
    url="https://github.com/stopmachine/sg-sesame",
    version=version,
    zip_safe=False,
)
