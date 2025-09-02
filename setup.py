"""
Setup configuration for TIFA - Threat Intelligence Feed Aggregator
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh.readlines() if line.strip() and not line.startswith("#")]

setup(
    name="tifa",
    version="2.0.0",
    author="TIFA Team",
    description="Elite Threat Intelligence Feed Aggregator with AI Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Deepam02/TIFA",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "tifa=app:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
