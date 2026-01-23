from setuptools import setup, find_packages
import os

# Read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="vouch",
    version="0.1.0",
    description="Forensic logging and verification tool for data analysis workflows.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="Vouch Team",
    author_email="info@vouch-audit.org", # Placeholder
    url="https://github.com/vouch-audit/vouch", # Placeholder
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        "cryptography>=41.0.0",
        "pandas>=2.0.0",
        "numpy>=1.20.0",
        "asn1crypto>=1.5.0",
        "ijson>=3.0.0",
        "pyyaml>=6.0.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Legal Industry",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
    entry_points={
        "console_scripts": [
            "vouch=vouch.cli:main",
        ],
    },
)
