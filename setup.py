from setuptools import setup, find_packages

setup(
    name="vouch",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "pandas",
        "numpy",
        "asn1crypto",
    ],
    entry_points={
        "console_scripts": [
            "vouch=vouch.cli:main",
        ],
    },
)
