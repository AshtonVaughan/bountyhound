"""Setup configuration for BountyHound Agent."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="bountyhound-agent",
    version="7.0.0",
    description="Advanced bug bounty hunting framework with AI-driven testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="BountyHound Team",
    author_email="",
    url="https://github.com/yourusername/bountyhound-agent",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        "colorama>=0.4.6",
        "requests>=2.31.0",
        "boto3>=1.28.0",
        "botocore>=1.31.0",
    ],
    extras_require={
        "mobile": [
            "frida",
            "frida-tools",
            "androguard",
        ],
        "cloud": [
            "boto3",
            "awscli",
        ],
        "blockchain": [
            "slither-analyzer",
            "mythril",
            "web3",
        ],
        "sast": [
            "semgrep",
            "bandit",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-xdist>=3.3.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.4.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    entry_points={
        "console_scripts": [
            "bountyhound=cli.main:main",
        ],
    },
)
