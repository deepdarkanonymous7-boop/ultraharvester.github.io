from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [l.strip() for l in f if l.strip() and not l.startswith("#")]

setup(
    name="ultraharvester",
    version="1.0.0",
    author="UltraHarvester Team",
    description="Advanced OSINT Information Gathering Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ultraharvester/ultraharvester",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ultraharvester=ultraharvester.cli:main",
            "uh=ultraharvester.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet",
    ],
    keywords="osint, information-gathering, security, reconnaissance, pentesting",
    package_data={
        "ultraharvester": [
            "web/templates/*.html",
            "web/static/**/*",
        ]
    },
)
