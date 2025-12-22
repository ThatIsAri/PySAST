# setup.py
from setuptools import setup, find_packages

setup(
    name="pysast",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "astunparse>=1.6.3",
        "Jinja2>=3.0.0",
        "colorama>=0.4.4",
        "pygments>=2.10.0",
        "markdown>=3.3.4",
        "pytest>=6.2.5",
    ],
    entry_points={
        'console_scripts': [
            'pysast=run_scanner:main',
        ],
    },
    python_requires='>=3.7',
)