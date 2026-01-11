from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pysast",
    version="2.0.0",
    author="Kudryavtsev G.G.",
    author_email="pulsneon@gmail.com",
    description="Статический анализатор кода для языков Python, Java, PHP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ThatIsAri/PySAST",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "pysast=pysast.cli:main",
        ],
    },
)