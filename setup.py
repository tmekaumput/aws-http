import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aws-http",
    version="0.0.1",
    author="Top Mekaumput",
    author_email="top.mekaumput@iomate.com.au",
    description="AWS HTTP Package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tmekaumput/aws-http",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)