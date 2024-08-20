from setuptools import setup, find_packages


setup(
    name="shellblocks",
    version="0.1",
    packages=find_packages(),
    package_data={
        "shellblocks": ["**/*.c", "**/*.S", "**/*.ld", "**/*.h"]
    }
)
