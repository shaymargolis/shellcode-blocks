import pytest

from tempfile import TemporaryDirectory

from pathlib import Path


@pytest.fixture(scope='function')
def temp_dir_path():
    tempdir = TemporaryDirectory()
    yield Path(tempdir.name)
    tempdir.cleanup()
