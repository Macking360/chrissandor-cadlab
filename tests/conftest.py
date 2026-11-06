
import pytest

from cadlab import cli
from cadlab.log import AppLog
from cadlab.platform_support import current_layout

PASSWORD = "unit test password 123"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "cadlab-home"
    monkeypatch.setenv("CADLAB_HOME", str(home))
    monkeypatch.setenv("CADLAB_PASSWORD", PASSWORD)
    monkeypatch.setenv("CADLAB_SKIP_ACL", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    AppLog._bound = None
    yield home


@pytest.fixture
def layout(isolated_home):
    from cadlab.platform_support import initialize_layout
    return initialize_layout(current_layout())


@pytest.fixture
def lab(layout):
    from cadlab.pki import PKILab
    instance = PKILab(layout)
    instance.create_root(years=10)
    instance.create_intermediate(years=5)
    yield instance
    instance.close()


@pytest.fixture
def run(capsys):
    def call(*argv):
        code = cli.main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err
    return call
