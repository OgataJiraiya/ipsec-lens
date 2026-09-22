import pytest
from fastapi.testclient import TestClient
from backend.api.main import create_app
from scripts.fixtures import generate


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    return generate(tmp_path_factory.mktemp("captures"))


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "runtime")
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.state.store.engine.dispose()


@pytest.fixture
def strong(fixtures):
    return fixtures["strong"]


@pytest.fixture
def strong_run(strong):
    from backend.services.analysis import build_analysis
    from backend.telemetry.importer import Telemetry
    return build_analysis(strong, "a"*32, strong.name, "Test", "MODERN",
        telemetry=Telemetry.model_validate_json((strong.parent / "telemetry.json").read_bytes()))
