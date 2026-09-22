"""Local lifecycle boundaries: typed exports, exact-ID deletion and retry semantics."""
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import event
from backend.schemas.models import Analysis
from backend.tests.test_api import upload


def folder(client):
    return Path(client.app.state.store.engine.url.database).parent


def test_export_persisted_revision_and_safe_headers(client, strong):
    run = upload(client, strong, label='<script>display only</script>').json()
    telemetry = json.loads((strong.parent / 'telemetry.json').read_text())
    telemetry['expected_revision'] = 1
    updated = client.post(f"/api/analyses/{run['analysis_id']}/telemetry", json=telemetry).json()
    result = client.get(f"/api/analyses/{run['analysis_id']}/export")
    assert result.status_code == 200
    assert result.headers['content-type'] == 'application/json'
    assert result.headers['x-content-type-options'] == 'nosniff'
    assert result.headers['content-disposition'] == f'attachment; filename="ipseclens-{run["analysis_id"]}.json"'
    assert Analysis.model_validate(result.json()).revision == 2
    assert result.json() == updated
    assert str(folder(client)) not in result.text
    assert 'encryption_key"' not in result.text and 'private_key' not in result.text


@pytest.mark.parametrize('identity', ['z'*32, 'A'*32, 'a'*31, 'a'*33, '..%2Foutside', 'a'*32+'.pcap'])
def test_lifecycle_rejects_invalid_identity(client, identity):
    assert client.get(f'/api/analyses/{identity}/export').status_code == 404
    assert client.delete(f'/api/analyses/{identity}').status_code == 404


def test_missing_export_and_idempotent_delete(client):
    url = '/api/analyses/' + 'a'*32
    assert client.get(url+'/export').status_code == 404
    assert client.delete(url).json()['status'] == 'ALREADY_ABSENT'


@pytest.mark.parametrize('retained', [False, True])
def test_delete_only_selected_analysis(client, strong, retained):
    run = upload(client, strong, retain_capture=str(retained).lower()).json()
    other = upload(client, strong, retain_capture='true').json()
    path = folder(client)/'captures'/(run['analysis_id']+'.pcap')
    url = '/api/analyses/'+run['analysis_id']
    assert client.delete(url).json()['status'] == 'DELETED'
    assert not path.exists()
    assert client.get(url).status_code == 404
    assert client.get(url+'/export').status_code == 404
    assert client.get(url+'/report/technical').status_code == 404
    assert client.delete(url).json()['status'] == 'ALREADY_ABSENT'
    assert [r['analysis_id'] for r in client.get('/api/analyses').json()] == [other['analysis_id']]
    assert (folder(client)/'captures'/(other['analysis_id']+'.pcap')).exists()


def test_delete_missing_retained_capture(client, strong):
    run = upload(client, strong, retain_capture='true').json()
    (folder(client)/'captures'/(run['analysis_id']+'.pcap')).unlink()
    assert client.delete('/api/analyses/'+run['analysis_id']).json()['status'] == 'DELETED'


def test_nonretained_never_removes_unowned_file(client, strong):
    run = upload(client, strong).json()
    captures = folder(client)/'captures'
    captures.mkdir()
    path = captures/(run['analysis_id']+'.pcap')
    path.write_text('not owned by this analysis')
    assert client.delete('/api/analyses/'+run['analysis_id']).status_code == 200
    assert path.read_text() == 'not owned by this analysis'


@pytest.mark.parametrize('kind', ['file_link', 'directory_link', 'directory'])
def test_delete_refuses_symlinks_and_nonregular_files(client, strong, tmp_path, kind):
    run = upload(client, strong, retain_capture='true').json()
    captures = folder(client)/'captures'
    path = captures/(run['analysis_id']+'.pcap')
    outside = tmp_path/'outside'
    outside.mkdir()
    sentinel = outside/path.name
    sentinel.write_text('keep')
    path.unlink()
    if kind == 'file_link':
        path.symlink_to(sentinel)
    elif kind == 'directory_link':
        captures.rmdir()
        captures.symlink_to(outside, target_is_directory=True)
    else:
        path.mkdir()
    response = client.delete('/api/analyses/'+run['analysis_id'])
    assert response.status_code == 409
    assert client.app.state.store.get(run['analysis_id']) is not None
    assert sentinel.read_text() == 'keep'
    assert str(outside) not in response.text


def test_unlink_failure_rolls_back_and_retry_completes(client, strong, monkeypatch):
    run = upload(client, strong, retain_capture='true').json()
    store = client.app.state.store
    original = store._remove_capture
    def fail(identity):
        raise PermissionError('private path must not be reflected')
    monkeypatch.setattr(store, '_remove_capture', fail)
    response = client.delete('/api/analyses/'+run['analysis_id'])
    assert response.status_code == 409 and 'private path' not in response.text
    assert store.get(run['analysis_id']) is not None
    monkeypatch.setattr(store, '_remove_capture', original)
    assert client.delete('/api/analyses/'+run['analysis_id']).json()['status'] == 'DELETED'


def test_commit_failure_after_unlink_is_retryable(client, strong):
    run = upload(client, strong, retain_capture='true').json()
    store = client.app.state.store
    def fail(connection):
        raise RuntimeError('simulated commit failure')
    event.listen(store.engine, 'commit', fail)
    try:
        assert client.delete('/api/analyses/'+run['analysis_id']).status_code == 500
    finally:
        event.remove(store.engine, 'commit', fail)
    assert store.get(run['analysis_id']) is not None
    assert not (folder(client)/'captures'/(run['analysis_id']+'.pcap')).exists()
    assert client.delete('/api/analyses/'+run['analysis_id']).json()['status'] == 'DELETED'


def test_concurrent_delete_serializes_and_stale_update_cannot_restore(client, strong):
    run = upload(client, strong, retain_capture='true').json()
    store = client.app.state.store
    stale = store.get(run['analysis_id'])
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(store.delete, [run['analysis_id']]*2))
    assert sorted(results) == [False, True]
    with pytest.raises(ValueError):
        store.replace(stale, 1)
    assert store.get(run['analysis_id']) is None


def test_delete_origin_host_and_body_limits(client, strong, monkeypatch):
    run = upload(client, strong).json()
    url = '/api/analyses/'+run['analysis_id']
    assert client.delete(url, headers={'Origin':'https://untrusted.example'}).status_code == 403
    assert client.delete(url, headers={'Host':'untrusted.example'}).status_code == 400
    monkeypatch.setattr('backend.core.config.MAX_UPLOAD', 1)
    monkeypatch.setattr('backend.core.config.MAX_TELEMETRY', 1)
    assert client.request('DELETE', url, content=b'123').status_code == 413
    assert client.get(url).status_code == 200


def test_fixture_provenance_uses_content_not_name(client, strong, tmp_path):
    run = upload(client, strong).json()
    assert run['capture_source'] == 'SYNTHETIC_FIXTURE'
    assert 'Capture source: SYNTHETIC FIXTURE' in client.get('/api/analyses/'+run['analysis_id']+'/report/executive').text
    changed = tmp_path/'strong.pcap'
    # Different valid timestamp; cannot inherit fixture identity from its basename.
    raw = bytearray(strong.read_bytes())
    raw[24] ^= 1
    changed.write_bytes(raw)
    assert upload(client, changed).json()['capture_source'] == 'UNVERIFIED'
