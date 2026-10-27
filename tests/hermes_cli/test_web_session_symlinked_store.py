"""Dashboard mutations recognize a profile whose ``state.db`` is relocated by symlink."""

import sys
from types import ModuleType, SimpleNamespace

import pytest
from fastapi import HTTPException
# The production helper late-imports these modules after the home-I/O test guard is active.
# Preload third-party-backed modules during collection; stub only the routing/auth collaborators.
from gateway import session_authorities as _session_authorities
from gateway import session_contract as _session_contract
from hermes_cli import web_server_sessions
import hermes_state


def _request(authority, runner=None):
    state = SimpleNamespace(native_http_principal=None, session=None)
    app_state = SimpleNamespace(
        auth_required=False,
        session_authority=authority,
        gateway_runner=runner,
    )
    return SimpleNamespace(state=state, app=SimpleNamespace(state=app_state))


def _relocated_store(tmp_path):
    home = tmp_path / 'profile'
    target = tmp_path / 'relocated' / 'state.db'
    home.mkdir()
    target.parent.mkdir()
    target.touch()
    (home / 'state.db').symlink_to(target)
    return home, target


def _stub_runtime_modules(monkeypatch, home):
    web = ModuleType('hermes_cli.web_server')
    web._has_valid_session_token = lambda request: True
    cron = ModuleType('hermes_cli.web_server_cron')
    cron._cron_profile_home = lambda profile: ('default', home)
    monkeypatch.setitem(sys.modules, web.__name__, web)
    monkeypatch.setitem(sys.modules, cron.__name__, cron)


def test_mutation_guard_accepts_the_authority_for_a_symlinked_store(tmp_path, monkeypatch):
    home, target = _relocated_store(tmp_path)
    authority = SimpleNamespace(profile_id=str(home), db=SimpleNamespace(db_path=home / 'state.db'))
    request = _request(authority)
    _stub_runtime_modules(monkeypatch, home)
    monkeypatch.setattr(hermes_state, '_default_db_path', lambda: home / 'state.db')

    owner, actor = web_server_sessions._session_mutation_context(request, None)

    assert owner is authority
    assert actor.profile_id == str(home)
    assert (home / 'state.db').resolve() == target


def test_mutation_guard_rejects_an_unregistered_profile_aliasing_the_launch_store(tmp_path, monkeypatch):
    from gateway.session_authorities import SessionAuthorities

    launch, target = _relocated_store(tmp_path)
    parked = tmp_path / 'profiles' / 'parked'
    parked.mkdir(parents=True)
    (parked / 'state.db').symlink_to(target)
    authority = SimpleNamespace(profile_id=str(launch), db=SimpleNamespace(db_path=launch / 'state.db'))
    registry = SessionAuthorities(launch, multiplexed=True)
    registry.add(launch, authority, name='default')
    runner = SimpleNamespace(session_authorities=registry, session_authority=authority)
    request = _request(authority, runner)
    _stub_runtime_modules(monkeypatch, parked)

    with pytest.raises(HTTPException) as exc:
        web_server_sessions._session_mutation_context(request, 'parked')

    assert exc.value.status_code == 403
    assert exc.value.detail == 'profile_mismatch'


def test_standalone_mutation_guard_rejects_another_home_aliasing_the_launch_store(tmp_path, monkeypatch):
    launch, target = _relocated_store(tmp_path)
    other = tmp_path / 'other'
    other.mkdir()
    (other / 'state.db').symlink_to(target)
    authority = SimpleNamespace(profile_id=str(launch), db=SimpleNamespace(db_path=launch / 'state.db'))
    request = _request(authority)
    _stub_runtime_modules(monkeypatch, other)

    with pytest.raises(HTTPException) as exc:
        web_server_sessions._session_mutation_context(request, 'other')

    assert exc.value.status_code == 403
    assert exc.value.detail == 'profile_mismatch'


def test_mutation_guard_rejects_an_authority_for_a_different_store(tmp_path, monkeypatch):
    home, _target = _relocated_store(tmp_path)
    foreign = tmp_path / 'foreign' / 'state.db'
    foreign.parent.mkdir()
    foreign.touch()
    authority = SimpleNamespace(profile_id=str(foreign.parent), db=SimpleNamespace(db_path=foreign))
    request = _request(authority)
    _stub_runtime_modules(monkeypatch, home)
    monkeypatch.setattr(hermes_state, '_default_db_path', lambda: home / 'state.db')

    with pytest.raises(HTTPException) as exc:
        web_server_sessions._session_mutation_context(request, None)

    assert exc.value.status_code == 403
    assert exc.value.detail == 'profile_mismatch'
