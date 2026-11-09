"""Cron ownership and execution use the reserved profile, not relocated SQLite storage."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.platforms('posix')


@pytest.fixture
def relocated_profile(tmp_path, monkeypatch):
    root = tmp_path / '.hermes'
    home = root / 'profiles' / 'teo'
    foreign = root / 'profiles' / 'other'
    target = tmp_path / 'hermes-state' / 'teo' / 'state.db'
    for directory in (home, foreign, target.parent):
        directory.mkdir(parents=True)
    (home / 'state.db').symlink_to(target)
    (root / '.env').write_text('OPENAI_API_KEY=launch-only-test-key\n')
    (home / '.env').write_text('OPENAI_API_KEY=teo-only-test-key\n')
    (foreign / '.env').write_text('OPENAI_API_KEY=other-only-test-key\n')
    (root / 'config.yaml').write_text(json.dumps({'gateway': {'profile_routes': [
        {'platform': 'telegram', 'chat_id': '12345', 'profile': 'teo'},
        {'platform': 'telegram', 'chat_id': '67890', 'profile': 'other'},
    ]}}))
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(root))
    monkeypatch.setenv('HERMES_RUNTIME_DIR', str(tmp_path / 'runtime'))
    monkeypatch.setenv('OPENAI_API_KEY', 'launch-only-test-key')
    return root, home, target


@pytest.mark.asyncio
async def test_cron_owner_lookup_uses_profile_even_when_store_is_relocated(relocated_profile):
    from gateway import session_cron
    from hermes_state_registry import acquire

    root, home, target = relocated_profile
    with acquire(home / 'state.db') as db:
        authority = SimpleNamespace(profile_id=str(home), db=db)
        session_cron.bind_owner(authority)
        try:
            assert (home / 'state.db').resolve() == target
            assert db.db_path == target
            owner = session_cron.owner_for_home(home)
            assert owner == (authority, asyncio.get_running_loop())
            assert session_cron.owner_for_home(target.parent) is None
            assert session_cron.owner_for_home(root) is None
            assert session_cron.owner_for_home(root / 'profiles' / 'other') is None
        finally:
            session_cron.unbind_owner(authority)
        assert session_cron.owner_for_home(home) is None


_CHILD_PROBE = """
import json
from cron.scheduler_preflight import _primary_profile_routes_for_current_home, _preflight_check_delivery
from hermes_cli.profiles import profile_matches_home
from hermes_constants import get_hermes_home, get_default_hermes_root
print(json.dumps({
    'home': str(get_hermes_home()), 'root': str(get_default_hermes_root()),
    'matches': profile_matches_home('teo'), 'foreign_matches': profile_matches_home('other'),
    'routes': [route.chat_id for route in _primary_profile_routes_for_current_home()],
    'preflight': _preflight_check_delivery({'deliver': 'telegram:12345'}),
}))
"""


@pytest.mark.asyncio
async def test_cron_execution_and_child_keep_canonical_profile_home(relocated_profile, monkeypatch):
    from agent.secret_scope import get_secret
    from cron import scheduler
    from gateway import session_cron
    from gateway.session_authority import LiveSession, SessionAuthority
    from gateway.session_contract import SessionRef
    from hermes_constants import get_hermes_home
    from hermes_state_registry import acquire
    from hermes_state_runtime import begin_runtime_epoch
    from tools.environments.local import build_subprocess_env, strip_launch_profile_env

    root, home, target = relocated_profile
    seen = {}

    def run_job(job, **kwargs):
        seen['home'] = get_hermes_home()
        seen['key'] = get_secret('OPENAI_API_KEY')
        env = strip_launch_profile_env(build_subprocess_env(scrub_secrets=True, inherit_profile_home=True))
        seen['env_home'] = env['HERMES_HOME']
        seen['env_key'] = env.get('OPENAI_API_KEY')
        # Real child imports: ContextVars cannot carry identity across this boundary.
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[2])
        child = subprocess.run([sys.executable, '-c', _CHILD_PROBE], env=env,
                               text=True, capture_output=True, timeout=30, check=True)
        seen['child'] = json.loads(child.stdout)
        return True, 'document', 'answer', None

    monkeypatch.setattr(scheduler, 'run_job', run_job)
    with acquire(home / 'state.db') as db:
        authority = SessionAuthority(SimpleNamespace(_draining=False), profile_id=str(home),
                                     instance_id='test', db=db,
                                     epoch=begin_runtime_epoch(db, instance_id='test'))
        authority.sessions['s'] = LiveSession(SimpleNamespace(user_id='cron-owner'), 'route')
        row = {'payload': {'text': ''}, 'request_id': 'cron:job:fire',
               'principal_id': 'cron-owner', 'admission_id': 'admission'}
        policy = SimpleNamespace(request_json=json.dumps({
            'extra_prompt': None, 'request_id': row['request_id'], 'cron_job': {'id': 'job'}}))
        assert await session_cron.execute(authority, SessionRef(str(home), 's'), row, policy) == 'answer'
        assert authority.pending_results['admission']['result']['completed'] is True
        assert db.db_path == target
    assert seen == {
        'home': home, 'key': 'teo-only-test-key', 'env_home': str(home), 'env_key': None,
        'child': {'home': str(home), 'root': str(root), 'matches': True, 'foreign_matches': False,
                  'routes': ['12345'], 'preflight': None},
    }
    assert get_hermes_home() == root
    assert session_cron.current_execution() is None
    assert authority._cron_cancellations == {}
    assert not (target.parent / 'cron').exists()
