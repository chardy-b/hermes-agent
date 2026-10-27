"""A relocated ``state.db`` keeps its profile ownership at runtime boundaries."""

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest


class _Registry:
    def __init__(self):
        self.calls = []

    def add(self, home, authority, *, name):
        self.calls.append(('add', home, authority, name))

    def replace(self, home, authority):
        self.calls.append(('replace', home, authority))

    def __iter__(self):
        return iter(())


def _relocated_store(tmp_path):
    home = tmp_path / 'profile'
    target = tmp_path / 'relocated' / 'state.db'
    home.mkdir()
    target.parent.mkdir()
    target.touch()
    (home / 'state.db').symlink_to(target)
    return home, target


@pytest.mark.asyncio
async def test_profile_authority_accepts_the_store_named_by_a_state_db_symlink(tmp_path, monkeypatch):
    from gateway import run, run_runtime
    from gateway import session_authority

    home, target = _relocated_store(tmp_path)
    db = SimpleNamespace(db_path=home / 'state.db')
    registry = _Registry()
    runner = SimpleNamespace(
        _session_db=db,
        session_authorities=registry,
        session_runtime_descriptor={'instance_id': 'runtime'},
    )
    authority = object()
    initialized = []

    async def initialize(actual_runner, **kwargs):
        initialized.append((actual_runner, kwargs))
        return authority

    monkeypatch.setattr(run, '_profile_runtime_scope', lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(session_authority, 'initialize_session_authority', initialize)

    assert await run_runtime._build_profile_authority(runner, 'sol', home, register=True) is authority
    assert Path(db.db_path).resolve() == target
    assert initialized == [(runner, {
        'profile_id': str(home), 'instance_id': 'runtime', 'db': db, 'register': True,
    })]
    assert registry.calls == [
        ('add', home, None, 'sol'),
        ('replace', home, authority),
    ]


@pytest.mark.asyncio
async def test_profile_authority_rejects_a_different_profiles_store(tmp_path, monkeypatch):
    from gateway import run, run_runtime
    from gateway import session_authority

    home, expected = _relocated_store(tmp_path)
    foreign = tmp_path / 'foreign' / 'state.db'
    foreign.parent.mkdir()
    foreign.touch()
    registry = _Registry()
    runner = SimpleNamespace(
        _session_db=SimpleNamespace(db_path=foreign),
        session_authorities=registry,
        session_runtime_descriptor={'instance_id': 'runtime'},
    )

    async def unexpected_initialize(*args, **kwargs):
        raise AssertionError('a foreign store must not create an authority')

    monkeypatch.setattr(run, '_profile_runtime_scope', lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(session_authority, 'initialize_session_authority', unexpected_initialize)

    with pytest.raises(RuntimeError) as exc:
        await run_runtime._build_profile_authority(runner, 'sol', home, register=False)

    message = str(exc.value)
    assert 'does not belong to the reserved profile' in message
    assert f'opened {foreign}' in message
    assert f'expected {expected}' in message
    assert registry.calls == []


@pytest.mark.asyncio
async def test_profile_authority_rejects_a_store_already_owned_by_another_profile(tmp_path, monkeypatch):
    from gateway import run, run_runtime
    from gateway import session_authority
    from gateway.session_authorities import SessionAuthorities

    launch, target = _relocated_store(tmp_path)
    secondary = tmp_path / 'secondary'
    secondary.mkdir()
    (secondary / 'state.db').symlink_to(target)
    launch_authority = SimpleNamespace(
        profile_id=str(launch), db=SimpleNamespace(db_path=launch / 'state.db'))
    registry = SessionAuthorities(launch, multiplexed=True)
    registry.add(launch, launch_authority, name='default')
    runner = SimpleNamespace(
        _session_db=SimpleNamespace(db_path=secondary / 'state.db'),
        session_authorities=registry,
        session_runtime_descriptor={'instance_id': 'runtime'},
    )

    async def unexpected_initialize(*args, **kwargs):
        raise AssertionError('one store must not create authorities for two profile homes')

    monkeypatch.setattr(run, '_profile_runtime_scope', lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(session_authority, 'initialize_session_authority', unexpected_initialize)

    with pytest.raises(RuntimeError) as exc:
        await run_runtime._build_profile_authority(runner, 'secondary', secondary, register=False)

    message = str(exc.value)
    assert 'already owned' in message
    assert str(launch) in message
    assert str(target) in message
    assert registry.for_home(secondary) is None


def test_api_image_collector_accepts_a_symlinked_active_store(tmp_path, monkeypatch):
    from gateway import session_ingress_media as media
    import hermes_constants

    home, target = _relocated_store(tmp_path)
    digest = 'a' * 64
    image = tmp_path / 'media' / digest / f'api_{digest[:32]}.png'
    image.parent.mkdir(parents=True)
    image.touch()
    db = SimpleNamespace(db_path=home / 'state.db')
    released = []

    def release(actual_db, references):
        released.append((actual_db, references))
        return len(references)

    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: home)
    monkeypatch.setattr(media, '_media_root', lambda: image.parent.parent)
    monkeypatch.setattr(media, 'release_unheld_media', release)

    assert media.collect_unheld_api_images(db) == 1
    assert Path(db.db_path).resolve() == target
    assert released == [(db, [{'path': str(image), 'sha256': digest}])]


def test_api_image_collector_rejects_a_foreign_store(tmp_path, monkeypatch):
    from gateway import session_ingress_media as media
    import hermes_constants

    home, _target = _relocated_store(tmp_path)
    foreign = tmp_path / 'foreign' / 'state.db'
    foreign.parent.mkdir()
    foreign.touch()
    monkeypatch.setattr(hermes_constants, 'get_hermes_home', lambda: home)
    monkeypatch.setattr(media, '_media_root', lambda: (_ for _ in ()).throw(
        AssertionError('a foreign store must not enumerate active-profile media')))

    assert media.collect_unheld_api_images(SimpleNamespace(db_path=foreign)) == 0
