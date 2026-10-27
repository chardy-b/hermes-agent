"""Telegram-only Claude login command; no agent, transcript, or durable delivery path."""
from __future__ import annotations

import asyncio

from aiohttp import ClientSession, ClientTimeout

from gateway.claude_oauth_process import ClaudeLoginProcess
from gateway.claude_oauth_web import DISABLED, PATH, TTL, Handoff, configured_origin
from gateway.slash_access import policy_from_extra


async def _send_private_link(adapter, chat_id, text):
    """Bypass transcript/ledger and PTB's debug logging of API response message text."""
    bot = getattr(adapter, "_bot", None)
    if bot is None:
        raise RuntimeError("Telegram unavailable")
    async with ClientSession(timeout=ClientTimeout(total=15), trust_env=False) as client:
        async with client.post(
            "https://api.telegram.org/bot" + bot.token + "/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True,
                  "protect_content": True},
        ) as response:
            if response.status != 200:
                raise RuntimeError("Telegram delivery failed")
            # Do not parse/log the Telegram response: it repeats the capability link.


async def handle_claude_login(runner, event, args):
    source = event.source
    platform = str(getattr(source.platform, "value", source.platform))
    if (platform != "telegram" or source.chat_type not in {"dm", "private"}
            or not source.user_id or str(source.chat_id) != str(source.user_id)
            or not runner._is_user_authorized(source)):
        return "Claude login requires an authorized Telegram private chat."
    adapter = runner._intake_adapter_for(source)
    if adapter is None:
        return "Claude login requires a live Telegram connection."
    policy = policy_from_extra(adapter.config.extra, "dm")
    if not policy.is_admin(source.user_id):
        return "Claude login requires a Telegram administrator."
    if args not in {"claude", "claude cancel"}:
        return "Use /login claude or /login claude cancel. Never send codes in chat."

    # Bind config and child env at command time, before any deferred work or HTTP callback.
    with runner._profile_scope_for_source(source):
        from hermes_constants import get_hermes_home
        from hermes_cli.config_effective import load_user_config_effective
        from tools.environments.local import served_profile_child_env
        home = str(get_hermes_home())
        owner = (home, id(adapter), str(source.chat_id), str(source.user_id))
        live = getattr(runner, "_claude_login_attempt", None)
        if live is not None:
            if live.owner != owner:
                return "Another Claude login is active. Try again after it finishes."
            if args == "claude cancel":
                await close_claude_login(runner)
                return "Claude login cancelled."
            return "Claude login is already active. Use /login claude cancel to cancel it."
        if args == "claude cancel":
            return "No Claude login is active."
        try:
            settings = load_user_config_effective(fail_closed=True).get("gateway", {}).get("claude_oauth", {})
            origin = configured_origin(settings)
            port = int(settings.get("port", 8769))
            if not 1024 <= port <= 65535:
                return DISABLED
            env = served_profile_child_env(target_home=home)
        except Exception:
            return DISABLED

    import os
    if os.name != "posix":
        return "Claude login handoff currently requires a POSIX host with PTY support."
    # Never open the host's browser; only the private form displays the authorization URL.
    env["BROWSER"] = "true"
    attempt = Handoff(origin, owner)
    runner._claude_login_attempt = attempt
    task = asyncio.create_task(_run(runner, adapter, source, attempt, port, env))
    runner._claude_login_task = task
    runner._retain_background_task(task)
    return "Preparing private Claude login. Never paste the authorization code into Telegram."


async def _run(runner, adapter, source, attempt, port, env):
    notice = DISABLED
    try:
        async with asyncio.timeout(TTL):
            await attempt.start(port)
            await attempt.verify_reachable()
            attempt.process = await ClaudeLoginProcess.start(env)
            await attempt.process.wait_ready()
            await _send_private_link(adapter, source.chat_id,
                "Open this private form to authorize Claude Code and enter the code (expires within five minutes):\n"
                + attempt.origin + PATH + "/#" + attempt.token)
            result = await attempt.process.wait()
            notice = "Claude Code login completed." if result == 0 else "Claude login failed. Start again with /login claude."
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        notice = "Claude login expired. Start again with /login claude."
    except Exception:
        # Neither child output nor transport exceptions may reach logs or chat.
        notice = "Claude login unavailable. " + DISABLED
    finally:
        attempt.invalidate()
        try:
            await attempt.close()
        finally:
            if getattr(runner, "_claude_login_attempt", None) is attempt:
                runner._claude_login_attempt = None
    await runner._deliver_platform_notice(source, notice)


async def close_claude_login(runner):
    """Used by owner cancellation and gateway teardown before forgetting background tasks."""
    attempt = getattr(runner, "_claude_login_attempt", None)
    if not isinstance(attempt, Handoff):
        return
    attempt.invalidate()
    task = runner._claude_login_task
    if not task.cancelling():
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    # A task cancelled before its first instruction never enters its finally block.
    if getattr(runner, "_claude_login_attempt", None) is attempt:
        await attempt.close()
        runner._claude_login_attempt = None
