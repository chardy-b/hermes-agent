# Claude Code login from Telegram (isolated fork)

Send `/login claude` in an authorized private Telegram chat. Hermes starts exactly
`claude auth login` in a private PTY, delivers a protected link to a masked HTTPS form,
and discards the CLI output. The form links to Claude's PKCE authorization page. Complete
that page, then paste its full returned `code#state` value into the form. The form requires one nonempty `code#state` pair; its state must exactly match the single
state parameter in the owned CLI authorization URL. Missing, duplicate, or mismatched
states are rejected before any PTY write. Never send the code to the bot.
`/login claude cancel` invalidates the link and kills the owned login process. The whole
attempt expires after five minutes; a restart also invalidates it. Login success is
reported only when the CLI exits successfully, not merely when the code is submitted.

This does **not** attach to an arbitrary terminal process or intercept a model-launched
`claude auth login`. Start through the slash command so its output never reaches tools,
model history, sessions, process checkpoints, or completion watchers. Existing local masked
prompts and desktop secret RPCs cannot safely collect Telegram text and are not reused as
an unmasked fallback. The approval-explanation feature is unchanged.

## Installation status and setup

This worktree has Claude Code 2.1.266 available at `/home/hermes/.local/bin/claude`.
A local PTY probe of that installed CLI observed an OSC 8 terminal hyperlink to
`https://claude.com/cai/oauth/authorize`, with `response_type=code`, S256 PKCE, and a state
parameter. The repaired parser accepted the real output. The probe used temporary Claude
configuration, suppressed browser opening, submitted no code, and terminated/reaped the CLI.
This validates URL extraction only: no authorization page, returned code, token exchange,
or successful account login was validated. Automated tests use synthetic codes and a fake
CLI over a real PTY; their external HTTPS/Telegram transports are substituted.

No reverse proxy or public HTTPS endpoint has been provisioned or tested live, and no
phone/Telegram end-to-end login has been validated. No live configuration or secrets were changed. The feature defaults to
**disabled**. Run this fork's gateway to use it; another checkout's running gateway will not
load these changes. Do not run two gateways with the same Telegram bot token.

Configure these non-secret settings in the serving profile using the normal config CLI:

```sh
hermes config set gateway.claude_oauth.public_url https://login.example.org
hermes config set gateway.claude_oauth.port 8769
```

Use an operator-controlled dedicated HTTPS origin (no other apps/service workers on it), a
valid publicly trusted certificate, and a reverse proxy on the same host. Forward only
`/claude-oauth/` to `http://127.0.0.1:8769`. The listener exists only during a login attempt.
The dashboard runs in another process, so mounting there would require a new secret IPC
bridge; this implementation instead uses a small ephemeral gateway-owned listener behind
your existing TLS service. It is never advertised as a localhost URL.

Example nginx location inside the dedicated TLS virtual host:

```nginx
location ^~ /claude-oauth/ {
    proxy_pass http://127.0.0.1:8769;
    proxy_set_header Host $host;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    client_max_body_size 2k;
    access_log off;
}
location / { return 404; }
```

Disable request-body/header capture, tracing/APM, WAF payload retention, and debug logs at
**every** ingress layer. No request mirroring or body-to-disk buffering. Preserve Origin,
Authorization and X-CSRF-Token headers. Do not add third-party scripts, analytics, caching,
or redirects. Keep the backend bound to loopback; do not publish its HTTP port. Test the
HTTPS origin from the actual phone/network. A same-listener, certificate-verified challenge
probe is required before the CLI starts or a link is sent; this confirms server reachability,
not arbitrary mobile-network routing or correct forwarding of every form route. Failed
probes give setup instructions, never a link. Preserve paths without rewriting: the listener
serves GET `/claude-oauth/`, `/claude-oauth/form.js`, `/claude-oauth/health`, and POST
`/claude-oauth/inspect`, `/claude-oauth/code`. Keep this prefix separate from dashboard/API
routes. The health check requires an ephemeral probe header; it does not accept login codes.

## Security boundary and limitations

The 256-bit capability is delivered only to the requesting private Telegram identity and
bound in memory to its profile, receiving adapter, chat, user, and exact owned PTY. Browser
possession is the authorization: sharing the link grants access until expiry. This is not
Telegram browser identity verification. Protected Telegram messages discourage forwarding
but cannot prevent screenshots/copying or a compromised Telegram account. The browser removes
the fragment from its history immediately, keeps credentials in memory, uses a password input,
and sends the code via a bounded POST. Origin checks, an independent CSRF token, CSP,
no-referrer/no-store headers, and an atomic single claim reject cross-site and replay requests.
No URL carries the code. The server never persists the capability or code. Python/browser
memory is not guaranteed to be zeroized; disable host core dumps/swap capture as appropriate.

Only one login can run per gateway process: simultaneous identities cannot replace, cancel,
or submit to another identity's process. Claude's login credentials belong to the gateway's
OS account (and its Claude configuration), not to the Telegram conversation. Operators of
shared gateways must configure Telegram `allow_admin_from` and use separate OS accounts for
separate Claude accounts. Normal gateway user authorization and admin policy both apply.
Claude itself persists its **resulting account credentials** as part of normal login; Hermes
never saves the pasted authorization code or edits configuration secrets. The installed
Claude executable and the host/proxy/browser are trusted parts of this boundary. External
instrumentation or a modified CLI that records stdin is outside Hermes's control.

Requires the Hermes messaging dependencies (including aiohttp). POSIX only for now. No automatic interception of model-run terminal login, no arbitrary
secret-to-process API, and no fallback to asking for codes in chat. Authenticate before
starting Claude work. The manual code flow is described by
[Anthropic's authentication troubleshooting guide](https://support.claude.com/en/articles/14552646-troubleshoot-claude-code-installation-and-authentication).
