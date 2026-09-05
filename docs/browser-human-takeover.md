# Secure browser human takeover

Browser takeover transfers one existing Camofox browser session from the agent to an authenticated human and then back to the agent. It is opt-in. noVNC is only the viewer transport; the coordinator lease and edge claim authorize access.

## Threat model and invariants

The protected assets are browser credentials, cookies, storage, page content, browser-control transports, and the ability to send browser input. Assume a takeover URL can be copied and that the viewer transport is not trustworthy enough to authorize itself.

The implementation therefore:

- binds the Hermes API listener, Camofox, VNC, and noVNC endpoints to literal loopback addresses;
- creates a single-use, short-lived edge claim for one exact principal, profile, Hermes session, browser profile, browser session, and transport family;
- accepts only the configured HTTPS public Origin;
- never publishes raw CDP, VNC, noVNC, cookie, storage, or provider-session values;
- allows only one live viewer connection per lease and bounds authenticated reconnect attempts;
- revokes edge access before returning browser ownership to the agent;
- reports observed state without claiming that CAPTCHA, login, or consent succeeded;
- invalidates outstanding claims and viewer connections during gateway shutdown.

A reverse proxy, noVNC password, or Tailscale identity does not replace the coordinator lease.

## Install the optional dependency

From a reviewed checkout:

```bash
scripts/install.sh --ensure browser-takeover
```

This uses the existing hardened browser installer: the pinned Camofox package is installed with npm lifecycle scripts disabled and a bounded timeout, then Node.js, npm, and the global package manifest are validated. `hermes doctor` performs the separate live browser/display and VNC/noVNC health check after the operator starts the configured Camofox service. Default Hermes installation does not enable takeover.

## Configure non-secret settings

Use `~/.hermes/config.yaml` for endpoints and policy. Keep API and Camofox credentials in Hermes secret handling or the service environment; never place them in this file or a command argument.

```yaml
browser:
  camofox:
    url: http://127.0.0.1:9377
    managed_persistence: true

gateway:
  platforms:
    api_server:
      enabled: true
      extra:
        host: 127.0.0.1
        port: 8642
        browser_takeover:
          enabled: true
          adapter: camofox-vnc
          public_origin: https://hermes.example.net
          claim_ttl_seconds: 300
```

Set `API_SERVER_KEY` and, when the Camofox service requires it, `CAMOFOX_API_KEY` through the normal Hermes secret mechanism. `CAMOFOX_URL` remains a legacy fallback; `browser.camofox.url` is preferred because it is not a secret.

The public origin must be exactly one HTTPS origin: no path, query, fragment, embedded username, or embedded password.

## Publish through a trusted edge

Keep Hermes on loopback and publish only its authenticated HTTP edge.

For tailnet-only access, configure Tailscale Serve to proxy the local API port and set `public_origin` to the resulting HTTPS tailnet hostname. Verify the generated Serve configuration with `tailscale serve status`. Do not publish the Camofox, VNC, noVNC, or CDP ports.

For an authenticated reverse proxy:

1. Terminate TLS at the proxy.
2. Require the intended user or device authentication at the proxy.
3. Forward to `127.0.0.1:8642` only.
4. Preserve the exact `Origin` header and WebSocket upgrade headers.
5. Do not expose any private browser/viewer port.
6. Set `public_origin` to the exact external HTTPS origin.

Run `hermes doctor` after configuration. The Browser Takeover section validates adapter health, browser/display continuity, loopback binding, TLS origin, and dependencies without printing endpoints or secrets.

## Operator flow

1. The agent encounters a task that needs human verification and invokes `browser_human_assist` with an allowlisted reason category.
2. Hermes sends the private takeover prompt. Open only the link from the expected conversation.
3. Finish the human-only interaction. Select **Done** on the page or reply exactly `Done` in the same authenticated session.
4. To abandon the handoff, reply exactly `Cancel` in that session.
5. Hermes revokes viewer access first, observes only content-free browser lifecycle state, and then allows the agent to re-check the page.

Do not paste challenge text, cookies, credentials, or browser storage into chat.

## Troubleshooting

- `Browser takeover adapter: unavailable or unsupported`: verify Camofox is running and the configured adapter is `camofox-vnc`.
- `Browser/display continuity: failed`: verify the Camofox health response advertises a loopback viewer and that the original managed task/profile is still active.
- `listener: must bind to loopback`: set the API server host to `127.0.0.1` or `::1`; keep remote exposure at the authenticated proxy.
- `TLS origin required`: use the exact external HTTPS origin, without a path or credentials.
- `dependencies`: run `scripts/install.sh --ensure browser-takeover`, then rerun `hermes doctor`.
- A link that is expired, canceled, already claimed, from the wrong Origin, or from another profile/session must be rejected. Request a new handoff rather than reusing it.
- If the browser was lost, start a new browser session. Do not treat the terminal `browser_lost` report as a successful return.

## Disable and roll back

1. Set `browser_takeover.enabled: false` or remove the block.
2. Restart the gateway. Shutdown invalidates in-memory claims and closes registered viewer connections.
3. Run `hermes doctor` and confirm takeover is disabled.
4. If the optional provider is no longer needed, remove `@askjo/camofox-browser` from the Hermes-local npm prefix. Preserve managed browser profiles unless the operator explicitly intends to erase saved browser state.

Disabling takeover does not require exposing or deleting credentials. Rotate API/Camofox credentials only when compromise is suspected.

## Validation boundary

Unit and in-process integration tests cover exact scope, claims, Origin checks, lifecycle races, reconnect bounds, browser loss, structured delivery, and shutdown invalidation. A fresh-host remote acceptance test still requires an isolated host with a real Camofox/VNC/noVNC stack and a real Tailscale or authenticated reverse-proxy route. Do not claim that gate from mocked health checks.
