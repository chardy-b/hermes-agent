import { afterEach, describe, expect, it, vi } from 'vitest'

import { setApiRequestConnection, setApiRequestProfile } from '@/api/client'
import type { McpOAuthFlow } from '@/api/mcp'
import { requestGatewayForAgent } from '@/store/gateway'

import { completeMcpDesktopOAuth, McpOAuthCancelled } from './mcp-dashboard-oauth'

vi.mock('@/store/gateway', () => ({ requestGatewayForAgent: vi.fn() }))

const redirectUri = 'http://127.0.0.1:49152/callback'
const authUrl = `https://idp.example/authorize?state=expected&redirect_uri=${encodeURIComponent(redirectUri)}`
const started = { ok: true, session_id: 'flow-1', auth_url: authUrl, flow: 'pkce' }
const tools = [{ name: 'list_reports', description: 'List reports' }]

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void

  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })

  return { promise, resolve, reject }
}

function harness() {
  const callback = deferred<{ code: string | null; state: string | null; error: string | null }>()

  const bridge = {
    listen: vi.fn().mockResolvedValue({ id: 'listener-1', redirectUri }),
    wait: vi.fn(() => callback.promise),
    cancel: vi.fn(async () => {
      callback.resolve({ code: null, state: null, error: 'cancelled' })

      return true
    })
  }

  const api = vi.fn().mockRejectedValue(new Error('Desktop OAuth must not use the remote REST callback'))

  const openExternal = vi.fn(async () => {
    callback.resolve({ code: 'code-1', state: 'expected', error: null })
  })

  Object.defineProperty(window, 'hermesDesktop', { configurable: true, value: { mcpOauth: bridge, api, openExternal } })
  let relayed = false
  const rpc = vi.mocked(requestGatewayForAgent)
  rpc.mockImplementation(async (_connection, _profile, method) => {
    if (method.endsWith('.start')) {
      return started
    }

    if (method.endsWith('.callback')) {
      relayed = true

      return { ok: true }
    }

    if (method.endsWith('.cancel')) {
      return { ok: true, status: 'error' }
    }

    return { ok: true, status: relayed ? 'approved' : 'pending', tools }
  })

  return { bridge, callback, api, openExternal, rpc }
}

afterEach(() => {
  vi.resetAllMocks()
  setApiRequestConnection(null)
  setApiRequestProfile(null)
  delete document.documentElement.dataset.hermesDesktopHost
})

describe('Desktop MCP client callback lifecycle', () => {
  it.each(['local', 'remote-gateway'])(
    'relays through the native listener and keeps the %s owner after foreground changes',
    async connectionId => {
      const { bridge, api, openExternal, rpc } = harness()
      setApiRequestConnection(connectionId)
      setApiRequestProfile('origin-profile')
      const callbackResult = { code: 'code-1', state: 'expected', error: null }
      bridge.wait.mockResolvedValue(callbackResult)
      openExternal.mockImplementation(async () => {
        setApiRequestConnection('other-gateway')
        setApiRequestProfile('other-profile')
      })
      const result = await completeMcpDesktopOAuth({ serverName: 'reports', sleep: async () => {} })
      expect(result).toMatchObject({ status: 'approved', tools })
      expect(rpc).toHaveBeenCalledWith(
        connectionId,
        'origin-profile',
        'mcp.servers.oauth.start',
        { name: 'reports', client_redirect_uri: redirectUri },
        60_000
      )
      expect(rpc).toHaveBeenCalledWith(
        connectionId,
        'origin-profile',
        'mcp.servers.oauth.callback',
        { name: 'reports', session_id: 'flow-1', ...callbackResult },
        60_000
      )
      expect(rpc.mock.calls.every(call => call[0] === connectionId && call[1] === 'origin-profile')).toBe(true)
      expect(bridge.cancel).toHaveBeenCalledWith('listener-1')
      expect(api).not.toHaveBeenCalled()
    }
  )

  it.each(['cancel', 'legacy'])('cleans up the owner before opening an unsafe authorization on %s', async outcome => {
    const { rpc, bridge, openExternal, api } = harness()
    setApiRequestConnection('remote-gateway')
    setApiRequestProfile('origin-profile')
    let cancelled = false
    rpc.mockImplementation(async (_connection, _profile, method) => {
      if (method.endsWith('.start')) {
        setApiRequestConnection('other-gateway')
        setApiRequestProfile('other-profile')
        cancelled = outcome === 'cancel'

        return outcome === 'legacy'
          ? { ...started, auth_url: 'https://idp.example/authorize?redirect_uri=http://remote/callback' }
          : started
      }

      return { ok: true }
    })
    const action = completeMcpDesktopOAuth({ serverName: 'reports', cancelled: () => cancelled })

    if (outcome === 'cancel') {
      await expect(action).rejects.toBeInstanceOf(McpOAuthCancelled)
    } else {
      await expect(action).rejects.toThrow('Update the Hermes backend')
    }

    expect(openExternal).not.toHaveBeenCalled()
    expect(bridge.cancel).toHaveBeenCalledWith('listener-1')
    expect(rpc).toHaveBeenCalledWith(
      'remote-gateway',
      'origin-profile',
      'mcp.servers.oauth.cancel',
      { name: 'reports', session_id: 'flow-1' },
      60_000
    )
    expect(rpc.mock.calls.every(call => call[0] === 'remote-gateway' && call[1] === 'origin-profile')).toBe(true)
    expect(api).not.toHaveBeenCalled()
  })
})

function browserPopup() {
  const popupDocument = document.implementation.createHTMLDocument('OAuth')
  const replace = vi.fn()
  const close = vi.fn()
  const popup = {
    closed: false,
    close,
    document: popupDocument,
    location: { replace },
    opener: window
  } as unknown as Window

  return { close, popup, popupDocument, replace }
}

describe('browser-hosted MCP OAuth lifecycle', () => {
  it('reserves and hardens a blank popup synchronously, then keeps the captured scope through completion', async () => {
    document.documentElement.dataset.hermesDesktopHost = 'browser'
    const { popup, popupDocument, replace } = browserPopup()
    const open = vi.spyOn(window, 'open').mockReturnValue(popup)
    const post = deferred<McpOAuthFlow>()
    const api = vi.fn(async request => {
      if (request.method === 'POST') {
        return post.promise
      }

      return { flow_id: 'flow/one', server_name: 'reports/quarterly', status: 'approved', authorization_url: authUrl, error: null, tools }
    })
    Object.defineProperty(window, 'hermesDesktop', { configurable: true, value: { api } })

    const action = completeMcpDesktopOAuth({
      serverName: 'reports/quarterly',
      profile: { connectionId: 'cloud-one', profile: 'finance' },
      sleep: async () => {}
    })

    expect(open).toHaveBeenCalledWith('', '_blank')
    expect(open.mock.calls[0]).toHaveLength(2)
    expect(popup.opener).toBeNull()
    expect(popupDocument.head.querySelector('meta[name="referrer"]')?.getAttribute('content')).toBe('no-referrer')
    expect(api).toHaveBeenCalledTimes(1)
    expect(replace).not.toHaveBeenCalled()

    post.resolve({ ...started, flow_id: 'flow/one', server_name: 'reports/quarterly', status: 'authorization_required', authorization_url: authUrl, error: null })
    await expect(action).resolves.toMatchObject({ status: 'approved', tools })
    expect(replace).toHaveBeenCalledWith(authUrl)
    expect(api).toHaveBeenNthCalledWith(1, {
      connectionId: 'cloud-one', profile: 'finance', priority: 'foreground',
      path: '/api/mcp/servers/reports%2Fquarterly/auth', method: 'POST', timeoutMs: 60_000
    })
    expect(api).toHaveBeenNthCalledWith(2, {
      connectionId: 'cloud-one', profile: 'finance', priority: 'foreground',
      path: '/api/mcp/oauth/flows/flow%2Fone', timeoutMs: 60_000
    })
  })

  it('treats a null open result as blocked without retrying with noopener features', async () => {
    document.documentElement.dataset.hermesDesktopHost = 'browser'
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    const api = vi.fn()
    Object.defineProperty(window, 'hermesDesktop', { configurable: true, value: { api } })

    await expect(completeMcpDesktopOAuth({ serverName: 'reports' })).rejects.toThrow('allow popups')
    expect(open).toHaveBeenCalledOnce()
    expect(open.mock.calls[0]).toHaveLength(2)
    expect(api).not.toHaveBeenCalled()
  })

  it.each([
    ['cancelled after start', authUrl, true, McpOAuthCancelled],
    ['javascript authorization URL', 'javascript:document.cookie', false, Error],
    ['data authorization URL', 'data:text/html,credential', false, Error]
  ])('closes and deletes the flow when %s', async (_case, authorizationUrl, cancelAfterStart, expectedError) => {
    document.documentElement.dataset.hermesDesktopHost = 'browser'
    const { close, popup, replace } = browserPopup()
    vi.spyOn(window, 'open').mockReturnValue(popup)
    let cancelled = false
    const api = vi.fn(async request => {
      if (request.method === 'POST') {
        cancelled = cancelAfterStart

        return { flow_id: 'flow unsafe', server_name: 'reports', status: 'authorization_required', authorization_url: authorizationUrl, error: null }
      }

      return { ok: true }
    })
    Object.defineProperty(window, 'hermesDesktop', { configurable: true, value: { api } })

    await expect(completeMcpDesktopOAuth({ serverName: 'reports', cancelled: () => cancelled })).rejects.toBeInstanceOf(expectedError)
    expect(replace).not.toHaveBeenCalled()
    expect(close).toHaveBeenCalledOnce()
    expect(api).toHaveBeenLastCalledWith({
      path: '/api/mcp/oauth/flows/flow%20unsafe', method: 'DELETE', timeoutMs: 60_000
    })
  })
})
