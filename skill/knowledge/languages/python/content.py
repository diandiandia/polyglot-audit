"""Substantive per-card content for the Python knowledge cards (py-01..py-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, official Python documentation).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Python section).
"""

LANGUAGE = {
    "name": "Python",
    "prefix": "py",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsafe Deserialization via pickle/marshal/shelve",
        "platform": "CPython 3.x standard library; applies on every OS and deployment target",
        "mechanism": (
            "The pickle protocol is an execution protocol, not a data format: during "
            "pickle.loads the VM in the pickle module executes opcodes such as GLOBAL and "
            "REDUCE, importing modules and calling callables named inside the byte stream. "
            "An attacker who controls the bytes therefore achieves code execution simply by "
            "encoding __reduce__ that returns (os.system, (cmd,)); no parse bug is required. "
            "marshal and shelve reuse the same object-reconstruction machinery, and "
            "yaml.load with a non-SafeLoader resolves arbitrary Python tags the same way."
        ),
        "source": (
            "Byte streams an attacker can write: HTTP request bodies, message-queue "
            "payloads, cache/queue entries shared across trust boundaries, session or "
            "cookie blobs, files downloaded from untrusted origins."
        ),
        "sink": (
            "pickle.loads / pickle.load / marshal.loads / shelve.open on attacker-"
            "influenced bytes; yaml.load without an explicit SafeLoader"
        ),
        "guards": (
            "Check whether the load site restricts reconstruction: a custom Unpickler "
            "whose find_class allows only an explicit module/class whitelist, a payload "
            "integrity check (HMAC/signature) verified BEFORE loads, or replacement by a "
            "data-only format (json). For YAML, verify the call passes yaml.SafeLoader "
            "explicitly; yaml.load without a Loader argument is not a guard."
        ),
        "not_candidate_when": (
            "The bytes are produced and consumed inside one trust domain with no network "
            "or shared-storage exposure (pure intra-process memoization), or an "
            "authenticated-encryption/HMAC envelope is verified before loads and the "
            "key is not attacker-readable, or loads runs behind a restricted Unpickler "
            "with a class whitelist that excludes all executable callables."
        ),
        "vuln": "obj = pickle.loads(untrusted_payload)",
        "safe": "obj = json.loads(untrusted_payload)",
        "signal": r"pickle\.loads\(untrusted_payload\)",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "Python documentation: pickle module security notes — https://docs.python.org/3/library/pickle.html",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.python.org/3/library/pickle.html",
    },
    {
        "num": "02",
        "title": "Code and Expression Injection via eval/exec",
        "platform": "CPython 3.x standard library; applies on every OS and deployment target",
        "mechanism": (
            "eval/exec compile the attacker-influenced string to Python bytecode and run "
            "it with the caller's namespaces; the string is code, so any statement-level "
            "capability (imports, attribute traversal, attribute assignment) is available. "
            "Passing {'__builtins__': {}} does not sandbox it: literals can reach object "
            "dunder chains (().__class__.__bases__[0].__subclasses__()) to recover "
            "dangerous types. The same class of flaw appears via str.format when the "
            "format string itself is attacker-controlled ('{0.__class__}' traverses "
            "attributes) and via templates constructed from input."
        ),
        "source": (
            "User-supplied expression strings: query parameters, JSON fields reused as "
            "formulas or rules, calculator/policy expressions, attacker-controlled "
            "format strings or template text."
        ),
        "sink": (
            "eval() / exec() / compile() on dynamic strings; __import__ and "
            "importlib.import_module with dynamic names; str.format called with an "
            "attacker-controlled format string"
        ),
        "guards": (
            "Verify the expression is parsed by ast.literal_eval (literals only, no name "
            "resolution) or matched against a strict grammar/allowlist of identifiers and "
            "operators before evaluation; verify format strings are compile-time "
            "constants with only the values dynamic; treat any eval/exec reachable from "
            "input as a candidate unless such a structural guard is present."
        ),
        "not_candidate_when": (
            "The evaluated string is a compile-time constant, the input is strictly "
            "validated to a numeric/whitelisted grammar before reaching eval, "
            "ast.literal_eval is used instead of eval, or the format string is a "
            "constant and only substitution values are dynamic."
        ),
        "vuln": "result = eval(user_expression)",
        "safe": "result = ast.literal_eval(user_expression)",
        "signal": r"eval\(user_expression\)",
        "references": [
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "CWE-95: Eval Injection — https://cwe.mitre.org/data/definitions/95.html",
            "Python documentation: ast.literal_eval — https://docs.python.org/3/library/ast.html#ast.literal_eval",
        ],
        "doc_url": "https://docs.python.org/3/library/ast.html#ast.literal_eval",
    },
    {
        "num": "03",
        "title": "Command Injection in subprocess with shell=True",
        "platform": "CPython 3.x standard library on POSIX and Windows (shell resolution differs per OS)",
        "mechanism": (
            "With shell=True the argument string is handed to /bin/sh -c (or COMSPEC on "
            "Windows), so shell metacharacters in input (';', '|', '&&', '$(...)', "
            "backquotes) terminate the intended command and start attacker-controlled "
            "ones. Even without shell=True, an attacker-supplied value that begins with "
            "'-' reaches the spawned program as an option (argument injection) unless "
            "the call is positional and guarded."
        ),
        "source": (
            "Request parameters, headers, filenames, or environment values that are "
            "interpolated or appended into a command string or argv element."
        ),
        "sink": (
            "subprocess.run/call/check_output/Popen with shell=True; os.system; os.popen"
        ),
        "guards": (
            "Prefer the argv-list form (shell=False) with the dynamic value as one "
            "element and a fixed executable path; if interpolation into a shell string "
            "is unavoidable, verify shlex.quote (not ad-hoc escaping) is applied; check "
            "for strict allowlist validation (e.g. ^[A-Za-z0-9_-]+$) before the value "
            "enters the command."
        ),
        "not_candidate_when": (
            "The command string is entirely constant, the dynamic value is passed as a "
            "single argv element to a program that accepts no options, or the value is "
            "validated against a strict allowlist grammar that excludes all shell "
            "metacharacters before use."
        ),
        "vuln": "subprocess.Popen(f\"echo {user_input}\", shell=True)",
        "safe": "subprocess.Popen([\"echo\", user_input])",
        "signal": r"subprocess\.Popen\(.*shell=True\)",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-88: Argument Injection or Modification — https://cwe.mitre.org/data/definitions/88.html",
            "Python documentation: subprocess security considerations — https://docs.python.org/3/library/subprocess.html",
        ],
        "doc_url": "https://docs.python.org/3/library/subprocess.html",
    },
    {
        "num": "04",
        "title": "Path Traversal in os.path.join and Archive Extraction",
        "platform": "CPython 3.x standard library; archive filters require Python 3.12+ (tarfile data filter)",
        "mechanism": (
            "os.path.join discards the base directory entirely when the second argument "
            "is absolute ('/etc/passwd' yields '/etc/passwd'), and keeps '..' segments "
            "otherwise, so one join call does not confine the result to the base. "
            "Archive members replicate the same flaw at extraction time: tar/zip entry "
            "names with absolute paths or '..' escape the extraction root because "
            "extractall trusts member names by default. tempfile.mktemp returns a "
            "predictable name that another process can create first (symlink race)."
        ),
        "source": (
            "Upload filenames, archive entry names, download/path parameters, or any "
            "path component taken from a request."
        ),
        "sink": (
            "os.path.join(base, attacker_path) whose result reaches open/read/write; "
            "tarfile/zipfile extractall on untrusted archives; tempfile.mktemp"
        ),
        "guards": (
            "Check for basename() stripping or normalization before join (os.path.basename "
            "or PurePath.name), and for a realpath containment check: "
            "os.path.realpath(candidate) must startswith realpath(base) + os.sep. For "
            "archives, require member-name validation or extraction with the tarfile "
            "'data' filter; for temp files require tempfile.mkstemp or TemporaryFile."
        ),
        "not_candidate_when": (
            "The path component is generated server-side (UUID/timestamp), basename is "
            "extracted and a realpath containment check rejects escapes, archive "
            "extraction uses the data filter or an equivalent member whitelist, or the "
            "temporary name comes from mkstemp/NamedTemporaryFile."
        ),
        "vuln": "full_path = os.path.join('/app/uploads', filename)",
        "safe": "full_path = os.path.join('/app/uploads', os.path.basename(filename))",
        "signal": r"os\.path\.join\('/app/uploads',\s*filename\)",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "CWE-59: Improper Link Resolution Before File Access — https://cwe.mitre.org/data/definitions/59.html",
            "Python documentation: os.path.join semantics — https://docs.python.org/3/library/os.path.html#os.path.join",
            "Python documentation: tarfile extraction filters — https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter",
        ],
        "doc_url": "https://docs.python.org/3/library/os.path.html#os.path.join",
    },
    {
        "num": "05",
        "title": "SQL Injection in DB-API via f-string Formatting",
        "platform": "CPython 3.x with any PEP 249 DB-API driver (sqlite3, psycopg, mysqlclient, etc.)",
        "mechanism": (
            "PEP 249 defines parameter binding (placeholder + params), but Python string "
            "formatting (f-string, %, .format, +) composes the SQL text before the "
            "driver parses it, so a value containing a quote or SQL syntax is read as "
            "statement structure, not data. Parameter binding sends values out-of-band "
            "so they can never change the parse; format strings can also smuggle multi-"
            "statement payloads where the driver permits them."
        ),
        "source": (
            "Request parameters, JSON fields, sort/filter names from the client that "
            "are interpolated into the statement text."
        ),
        "sink": (
            "cursor.execute / cursor.executemany / connection cursor text built with "
            "f-string, %, .format, or concatenation"
        ),
        "guards": (
            "Verify execute is called with two arguments (sql with placeholder, params "
            "sequence) rather than one pre-formatted string; for identifiers that cannot "
            "be parameterized (table/column names, ORDER BY direction) require an "
            "allowlist dictionary mapping client keys to fixed SQL fragments."
        ),
        "not_candidate_when": (
            "Values are bound through the driver's parameter mechanism, or the only "
            "interpolated parts come from a fixed server-side allowlist (never from "
            "raw client text)."
        ),
        "vuln": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
        "safe": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "signal": r"cursor\.execute\(f\"SELECT.*user_id",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements in SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "PEP 249: Python Database API Specification (parameter binding) — https://peps.python.org/pep-0249/",
            "OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://peps.python.org/pep-0249/",
    },
    {
        "num": "06",
        "title": "XML Entity Expansion, External Entities, and Regex Backtracking",
        "platform": "CPython 3.x standard library; xml.etree is vulnerable to expansion but raises on external entity retrieval, unlike xml.sax and xml.dom",
        "mechanism": (
            "Entity declarations in a DTD let a small document reference itself "
            "recursively: xml.etree and xml.sax still perform recursive entity expansion "
            "(billion-laughs) and quadratic blowup, so a few hundred bytes expand to "
            "gigabytes in memory. xml.sax and xml.dom additionally resolve external "
            "entities to file:// or http:// targets, giving local file read and SSRF. "
            "The same shape of unbounded work exists in re: a crafted input against a "
            "vulnerable pattern drives exponential backtracking on one CPU core with no "
            "timeout mechanism."
        ),
        "source": (
            "XML documents uploaded or posted by clients; regex patterns and subject "
            "strings supplied by users."
        ),
        "sink": (
            "xml.etree.ElementTree.fromstring/parse, xml.sax.parse/parseString, "
            "xml.dom.minidom.parseString on untrusted documents; re.match/search with "
            "attacker-influenced pattern or unbounded subject"
        ),
        "guards": (
            "Verify parsing goes through defusedxml (or an explicit parser with DTD and "
            "entity processing disabled) rather than the stdlib defaults; for regex, "
            "verify the pattern is a compile-time constant, subject length is capped, "
            "and the pattern has no nested quantifiers over overlapping alternations."
        ),
        "not_candidate_when": (
            "XML comes from a trusted internal producer and DTDs are absent by "
            "construction, or defusedxml is used; the regex pattern is constant with "
            "no nested quantifiers and the input length is bounded to a few kilobytes."
        ),
        "vuln": "tree = xml.etree.ElementTree.fromstring(xml_payload)",
        "safe": "import defusedxml.ElementTree as ET; tree = ET.fromstring(xml_payload)",
        "signal": r"xml\.etree\.ElementTree\.fromstring\(",
        "references": [
            "CWE-776: Improper Restriction of Recursive Entity References in DTDs — https://cwe.mitre.org/data/definitions/776.html",
            "CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html",
            "CWE-1333: Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html",
            "Python documentation: XML vulnerabilities — https://docs.python.org/3/library/xml.html#xml-vulnerabilities",
        ],
        "doc_url": "https://docs.python.org/3/library/xml.html#xml-vulnerabilities",
    },
    {
        "num": "07",
        "title": "Dynamic Typing and Truthiness Traps on Security Checks",
        "platform": "CPython 3.x; assert removal occurs whenever the interpreter runs with -O or PYTHONOPTIMIZE set",
        "mechanism": (
            "Python semantics silently weaken several guard idioms. assert is a "
            "statement the compiler deletes under -O, so a permission check written as "
            "assert disappears entirely in optimized deployments. Truthiness coerces "
            "None, 0, '', [] and {} to False, so 'if not user' style checks conflate "
            "'absent' with 'present but empty' and can pass or fail authorization "
            "depending on payload shape. == calls __eq__, which attacker-influenced "
            "objects can override; a mutable default argument (def check(acl=[])) "
            "shares one object across calls, letting an earlier request's state "
            "satisfy a later request's check."
        ),
        "source": (
            "Deserialized request objects, JSON bodies whose field types the server "
            "does not pin (string vs array vs null), and values crossing call "
            "boundaries via mutable default arguments."
        ),
        "sink": (
            "assert used as an authorization/authentication gate; if/while truthiness "
            "checks over untrusted collections or IDs on security paths; mutable "
            "default arguments holding security state"
        ),
        "guards": (
            "Check that authorization outcomes are enforced with explicit comparisons "
            "(is None, isinstance, ==/is against an exact expected value) and raised as "
            "exceptions rather than assert; check that JSON fields are type-validated "
            "before truthiness tests; check default arguments use None sentinels."
        ),
        "not_candidate_when": (
            "assert guards only internal invariants unreachable from input and "
            "deployment never runs with -O, the truthiness check is on a value "
            "provably non-empty by construction, or defaults are immutable/None-"
            "sentinel and state is per-call."
        ),
        "vuln": "assert is_admin(user), 'Unauthorized'",
        "safe": "if not is_admin(user): raise PermissionError('Unauthorized')",
        "signal": r"assert\s+is_admin\(user\)",
        "references": [
            "CWE-617: Reachable Assertion — https://cwe.mitre.org/data/definitions/617.html",
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
            "Python documentation: assert statements and -O — https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement",
        ],
        "doc_url": "https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement",
    },
    {
        "num": "08",
        "title": "SSRF and Protocol/Redirect Handling in urllib",
        "platform": "CPython 3.x standard library (urllib.request, urllib.parse, ssl); applies to server-side outbound fetchers",
        "mechanism": (
            "urlopen accepts whatever scheme the caller passes, so an attacker-supplied "
            "URL can select file://, ftp://, or (on builds still exposing it) other "
            "handlers, and urllib follows redirect chains blindly, allowing an "
            "approved-https URL to 30x into an internal address or a disallowed scheme. "
            "Building an ssl.SSLContext with CERT_NONE / check_hostname=False silently "
            "removes server authentication. urllib.parse also normalizes differently "
            "from browsers and origin servers (backslashes, embedded whitespace, "
            "percent-encoding), so an allowlist decided on parsed components can be "
            "evaded by a canonicalization mismatch."
        ),
        "source": (
            "URLs, host names, or path strings taken from requests, webhooks, import "
            "features, or link-preview fetchers."
        ),
        "sink": (
            "urllib.request.urlopen / Request.build_opener fetch of an attacker-"
            "influenced URL; ssl contexts created with CERT_NONE or "
            "check_hostname=False; security decisions based on urllib.parse output "
            "without canonicalization"
        ),
        "guards": (
            "Check for a scheme allowlist (https only) plus a host allowlist resolved "
            "against a DNS-rebinding-safe IP check before the request; check redirects "
            "are disabled or re-validated by a custom HTTPRedirectHandler that "
            "re-applies the allowlist per hop; check the default SSL context (no "
            "CERT_NONE) is kept."
        ),
        "not_candidate_when": (
            "The URL host is matched against a fixed allowlist after canonicalization "
            "and IP resolution, redirects are disabled or re-validated at every hop, "
            "and certificate verification remains at defaults; or the fetched URL is "
            "constructed entirely from server-side constants."
        ),
        "vuln": "resp = urllib.request.urlopen(user_url)",
        "safe": "if not user_url.startswith(('https://', 'http://')): raise ValueError(); resp = urllib.request.urlopen(user_url)",
        "signal": r"urllib\.request\.urlopen\(user_url\)",
        "references": [
            "CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html",
            "CWE-295: Improper Certificate Validation — https://cwe.mitre.org/data/definitions/295.html",
            "CWE-601: URL Redirection to Untrusted Site — https://cwe.mitre.org/data/definitions/601.html",
            "Python documentation: urllib.request — https://docs.python.org/3/library/urllib.request.html",
        ],
        "doc_url": "https://docs.python.org/3/library/urllib.request.html",
    },
    {
        "num": "09",
        "title": "Cryptographic Misuse: Weak PRNG, Fast Hashes, Non-constant-time Compare",
        "platform": "CPython 3.x standard library (random, hashlib, hmac, secrets)",
        "mechanism": (
            "random seeds a Mersenne Twister from a 32-bit-derived state and emits "
            "enough state bits through its outputs to reconstruct the generator, so "
            "tokens, reset codes, or keys drawn from random are predictable from a few "
            "observed values. md5/sha1 applied directly to passwords give fast, "
            "unsalted digests that tolerate massive offline guessing; hmac.compare_digest "
            "exists precisely because '==' on MACs short-circuits and leaks a timing "
            "oracle that recovers the tag byte by byte."
        ),
        "source": (
            "The security value itself: session tokens, password reset codes, API "
            "keys, MAC tags, password digests chosen by the developer's library call."
        ),
        "sink": (
            "random.choice/random.random/randint feeding tokens or keys; hashlib.md5/"
            "sha1 used for password storage; == / != comparisons of digests or MAC tags"
        ),
        "guards": (
            "Require secrets.token_hex/token_bytes for any security value; require "
            "hmac.compare_digest for authenticator comparisons; require a salted, "
            "deliberately slow KDF (hashlib.pbkdf2_hmac with sufficient iterations, or "
            "an Argon2/bcrypt implementation) for password storage."
        ),
        "not_candidate_when": (
            "random is used only for non-security purposes (sampling, shuffling, "
            "simulations), the fast hash digests untrusted content for integrity or "
            "deduplication rather than authentication, or the compared digests come "
            "from hmac.compare_digest already."
        ),
        "vuln": "token = ''.join(random.choice(chars) for _ in range(32))",
        "safe": "token = secrets.token_hex(32)",
        "signal": r"random\.choice\(chars\)",
        "references": [
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "PEP 506: Designing secrets-aware standard library modules — https://peps.python.org/pep-0506/",
            "Python documentation: secrets module — https://docs.python.org/3/library/secrets.html",
        ],
        "doc_url": "https://docs.python.org/3/library/secrets.html",
    },
    {
        "num": "10",
        "title": "Native Extension Buffers and Unbounded Resource Processing",
        "platform": "CPython 3.x standard library (ctypes, struct, io, zlib); int/str conversion limit requires Python 3.11+ (sys.set_int_max_str_digits)",
        "mechanism": (
            "ctypes and struct trust caller-declared sizes: a length taken from input "
            "drives ctypes.memmove / create_string_buffer / a struct.unpack format, so "
            "a mismatch between the declared and real buffer size writes past the "
            "allocation or misreads adjacent memory. io's read() with no argument "
            "loads the entire stream into memory, zlib/gzip decompress output without "
            "an output cap turns a small compressed upload into gigabytes (decompression "
            "bomb), and int<->str conversion is quadratic; before Python 3.11's "
            "conversion limit an attacker-supplied huge integer makes serialization "
            "burn CPU indefinitely."
        ),
        "source": (
            "Content-Length or declared sizes from protocol headers, compressed upload "
            "bodies, serialized integers, and binary payloads fed to struct/ctypes."
        ),
        "sink": (
            "ctypes memory APIs sized from input; struct.unpack with input-derived "
            "formats; file/socket .read() with no cap; zlib/bz2/lzma decompress without "
            "output limits; int(str)/str(int) on attacker-sized values"
        ),
        "guards": (
            "Check every input-derived length against a fixed constant before use; "
            "check reads use read(n) with n bounded; check decompression is incremental "
            "with an output-byte budget; check the interpreter enforces "
            "sys.set_int_max_str_digits (3.11+) where attacker integers are converted."
        ),
        "not_candidate_when": (
            "The transport already caps body size below the guard threshold and that "
            "cap is enforced before parsing, buffers are sized from compile-time "
            "constants, or decompression output is budgeted."
        ),
        "vuln": "data = request.raw.read()",
        "safe": "data = request.raw.read(1024 * 1024)",
        "signal": r"request\.raw\.read\(\)",
        "references": [
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "CWE-409: Improper Handling of Highly Compressed Data (Data Amplification) — https://cwe.mitre.org/data/definitions/409.html",
            "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer — https://cwe.mitre.org/data/definitions/119.html",
            "Python documentation: integer string conversion length limitation — https://docs.python.org/3/library/stdtypes.html#int-max-str-digits",
        ],
        "doc_url": "https://docs.python.org/3/library/stdtypes.html#int-max-str-digits",
    },
]
