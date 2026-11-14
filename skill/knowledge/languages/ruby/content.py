"""Substantive per-card content for the Ruby knowledge cards (ruby-01..ruby-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, official Ruby stdlib documentation).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Ruby section).
"""

LANGUAGE = {
    "name": "Ruby",
    "prefix": "ruby",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsafe Deserialization via Marshal.load",
        "platform": "Ruby 3.x standard library (Marshal, Psych YAML); on Psych 4.x (bundled since Ruby 3.1) YAML.load is an alias for safe_load, while Psych 3.x (Ruby 2.7/3.0) YAML.load permits arbitrary object instantiation",
        "mechanism": (
            "Marshal.load rebuilds the object graph named inside the byte stream, "
            "instantiating user-defined classes without running their initialize and "
            "then firing serialization hooks along the way, so attacker-chosen "
            "instances reach dangerous states and methods — the stdlib documentation "
            "itself warns Marshal data must never come from untrusted input. "
            "Psych's YAML.load on Psych 3.x resolves tags to arbitrary Ruby classes, "
            "giving the same primitive, while YAML.safe_load restricts resolution to "
            "permitted classes. The JSON gem's create_additions option likewise "
            "re-instantiates classes from json_class tags in the document."
        ),
        "source": (
            "Session/state cookies, queued or cached payloads, and any byte stream an "
            "attacker can write that reaches a load call."
        ),
        "sink": (
            "Marshal.load on untrusted bytes; YAML.load (Psych 3.x) without "
            "safe_load/permitted_classes; JSON.parse with create_additions: true"
        ),
        "guards": (
            "Check that untrusted state uses a data-only format (JSON without "
            "create_additions) or YAML.safe_load with an explicit permitted_classes "
            "list; check that a signature/HMAC over the payload is verified before "
            "any load call and the key is not attacker-readable."
        ),
        "not_candidate_when": (
            "The bytes are produced and consumed within one trust domain with no "
            "network or shared-storage exposure, an HMAC/signature envelope is "
            "verified before loading, or safe_load permits only the expected "
            "primitive types so no attacker-chosen class can be instantiated."
        ),
        "vuln": "data = Marshal.load(params[:state])",
        "safe": "data = JSON.parse(params[:state])",
        "signal": r"Marshal\.load\(params\[:state\]\)",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "Ruby stdlib documentation: Marshal — https://docs.ruby-lang.org/en/3.2/Marshal.html",
            "Ruby stdlib documentation: Psych — https://docs.ruby-lang.org/en/3.2/Psych.html",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/Marshal.html",
    },
    {
        "num": "02",
        "title": "Dynamic Code Execution and Metaprogramming via send",
        "platform": "Ruby 3.x standard library; MRI",
        "mechanism": (
            "eval compiles the string as Ruby source in the current binding, and "
            "instance_eval runs it with self bound to the receiver, exposing private "
            "state and instance variables of that object to the evaluated text. "
            "send and public_send invoke any method chosen by name — public_send "
            "excludes private methods but every public destructive method "
            "(destroy, update, execute) remains reachable — while class_eval can "
            "define or overwrite methods on a class and const_get resolves "
            "attacker-chosen names to constants, including class objects. Building "
            "an ERB template from input is the same primitive one level up: the "
            "template's <%= %> sections are Ruby code that ERB executes during "
            "render."
        ),
        "source": (
            "Request parameters selecting action/method names, template text, or "
            "constant/class names used in dispatch."
        ),
        "sink": (
            "eval / instance_eval / class_eval on dynamic strings; send / "
            "public_send / const_get with input-derived names; ERB.new("
            "attacker_text).result"
        ),
        "guards": (
            "Require dispatch through a fixed allowlist hash that maps input keys to "
            "constant symbols or callables before any send; require templates to be "
            "application-owned files with only data dynamic; require eval to see "
            "compile-time constant strings only."
        ),
        "not_candidate_when": (
            "The dispatched name is matched against a fixed allowlist of symbols "
            "before send, the evaluated string is a constant, or the ERB template "
            "comes from a compile-time file and input only supplies render data."
        ),
        "vuln": "user.public_send(params[:method], params[:arg])",
        "safe": "/* allowlist allowed method names */",
        "signal": r"user\.public_send\(params\[:method\]",
        "references": [
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "CWE-470: Use of Externally-Controlled Input to Select Classes or Code — https://cwe.mitre.org/data/definitions/470.html",
            "Ruby stdlib documentation: Object — https://docs.ruby-lang.org/en/3.2/Object.html",
            "Ruby stdlib documentation: ERB — https://docs.ruby-lang.org/en/3.2/ERB.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/Object.html",
    },
    {
        "num": "03",
        "title": "Command Injection in Kernel#open and System Backticks",
        "platform": "Ruby 3.x standard library; MRI on POSIX (Kernel#open and IO.read detect a leading pipe character regardless of intent)",
        "mechanism": (
            "Kernel#open and IO.read treat a string beginning with '|' as a command "
            "line and spawn it through the shell, so a filename parameter that an "
            "attacker prefixes with '| ' becomes command execution without any "
            "shell API appearing in the code. system, exec, backticks, %x and "
            "IO.popen/Open3 invoked with a single interpolated string likewise pass "
            "the whole text to /bin/sh, letting ; | $() split or append commands. "
            "File.open and FileUtils do not perform the pipe check, so the sink "
            "choice — Kernel#open versus File.open — decides exploitability."
        ),
        "source": (
            "Request-derived file names, command fragments and arguments reaching "
            "these APIs directly or through interpolation."
        ),
        "sink": (
            "Kernel#open(attacker_string); IO.read(attacker_string); system / exec / "
            "backticks / %x; IO.popen and Open3 calls with a single shell string"
        ),
        "guards": (
            "Require array-form IO.popen/Open3 with a fixed argv[0]; require "
            "File.open/FileUtils (no pipe processing) for genuine file access; "
            "require input validation that rejects a leading '|' and shell "
            "metacharacters before any string form is used."
        ),
        "not_candidate_when": (
            "File access goes through File.open/FileUtils which never spawn shells, "
            "command arguments are passed as array elements with a constant "
            "executable, or the value is validated to contain no leading pipe and "
            "no shell metacharacters before use."
        ),
        "vuln": "open(\"|\" + params[:file_cmd]).read",
        "safe": "IO.popen([\"/bin/safe\", params[:arg]]).read",
        "signal": r"open\(\"\|\"\s*\+\s*params",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "Ruby stdlib documentation: Kernel — https://docs.ruby-lang.org/en/3.2/Kernel.html",
            "Ruby stdlib documentation: IO — https://docs.ruby-lang.org/en/3.2/IO.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/Kernel.html",
    },
    {
        "num": "04",
        "title": "SQL Injection via String Interpolation in Queries",
        "platform": "Ruby 3.x; database adapters and query interfaces (database drivers, ActiveRecord-style fragment APIs) parameterize bound values but interpolate SQL fragments verbatim",
        "mechanism": (
            "Query interfaces accept both bound values and raw SQL fragments; inside "
            "a fragment, #{} is evaluated by Ruby before the database sees the "
            "string, so a quote or SQL keyword in the value becomes statement "
            "structure. Identifier and keyword positions (ORDER BY column, GROUP BY, "
            "limit/offset fragments) cannot be parameterized at all, so code "
            "routinely interpolates sort keys and column names there even when "
            "values elsewhere are bound — making sort/filter parameters the usual "
            "injection point. Placeholders (? or named binds) hand values to the "
            "adapter out-of-band, so bound values cannot alter the parse."
        ),
        "source": (
            "Request parameters for search terms, sort keys, filter fields, column "
            "names and pagination values that reach fragment construction."
        ),
        "sink": (
            "Condition/fragment APIs taking interpolated strings (where(\"... "
            "#{...}\"), order(\"... #{...}\")), and raw driver execute calls built "
            "by concatenation"
        ),
        "guards": (
            "Require placeholders for every value; require identifier parts to be "
            "resolved through a fixed allowlist hash mapping client keys to column "
            "names (or the adapter's identifier quoting); require Integer() casting "
            "for limit/offset before interpolation."
        ),
        "not_candidate_when": (
            "Values are bound through placeholders, interpolated identifier parts "
            "come from a fixed server-side allowlist, or numeric fields are cast "
            "with Integer() before reaching the fragment."
        ),
        "vuln": "User.where(\"name = '#{params[:name]}'\")",
        "safe": "User.where(\"name = ?\", params[:name])",
        "signal": r"User\.where\(\"name = '#\{params",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "05",
        "title": "Mass Assignment and Parameter Type Confusion",
        "platform": "Ruby 3.x; MRI — request params are nested Hash/Array structures whose keys, nesting depth and value types the client controls",
        "mechanism": (
            "HTTP parameters arrive as nested hashes with attacker-chosen keys and "
            "value types, but Ruby method signatures say nothing about either: code "
            "written for params[:user] as a flat hash of strings silently accepts "
            "user[role]=admin, or a Hash/Array where a String was expected, because "
            "assignment interfaces copy whatever keys they are handed into model "
            "attributes or query conditions. Without an explicit permit list, the "
            "caller sets any attribute — role, admin, approved — and condition "
            "interfaces fed raw nested params change query shape based on the "
            "value's runtime type."
        ),
        "source": (
            "Form and query bodies with attacker-controlled keys and nesting "
            "(user[role]=admin, key[]=...), including JSON request bodies."
        ),
        "sink": (
            "Model update interfaces fed the raw params hash (update(params[:user]), "
            "attributes=), and query condition interfaces receiving raw nested "
            "params values"
        ),
        "guards": (
            "Require an explicit permit list between the request and the model "
            "(params.require(...).permit(:name, :email) style whitelisting); require "
            "type checks on params values (is_a?(String), to_s) before they enter "
            "comparisons or conditions."
        ),
        "not_candidate_when": (
            "Only permit-listed scalar keys reach the attribute update, params "
            "values are type-validated before use in conditions, or the hash is "
            "constructed server-side from known fields."
        ),
        "vuln": "User.update(params[:user])",
        "safe": "User.update(user_params) # using strong_parameters",
        "signal": r"User\.update\(params\[:user\]\)",
        "references": [
            "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes — https://cwe.mitre.org/data/definitions/915.html",
            "OWASP Web Application Security: Mass Assignment cheat sheet family — https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
    },
    {
        "num": "06",
        "title": "Regular Expression Multiline Anchors Trap",
        "platform": "Ruby 3.x standard library; ^ and $ are line anchors in Ruby regex, and Regexp.timeout exists only from Ruby 3.2+",
        "mechanism": (
            "In Ruby, ^ and $ anchor to line boundaries, so a validator like "
            "/^https:\\/\\/example\\.com$/ accepts 'https://example.com.attacker.tld\\n"
            "arbitrary' or any payload where the wanted prefix appears at a line "
            "start and everything else sits after a newline; \\A and \\z anchor the "
            "actual string boundaries ($ additionally matches before a trailing "
            "newline, \\Z does too, only \\z does not). The same unchecked-input "
            "shape feeds catastrophic backtracking: nested quantifiers over "
            "overlapping alternations drive exponential CPU on one thread, and only "
            "Ruby 3.2's Regexp.timeout bounds it. Converting external input with "
            "to_sym feeds attacker-chosen symbols into method and lookup namespaces; "
            "since Ruby 2.2 symbols are garbage-collected, so the historical "
            "memory-exhaustion angle is bounded, but the lookup-collision angle "
            "remains."
        ),
        "source": (
            "URLs, identifiers and multiline strings supplied by clients and "
            "validated with anchored regexes; patterns and subjects driving "
            "backtracking."
        ),
        "sink": (
            "=~ / match on security gates using ^...$ or $-anchored patterns; "
            "Regexp.new with input-derived patterns; to_sym on external input used "
            "for lookups"
        ),
        "guards": (
            "Require \\A / \\z anchors (not ^ / $) in validators, plus explicit "
            "rejection of \\n in the validated value; require Regexp.timeout (Ruby "
            "3.2+) or bounded input length with constant patterns; require to_sym "
            "inputs to come from a fixed set."
        ),
        "not_candidate_when": (
            "The pattern is anchored with \\A/\\z and newlines are rejected "
            "explicitly, the regex is a constant without nested quantifiers and the "
            "subject is length-bounded, or to_sym operates on values drawn from a "
            "server-side fixed set."
        ),
        "vuln": "valid = url =~ /^https:\\/\\/example\\.com$/",
        "safe": "valid = url =~ /\\Ahttps:\\/\\/example\\.com\\z/",
        "signal": r"url\s*=~\s*\/\^https",
        "references": [
            "CWE-1333: Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html",
            "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
            "Ruby stdlib documentation: Regexp — https://docs.ruby-lang.org/en/3.2/Regexp.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/Regexp.html",
    },
    {
        "num": "07",
        "title": "Raw HTML and html_safe Misuse",
        "platform": "Ruby 3.x; MRI — the html_safe flag is a plain String property; escaping layers honor it wherever the string is rendered",
        "mechanism": (
            "String#html_safe flips a trust flag on the String so the rendering "
            "layer skips HTML escaping for it; calling it on anything derived from "
            "input (or passing input through raw()) hands attacker bytes to the "
            "response as markup. The flag is not contextual: a string marked safe "
            "is emitted unescaped in body, attribute and script contexts alike, so "
            "single-quote or attribute-boundary payloads survive. A separate "
            "attribute-context hazard survives even correct HTML escaping: a "
            "javascript: URL placed into an href/src attribute executes on click "
            "because the text itself needed scheme validation, not escaping."
        ),
        "source": (
            "User-supplied text fields, bios, comments and URLs rendered into HTML "
            "responses."
        ),
        "sink": (
            "html_safe / raw() applied to input-derived strings; unescaped "
            "interpolation into attribute contexts; javascript:-scheme URLs placed "
            "into href/src attributes"
        ),
        "guards": (
            "Require that html_safe/raw is never called on input-derived strings — "
            "only on server-generated constant HTML; require allowlist-based "
            "sanitization (tag/attribute whitelists) before any HTML must be "
            "allowed; require URL scheme validation (http/https/relative only) "
            "before placing values into href/src."
        ),
        "not_candidate_when": (
            "The marked string is a server-side constant template fragment, input "
            "passed through a real allowlist sanitizer before being marked safe, or "
            "URL attributes are scheme-validated before rendering."
        ),
        "vuln": "raw_html = user_bio.html_safe",
        "safe": "safe_html = sanitize(user_bio)",
        "signal": r"user_bio\.html_safe",
        "references": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html",
            "OWASP Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "08",
        "title": "Path Traversal via Pathname#join",
        "platform": "Ruby 3.x standard library; MRI",
        "mechanism": (
            "Pathname#join replaces the whole path when the argument is absolute — "
            "Pathname.new('/safe/dir').join('/etc/passwd') is /etc/passwd — and "
            "'..' segments survive in plain File.join/File.read construction, so a "
            "single join call never confines the result to the base directory. "
            "Dir.glob expands metacharacters (*, ?, [, {) appearing in an "
            "attacker-supplied pattern beyond the intended directory, and archive "
            "entry names containing absolute paths or '..' escape the extraction "
            "root when unpacked verbatim. Temporary names built as Dir.tmpdir plus "
            "a fixed string are predictable, letting a local attacker pre-create a "
            "symlink at that path."
        ),
        "source": (
            "Request-supplied file names, download paths, glob patterns, archive "
            "entry names, and any path component from external input."
        ),
        "sink": (
            "Pathname#join / File.join / File.read with attacker components; "
            "Dir.glob with input-derived patterns; archive extraction loops; "
            "hard-coded temporary file names"
        ),
        "guards": (
            "Require File.basename extraction plus a realpath containment check "
            "(candidate.realpath starts_with? base.realpath) before use; require "
            "glob patterns to be constant with input escaped (Dir.glob escape) or "
            "results filtered; require archive entry names validated against the "
            "extraction root; require Tempfile.create for temporary files."
        ),
        "not_candidate_when": (
            "The component is basename()'d and containment is verified via realpath "
            "before any read/write, the glob pattern is constant with input escaped "
            "or result-filtered, archive members are validated against the target "
            "root, or temporary files come from Tempfile.create."
        ),
        "vuln": "Pathname.new('/safe/dir').join(params[:path])",
        "safe": "File.join('/safe/dir', File.basename(params[:path]))",
        "signal": r"Pathname\.new\('/safe/dir'\)\.join",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "Ruby stdlib documentation: Pathname — https://docs.ruby-lang.org/en/3.2/Pathname.html",
            "Ruby stdlib documentation: Dir — https://docs.ruby-lang.org/en/3.2/Dir.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/Pathname.html",
    },
    {
        "num": "09",
        "title": "Class Variable and Open Class State Leakage",
        "platform": "Ruby 3.x; MRI — class-level state (@@vars, class instance variables) is shared across all threads and requests in the process",
        "mechanism": (
            "Ruby classes are open: any code that loads can reopen a class and "
            "redefine a validation or authorization method, silently changing its "
            "semantics for the whole application without a call-site change. "
            "method_missing dispatch paths expose and route methods the class never "
            "declared, and send ignores private/protected visibility, so "
            "'private' is not an access control against send callers. Class-level "
            "mutable state — @@class variables and class instance variables — is a "
            "single object shared by every request and thread, so per-user security "
            "state stored there (current user, ACL, CSRF material) leaks between "
            "concurrent requests: one user's authorization satisfies another's "
            "check."
        ),
        "source": (
            "Concurrent requests sharing process-global state; attacker-influenced "
            "dispatch names routed through method_missing/send."
        ),
        "sink": (
            "Reopening/monkey-patching of auth-relevant methods; method_missing "
            "dispatch without allowlist; send reaching private methods; @@class "
            "variables and class-level attributes holding per-request identity or "
            "authorization state"
        ),
        "guards": (
            "Require per-request state to live in Thread.current/fiber-local storage "
            "or request-scoped objects, never @@variables; require respond_to_missing? "
            "paired with method_missing and an allowlist of routed names; require "
            "send targets validated against fixed allowlists; treat redefinition of "
            "security methods by loaded libraries as a change to review."
        ),
        "not_candidate_when": (
            "Class-level variables hold only immutable configuration written once "
            "at boot, method_missing routes a fixed allowlist and responds "
            "correctly to respond_to_missing?, and dispatched method names are "
            "allowlist-checked before send."
        ),
        "vuln": "class App; @@current_user = user; end",
        "safe": "Thread.current[:user] = user",
        "signal": r"@@current_user\s*=\s*user",
        "references": [
            "CWE-470: Use of Externally-Controlled Input to Select Classes or Code — https://cwe.mitre.org/data/definitions/470.html",
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "Ruby stdlib documentation: Module — https://docs.ruby-lang.org/en/3.2/Module.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/Module.html",
    },
    {
        "num": "10",
        "title": "Weak Randomness and Timeout Asynchronous Interrupts",
        "platform": "Ruby 3.x standard library; MRI — SecureRandom draws from the OS CSPRNG, rand/Random are seeded MT19937, and Timeout.timeout raises asynchronously from a timer thread",
        "mechanism": (
            "rand and Random are seeded PRNGs (MT19937) whose state is recoverable "
            "from observed outputs, so tokens, reset codes and keys drawn from them "
            "are predictable; SecureRandom reads the OS CSPRNG instead. Comparing "
            "authenticators with == short-circuits at the first differing byte, "
            "leaking a timing oracle that recovers the value byte by byte — a "
            "fixed-length constant-time comparison is required. Timeout.timeout "
            "raises its exception from a background timer thread at an arbitrary "
            "point inside the block, so a multi-step security operation (write "
            "temporary file then set permissions, debit then record, grant then "
            "persist) can be interrupted between steps, leaving half-applied state "
            "or a partially-open permission."
        ),
        "source": (
            "Token/key material generated by the application; authenticator values "
            "compared per request; timeouts wrapping security-relevant write "
            "operations."
        ),
        "sink": (
            "rand / Random.new feeding security values; == / != comparisons of "
            "tokens or MACs; Timeout.timeout wrapping multi-step security operations"
        ),
        "guards": (
            "Require SecureRandom (hex/uuid/random_bytes) for all security values; "
            "require a fixed-length constant-time comparison helper for "
            "authenticators; require ensure blocks that roll back on Timeout::Error "
            "and idempotent, ordered operations inside any Timeout block."
        ),
        "not_candidate_when": (
            "rand feeds only non-security sampling or display, the compared values "
            "are non-secret configuration, or the Timeout-wrapped operation is an "
            "idempotent read with rollback handling that leaves no partial "
            "authorization state."
        ),
        "vuln": "token = rand(100000..999999).to_s",
        "safe": "token = SecureRandom.hex(16)",
        "signal": r"rand\(100000\.\.999999\)",
        "references": [
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition — https://cwe.mitre.org/data/definitions/367.html",
            "Ruby stdlib documentation: SecureRandom — https://docs.ruby-lang.org/en/3.2/SecureRandom.html",
            "Ruby stdlib documentation: Timeout — https://docs.ruby-lang.org/en/3.2/Timeout.html",
        ],
        "doc_url": "https://docs.ruby-lang.org/en/3.2/SecureRandom.html",
    },
]
