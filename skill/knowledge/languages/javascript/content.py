"""Substantive per-card content for the JavaScript knowledge cards (js-01..js-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card carries real mechanism, source/sink, guard, and
disqualification text. Entries cite only public references believed to exist
(CWE pages, official Node.js and web-platform documentation).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (JavaScript section).
"""

LANGUAGE = {
    "name": "JavaScript",
    "prefix": "js",
}

CARDS = [
    {
        "num": "01",
        "title": "Prototype Pollution in Recursive Object Merging",
        "platform": "ECMAScript 2020 semantics in Node.js runtime; identical in browsers wherever recursive merge or path assignment runs",
        "mechanism": (
            "Ordinary objects inherit from Object.prototype, and plain assignment to "
            "__proto__ or to a path ending in constructor.prototype does not create an "
            "own property -- it re-points the prototype chain or walks to Function."
            "prototype. A recursive merge (or a dot/bracket path setter) that copies "
            "attacker keys without filtering therefore lets JSON like "
            "{\"__proto__\":{\"isAdmin\":true}} change what every later object in the "
            "process inherits. Property lookups on unrelated objects then find "
            "attacker-chosen values, which frequently flips security-relevant option "
            "flags (isAdmin, privileged, safeMode) that guards read indirectly."
        ),
        "source": (
            "Request bodies, JSON payloads, query strings, or any nested object "
            "parsed from attacker-controlled input that reaches a deep-merge, "
            "defaults-fill, or path-based set operation."
        ),
        "sink": (
            "Recursive merge helpers writing target[key] = value for attacker keys "
            "(especially __proto__ and constructor); lodash-style set/assign with "
            "path strings; obj[attackerPath] = value on plain objects"
        ),
        "guards": (
            "Check the merge skips or hard-freezes the dangerous keys (__proto__, "
            "constructor, prototype) before assignment, uses Object.create(null) "
            "targets or a Map instead of plain objects, or parses with a JSON "
            "reviver that drops inherited keys; assignment through defineProperty "
            "alone is not a guard unless the key check is also present."
        ),
        "not_candidate_when": (
            "The merged keys come from a fixed server-side schema and unknown keys "
            "are rejected before the merge, the target is an Object.create(null) "
            "dictionary immune to prototype writes, or the input is a top-level "
            "copy (Object.assign / spread) whose keys can never be nested paths."
        ),
        "vuln": "target[key] = source[key]; // key is __proto__",
        "safe": "if (key !== '__proto__' && key !== 'constructor') target[key] = source[key];",
        "signal": r"target\[key\]\s*=\s*source\[key\]",
        "references": [
            "CWE-1321: Improperly Controlled Modification of Dynamically-Determined Object Attributes — https://cwe.mitre.org/data/definitions/1321.html",
            "OWASP Prototype Pollution Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
            "MDN: Object.prototype.__proto__ — https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "02",
        "title": "Code Injection via eval and new Function",
        "platform": "ECMAScript 2020 semantics in Node.js runtime and browsers; identical engine behavior in both",
        "mechanism": (
            "eval and the Function constructor compile their argument as a full "
            "program with the caller's scope chain, so an injected expression is "
            "indistinguishable from first-party code and can close over in-scope "
            "variables. A string argument to setTimeout/setInterval is the same "
            "construction delayed. Node's vm module is frequently mistaken for a "
            "sandbox, but its contexts share the process: scripts can reach the "
            "host objects via the built-in constructor escape chains (this."
            "constructor.constructor) and exit into require('child_process'). "
            "Dynamic require(path) / import(specifier) with attacker text loads "
            "attacker-chosen modules from the resolver's search path."
        ),
        "source": (
            "User-supplied expression or rule strings (template fragments, formula "
            "fields, stored 'script' columns), request-derived module names, and "
            "persisted strings later handed to eval / new Function / string "
            "setTimeout."
        ),
        "sink": (
            "eval(), new Function(), string-form setTimeout/setInterval, vm."
            "runInNewContext/runInThisContext on untrusted text, dynamic "
            "require() / import() with attacker-controlled specifiers"
        ),
        "guards": (
            "Check the evaluated text is a compile-time constant and only values "
            "are dynamic; check data-shaped inputs are parsed with JSON.parse "
            "instead of evaluated; check expression needs are met by a parser/"
            "expression library that never calls eval; check dynamic imports "
            "resolve from a fixed allowlist of module names."
        ),
        "not_candidate_when": (
            "The argument is a literal constant in the shipped code, the input is "
            "parsed with JSON.parse (data, not code), or require targets are "
            "chosen from a fixed internal map keyed by a validated enum value."
        ),
        "vuln": "const res = eval(userCode);",
        "safe": "const res = JSON.parse(userCode);",
        "signal": r"eval\(userCode\)",
        "references": [
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "CWE-95: Eval Injection — https://cwe.mitre.org/data/definitions/95.html",
            "Node.js documentation: vm module (execution of untrusted code is not its purpose) — https://nodejs.org/api/vm.html",
        ],
        "doc_url": "https://nodejs.org/api/vm.html",
    },
    {
        "num": "03",
        "title": "Command Injection via child_process.exec",
        "platform": "Node.js runtime (child_process module); shell resolution is /bin/sh on POSIX and cmd.exe on Windows",
        "mechanism": (
            "child_process.exec and execSync do not take an argv vector: they hand "
            "the whole string to a shell, so metacharacters in interpolated input "
            "(';', '|', '&', '$( )', backquotes, newlines) end the intended command "
            "and start attacker-chosen ones. spawn with shell:true rebuilds the "
            "same string form. Even with the argv form, an input value that starts "
            "with '-' is consumed by the spawned program as an option (argument "
            "injection), which for utilities like curl or tar can flip them into "
            "file-write or exfiltration primitives."
        ),
        "source": (
            "Hosts, URLs, filenames, or free-text fields from requests that are "
            "interpolated into a command string or passed as leading argv elements."
        ),
        "sink": (
            "child_process.exec / execSync with template strings; spawn / "
            "execFile with shell:true; argv elements starting with '-' taken "
            "from input"
        ),
        "guards": (
            "Prefer execFile/spawn with an argv array, shell unset, and the "
            "dynamic value as one element; verify '--' is placed before "
            "attacker-derived arguments; verify strict allowlist validation "
            "(e.g. hostname grammar) before interpolation into any shell string."
        ),
        "not_candidate_when": (
            "The command is a fixed constant with no interpolation, the dynamic "
            "value lands in a single argv element after a literal '--' and the "
            "utility takes no further options, or the value is validated against "
            "a strict grammar that excludes shell metacharacters."
        ),
        "vuln": "child_process.exec(`ping ${host}`);",
        "safe": "child_process.execFile('ping', [host]);",
        "signal": r"child_process\.exec\(`ping",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-88: Argument Injection or Modification — https://cwe.mitre.org/data/definitions/88.html",
            "Node.js documentation: child_process.exec (shell caveats) — https://nodejs.org/api/child_process.html",
        ],
        "doc_url": "https://nodejs.org/api/child_process.html",
    },
    {
        "num": "04",
        "title": "DOM Cross-Site Scripting via innerHTML",
        "platform": "Browser DOM APIs (HTML documents); server-side rendering pipelines that emit HTML strings share the same sink semantics",
        "mechanism": (
            "Assigning a string to innerHTML, outerHTML, or insertAdjacentHTML, "
            "and calling document.write, invoke the HTML parser: script-bearing "
            "markup in the string executes in the page origin, and event-handler "
            "attributes (onerror, onload) fire without any script permission step. "
            "textContent and createElement/textNode insert text nodes and cannot "
            "create elements, which is the actual defense. javascript: URLs are a "
            "second sink: assigning attacker text to href/src or navigating to it "
            "runs the string as code on click. window.postMessage handlers that "
            "act on event.data without checking event.origin let any embedding "
            "page inject into this sink."
        ),
        "source": (
            "User comments, profile fields, URL fragments/hash, postMessage "
            "event.data, and DOM values read back from location or storage."
        ),
        "sink": (
            "element.innerHTML / outerHTML / insertAdjacentHTML assignment; "
            "document.write; javascript: URL assignment to href/location; "
            "acting on postMessage event.data without an origin check"
        ),
        "guards": (
            "Check the insertion point uses textContent or createElement with "
            "text nodes; if HTML is required, check it passes a sanitizer that "
            "strips script/event handlers before innerHTML; check postMessage "
            "handlers validate event.origin against an allowlist; check URL "
            "assignments are restricted to http(s) and rejected when the scheme "
            "is javascript:."
        ),
        "not_candidate_when": (
            "The string inserted is static HTML shipped with the app, the value "
            "reaches textContent or an escaped template output, the sanitizer "
            "runs in the same origin before insertion and is markup-aware, or "
            "the postMessage path validates origin and treats data as untrusted "
            "text."
        ),
        "vuln": "element.innerHTML = userComment;",
        "safe": "element.textContent = userComment;",
        "signal": r"element\.innerHTML\s*=\s*userComment",
        "references": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) — https://cwe.mitre.org/data/definitions/79.html",
            "MDN: Element.innerHTML — https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML",
            "OWASP Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML",
    },
    {
        "num": "05",
        "title": "Type Coercion and Loose Comparison Bypasses",
        "platform": "ECMAScript 2020 semantics in Node.js runtime and browsers; identical coercion rules in both (Abstract Equality Comparison)",
        "mechanism": (
            "The == operator applies ToPrimitive/ToNumber coercion before "
            "comparison, so values of different types can compare equal: '' == 0, "
            "'0' == false, [1] == 1, and document.cookie or query values parsed "
            "out of a string arrive as strings that coerce against numbers. On an "
            "authorization path, a check like value == 1 accepts '1', ' 1', or "
            "[1]. Query-string parsers that decode a[]=1 produce arrays where the "
            "code expects a string, and parseInt('08abc') stops at the first "
            "non-digit, so a validated-looking prefix hides the rest. Integers "
            "beyond 2^53 lose precision in doubles, letting two distinct 64-bit "
            "IDs collapse to one compared value."
        ),
        "source": (
            "Query strings, request bodies, cookies, and headers -- always "
            "strings or parser-produced arrays -- that flow into comparison "
            "or validation expressions."
        ),
        "sink": (
            "== / != on security-decision values; truthiness checks over "
            "parser-produced arrays; parseInt / Number validation feeding "
            "authorization; == on 64-bit identifiers"
        ),
        "guards": (
            "Check security comparisons use === / !==, that expected types are "
            "asserted (typeof) before the check, that token/MAC comparisons use "
            "crypto.timingSafeEqual over equal-length buffers, and that large "
            "IDs stay strings or BigInt end to end."
        ),
        "not_candidate_when": (
            "Both operands are provably the same type by construction and the "
            "comparison uses ===, the compared value is a constant not derived "
            "from request data, or the check is non-security and coercion is "
            "the intended behavior."
        ),
        "vuln": "if (token == expectedToken) { grantAccess(); }",
        "safe": "if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) { grantAccess(); }",
        "signal": r"token\s*==\s*expectedToken",
        "references": [
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "Node.js documentation: crypto.timingSafeEqual — https://nodejs.org/api/crypto.html",
        ],
        "doc_url": "https://nodejs.org/api/crypto.html",
    },
    {
        "num": "06",
        "title": "Path Traversal via path.resolve and fs APIs",
        "platform": "Node.js runtime (path and fs modules); behavior identical on POSIX and Windows with platform-specific separators",
        "mechanism": (
            "path.resolve(base, userFile) treats an absolute second argument as a "
            "full replacement -- resolve('/var/data', '/etc/passwd') returns "
            "'/etc/passwd' -- and it normalizes '..' segments away without ever "
            "checking containment, so '../..' escapes silently. path.join keeps "
            "the base but still preserves '..' segments, so join alone is not a "
            "confinement mechanism either. Any fs call (readFile, createReadStream, "
            "unlink) then operates on the escaped path; symlink entries inside "
            "user-uploaded archives add a second escape once extracted."
        ),
        "source": (
            "Download/upload filename parameters, stored file names from user "
            "profiles, archive entry names, and any path fragment from a request."
        ),
        "sink": (
            "path.resolve / path.join over attacker input feeding fs.readFile, "
            "fs.createReadStream, fs.writeFile, fs.unlink, or archive member "
            "extraction"
        ),
        "guards": (
            "Check the code strips to path.basename before composing, or "
            "normalizes the candidate and verifies path.resolve(candidate)."
            "startsWith(resolve(base) + sep) before any fs call; check symlinked "
            "entries in extracted archives are rejected or resolved and "
            "re-checked."
        ),
        "not_candidate_when": (
            "The path fragment is generated server-side (UUID/content hash), "
            "basename is taken and a realpath containment check runs before the "
            "fs call, or the resolved candidate is compared to a fixed "
            "allowlist of full paths."
        ),
        "vuln": "fs.readFile(path.resolve('/var/data', userFile), cb);",
        "safe": "const clean = path.basename(userFile); fs.readFile(path.join('/var/data', clean), cb);",
        "signal": r"fs\.readFile\(path\.resolve\(",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "Node.js documentation: path.resolve — https://nodejs.org/api/path.html",
            "Node.js documentation: fs module — https://nodejs.org/api/fs.html",
        ],
        "doc_url": "https://nodejs.org/api/path.html",
    },
    {
        "num": "07",
        "title": "Event Loop Blocking and Catastrophic Regex (ReDoS)",
        "platform": "Node.js runtime single-threaded event loop; also applies to browser main threads sharing the same regex engine behavior",
        "mechanism": (
            "JavaScript runs request handlers on one event loop thread: a single "
            "long-running synchronous call stalls every concurrent request. "
            "Regex patterns with nested quantifiers over overlapping alternations "
            "(e.g. /^([a-zA-Z0-9]+)*$/) backtrack exponentially on a crafted "
            "near-match input, so one 50-byte string can pin the loop for minutes "
            "-- and there is no built-in match timeout in V8. The same "
            "unbounded-work shape appears in synchronous CPU loops and in "
            "Buffer.alloc(attackerLength): the allocation is zero-filled "
            "synchronously, while Buffer.allocUnsafe returns uninitialized memory "
            "that can leak process-internal bytes into responses."
        ),
        "source": (
            "User-supplied subject strings matched against fixed patterns, "
            "attacker-supplied patterns (search features), declared lengths/sizes "
            "in protocol headers driving allocations."
        ),
        "sink": (
            "RegExp .exec/.test/.match on untrusted input with nested-quantifier "
            "patterns; long synchronous loops in request handlers; Buffer.alloc "
            "or Buffer.allocUnsafe sized from input"
        ),
        "guards": (
            "Check subject length is capped before matching and patterns avoid "
            "nested quantifiers over overlapping classes; check a worker thread "
            "or a timeout-wrapped execution isolates untrusted matches; check "
            "allocations use fixed or validated maximum sizes and "
            "Buffer.alloc (not allocUnsafe) for response-visible buffers."
        ),
        "not_candidate_when": (
            "The pattern is linear (no nested quantifiers) and inputs are length-"
            "bounded, the match runs in a worker pool with a deadline, or the "
            "buffer size is a compile-time constant independent of input."
        ),
        "vuln": "const match = /^([a-zA-Z0-9]+)*$/.exec(userInput);",
        "safe": "/* use linear regex or set timeouts */",
        "signal": r"\^.*a-zA-Z.*exec",
        "references": [
            "CWE-1333: Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html",
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "Node.js documentation: Buffer.alloc / allocUnsafe — https://nodejs.org/api/buffer.html",
        ],
        "doc_url": "https://nodejs.org/api/buffer.html",
    },
    {
        "num": "08",
        "title": "Unhandled Promise Rejection and Missing Await in Auth",
        "platform": "Node.js runtime (Promises/A+ semantics, async/await); identical semantics in browsers for client-side guards",
        "mechanism": (
            "Calling an async function returns a Promise; forgetting await means "
            "the Promise<boolean> object itself is truthy, so if (!checkAuth(req)) "
            "is always false and the request proceeds regardless of the eventual "
            "result. The rejection, when it comes, is unhandled: in modern Node "
            "it crashes the process (unhandledRejection default) or, with a "
            "handler attached, silently drops the decision. The same gap yields "
            "check-then-act races across await -- state can change between the "
            "check and the guarded operation -- and swallowed rejections "
            "(.catch(() => {}) or missing catch in a helper) turn failed "
            "authorization into fail-open."
        ),
        "source": (
            "Request-scoped authentication/authorization calls and any "
            "async guard function whose result gates a sensitive operation."
        ),
        "sink": (
            "async guard invoked without await in a conditional; floating "
            "Promises before sensitive operations; empty .catch handlers on "
            "auth paths; check-then-act sequences spanning an await"
        ),
        "guards": (
            "Check every security-decision call is awaited inside the "
            "conditional; check linters/no-floating-promises enforcement; check "
            "catch paths fail closed (deny) rather than return the success "
            "branch; check authorization is re-verified after any await that "
            "crosses a mutation of the guarded resource."
        ),
        "not_candidate_when": (
            "The call is intentionally fire-and-forget with no security "
            "decision downstream and rejections are explicitly handled, the "
            "guarded operation is re-authorized after the await, or the "
            "function is synchronous so no Promise is involved."
        ),
        "vuln": "if (!checkAuth(req)) { return res.status(401); }",
        "safe": "if (!await checkAuth(req)) { return res.status(401); }",
        "signal": r"if\s*\(!checkAuth\(req\)\)",
        "references": [
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "Node.js documentation: process events (unhandledRejection) — https://nodejs.org/api/process.html",
        ],
        "doc_url": "https://nodejs.org/api/process.html",
    },
    {
        "num": "09",
        "title": "Unsafe Deserialization and Reviver Misuse",
        "platform": "ECMAScript 2020 semantics in Node.js runtime; XML entity behavior depends on the parser in use",
        "mechanism": (
            "Historically, JavaScript 'deserialization' meant evaluating the "
            "payload -- new Function('return ' + text) or eval -- which executes "
            "embedded code verbatim. JSON.parse itself never executes code, but "
            "its reviver argument is called for every key with attacker-chosen "
            "key/value pairs, so a reviver that dispatches on key names into "
            "constructors or setters turns the payload into a constructor/"
            "property-assignment gadget chain. Server-side XML parsers invoked "
            "with entity processing enabled resolve external entities, giving "
            "file read and SSRF with the payload alone."
        ),
        "source": (
            "Request bodies, stored blobs, cross-service messages, and "
            "XML/config documents received from peers or uploads."
        ),
        "sink": (
            "new Function / eval used to reconstruct objects from text; "
            "JSON.parse with a reviver that assigns or constructs from "
            "attacker keys; XML parsers with entity expansion enabled"
        ),
        "guards": (
            "Check data-only payloads are read with plain JSON.parse and a "
            "schema validator rather than evaluation; check the reviver is a "
            "constant function that never calls constructors or writes to "
            "objects by attacker-supplied key; check XML parsing disables DTD/"
            "entity resolution."
        ),
        "not_candidate_when": (
            "The payload is parsed with JSON.parse and validated against a "
            "schema before use, the reviver only filters/prunes known keys "
            "with fixed logic, or the XML producer is a trusted internal "
            "service that never emits DTDs."
        ),
        "vuln": "const data = (new Function('return ' + rawJson))();",
        "safe": "const data = JSON.parse(rawJson);",
        "signal": r"new\s+Function\('return\s*'\s*\+\s*rawJson\)",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    },
    {
        "num": "10",
        "title": "Insecure Randomness via Math.random for Tokens",
        "platform": "ECMAScript 2020 semantics; Math.random in V8 (Node.js and Chrome) is a 128-bit xorshift128+ PRNG whose state is recoverable from outputs",
        "mechanism": (
            "Math.random is a pseudo-random generator seeded once per process and "
            "never reseeded; in V8 its xorshift128+ state can be reconstructed "
            "from a handful of observed outputs, after which all past and future "
            "outputs are predictable. Tokens, reset codes, and keys drawn from it "
            "are therefore guessable by anyone who can observe a few values "
            "(shares, leaderboards, timing endpoints) or read adjacent outputs. "
            "crypto.randomBytes / getRandomValues draw from the OS CSPRNG and do "
            "not share this weakness. Deprecated weak interfaces (md5 via "
            "createHash('md5') for credentials, single-DES) fail on the algorithm "
            "side the same way."
        ),
        "source": (
            "The token value itself: session identifiers, password-reset codes, "
            "API keys, CSRF nonces, and any secret the developer generated "
            "client-side or server-side with Math.random."
        ),
        "sink": (
            "Math.random() feeding token/key/nonce generation; crypto."
            "createHash('md5'/'sha1') for credentials; deprecated weak cipher "
            "construction in crypto.createCipheriv"
        ),
        "guards": (
            "Check security values come from crypto.randomBytes (Node) or "
            "crypto.getRandomValues (web), not Math.random; check credentials "
            "use a slow KDF or authenticated cipher from the crypto module; "
            "check comparers use crypto.timingSafeEqual."
        ),
        "not_candidate_when": (
            "Math.random drives only non-security behavior (animation, "
            "sampling, test fixtures, shuffling non-sensitive lists), the "
            "random value is combined with a CSPRNG source before use, or the "
            "fast hash digests content for integrity/dedup rather than "
            "authentication."
        ),
        "vuln": "const token = Math.random().toString(36).substring(2);",
        "safe": "const token = crypto.randomBytes(16).toString('hex');",
        "signal": r"Math\.random\(\)\.toString\(36\)",
        "references": [
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "Node.js documentation: crypto.randomBytes — https://nodejs.org/api/crypto.html",
        ],
        "doc_url": "https://nodejs.org/api/crypto.html",
    },
]
