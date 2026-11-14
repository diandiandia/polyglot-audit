"""Substantive per-card content for the PHP knowledge cards (php-01..php-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, official PHP manual pages).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (PHP section).
"""

LANGUAGE = {
    "name": "PHP",
    "prefix": "php",
}

CARDS = [
    {
        "num": "01",
        "title": "Type Juggling and Loose Comparison Bypasses",
        "platform": "PHP 8.x default configuration; PHP 8 tightened string<->int comparisons, but two numeric strings still compare numerically, so '0e'-prefixed digest collisions persist",
        "mechanism": (
            "PHP's == converts operands before comparing: two numeric strings are "
            "compared as numbers, so any md5/sha1 digest of the form '0e' followed by "
            "all digits (magic hashes, e.g. md5('240610708') == "
            "'0e462097431906509030567485623617') equals every other such digest because "
            "both cast to float 0. in_array() and array_search() default to loose "
            "comparison unless the third $strict argument is true, and switch() matches "
            "loosely, so membership/role checks pass on unexpected values. On PHP 7, "
            "passing an array to strcmp()/strlen() raises a warning and returns NULL, "
            "which == treats as equal to 0, letting an attacker-supplied array bypass "
            "the check (PHP 8 throws a TypeError instead)."
        ),
        "source": (
            "Request-supplied digests, tokens, role/flag parameters, and array-vs-scalar "
            "parameter shapes (a[]= style) that flow into comparison constructs."
        ),
        "sink": (
            "=== vs == distinctions aside: == / != on authenticators; in_array / "
            "array_search without $strict=true; switch matching attacker-controlled "
            "scalars; strcmp/strlen receiving attacker-chosen argument types"
        ),
        "guards": (
            "Require hash_equals() or password_verify() for every authenticator "
            "comparison; require in_array(..., true) strict mode on security paths; "
            "require gettype()/is_string() checks before functions that expect scalars; "
            "prefer === / !== everywhere an authentication outcome is decided."
        ),
        "not_candidate_when": (
            "Operands are provably the same internal type by construction (both "
            "server-generated integers), the comparison is === / !==, digest "
            "comparison already goes through hash_equals/password_verify, or "
            "in_array is strict=true and feeds a non-security decision."
        ),
        "vuln": "if ($password_hash == '0e123456789') { login(); }",
        "safe": "if (hash_equals($password_hash, $expected)) { login(); }",
        "signal": r"\$password_hash\s*==\s*'0e",
        "references": [
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
            "PHP manual: hash_equals — https://www.php.net/manual/en/function.hash-equals.php",
            "PHP manual: comparison operators table — https://www.php.net/manual/en/language.operators.comparison.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.hash-equals.php",
    },
    {
        "num": "02",
        "title": "PHP Object Injection via unserialize()",
        "platform": "PHP 7.4/8.x default configuration; the phar stream wrapper parses metadata via unserialize on plain file-stat calls (phar.readonly does not block reads)",
        "mechanism": (
            "unserialize() reconstructs the object graph named inside the serialized "
            "string without ever calling a constructor, so attacker-chosen classes are "
            "instantiated in arbitrary internal states; afterwards PHP fires the magic "
            "methods __wakeup, __destruct and __toString on those objects, and gadget "
            "methods inside the codebase chain from them into file writes, eval or "
            "command execution (POP chains need no parse bug, only reachable classes). "
            "Separately, ordinary file functions such as file_exists(), is_dir() or "
            "fopen() unserialize phar archive metadata whenever the path uses the "
            "phar:// wrapper, so code that never calls unserialize on user input is "
            "still exploitable if an attacker-controlled path can carry that wrapper."
        ),
        "source": (
            "Cookie/session blobs, state parameters, queued payloads, and any "
            "attacker-influenced file path that may reach a filesystem function."
        ),
        "sink": (
            "unserialize() on attacker-controlled data; is_dir/file_exists/fopen/"
            "file_get_contents and friends receiving phar:// paths"
        ),
        "guards": (
            "Check unserialize calls pass the allowed_classes second argument as [] or "
            "a tight class whitelist (PHP 7.0+); prefer json_decode for data exchange; "
            "check file functions never receive raw attacker paths — stream wrappers "
            "must be stripped (realpath plus scheme validation) before any stat/read."
        ),
        "not_candidate_when": (
            "The payload is produced and signed inside one trust domain with the "
            "signature verified before unserialize and a whitelist via allowed_classes, "
            "unserialize runs with allowed_classes=[] over value-only objects, or "
            "attacker paths are reduced to plain real paths before reaching file "
            "functions so no phar:// wrapper survives."
        ),
        "vuln": "$data = unserialize($_COOKIE['session']);",
        "safe": "$data = json_decode($_COOKIE['session'], true);",
        "signal": r"unserialize\(\$_COOKIE",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "PHP manual: unserialize (allowed_classes) — https://www.php.net/manual/en/function.unserialize.php",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://www.php.net/manual/en/function.unserialize.php",
    },
    {
        "num": "03",
        "title": "Local File Inclusion via include/require",
        "platform": "PHP 7.4/8.x; allow_url_include is Off by default (no remote include), allow_url_fopen is On by default (stream wrappers usable in file functions)",
        "mechanism": (
            "include/require execute the file their argument resolves to with full "
            "application privileges, so a path assembled from input is arbitrary code "
            "execution whenever the attacker can plant PHP content anywhere the web "
            "user reads (upload directories, session files, /tmp). Even without remote "
            "include, file functions honor stream wrappers: php://filter/"
            "convert.base64-encode/resource=... returns application source, and data:// "
            "yields inline content to file_get_contents/fopen because allow_url_fopen "
            "is On by default. move_uploaded_file() does not inspect content or type, "
            "so an attacker-chosen destination plus an uploaded .php payload combine "
            "into the same execution primitive."
        ),
        "source": (
            "GET/POST/cookie page or template parameters, uploaded file names and "
            "destination paths, import/export path options."
        ),
        "sink": (
            "include/require with a dynamic path; file_get_contents/fopen on an "
            "attacker string while allow_url_fopen is on; move_uploaded_file into an "
            "attacker-influenced location"
        ),
        "guards": (
            "Require a fixed allowlist mapping request keys to constant file paths; "
            "where a path is unavoidable, require basename() plus realpath containment "
            "inside a directory holding no executable or attacker-writable files; "
            "require stream wrappers to be rejected (validated realpath, no scheme "
            "prefix) before any file function; require server-generated upload names."
        ),
        "not_candidate_when": (
            "The included file is resolved through a fixed allowlist dictionary, "
            "realpath containment confines the result to a non-executable, non-"
            "attacker-writable directory, or upload destinations are generated "
            "server-side with content-type validation independent of client headers."
        ),
        "vuln": "include($_GET['page'] . '.php');",
        "safe": "include(ALLOWED_PAGES[$_GET['page']]);",
        "signal": r"include\(\$_GET\['page'\]",
        "references": [
            "CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program — https://cwe.mitre.org/data/definitions/98.html",
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "PHP manual: supported protocols and wrappers — https://www.php.net/manual/en/wrappers.php",
            "PHP manual: include — https://www.php.net/manual/en/function.include.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.include.php",
    },
    {
        "num": "04",
        "title": "Command and Code Injection via eval/system",
        "platform": "PHP 7.4/8.x on POSIX hosts (system/exec/shell_exec/passthru and backticks shell out via /bin/sh; disable_functions can remove them but is a deployment, not code, guard)",
        "mechanism": (
            "system(), exec(), shell_exec(), passthru(), proc_open() and the backtick "
            "operator hand the whole string to /bin/sh -c, so ; | && $() ` in a value "
            "like $host terminate the intended command and start attacker-controlled "
            "ones. eval() executes attacker text as PHP source directly. Dynamic "
            "dispatch constructs — $fn() variable functions, call_user_func with an "
            "input-derived name, and $$variable indirection — let the request choose "
            "which function runs. mail()'s fifth parameter is appended to the sendmail "
            "command line, so a crafted value such as -X/tmp/log invokes sendmail "
            "options from the request."
        ),
        "source": (
            "Request parameters interpolated into command strings, function/method "
            "names, variable variable names, or mail() additional parameters."
        ),
        "sink": (
            "system / exec / shell_exec / passthru / proc_open / backticks; eval; "
            "$fn() and call_user_func with input-derived names; mail() fifth argument"
        ),
        "guards": (
            "Require escapeshellarg() on every interpolated value (or proc_open with "
            "an argv array) so metacharacters cannot break out; require a fixed "
            "allowlist mapping input to callable names before dynamic dispatch; "
            "require mail() extra parameters to be compile-time constants."
        ),
        "not_candidate_when": (
            "The command string is entirely constant, every dynamic value passes "
            "through escapeshellarg before interpolation, dispatched function names "
            "resolve through a fixed allowlist array, or the eval target is a "
            "constant string with only numeric validated input."
        ),
        "vuln": "system('ping -c 1 ' . $host);",
        "safe": "system('ping -c 1 ' . escapeshellarg($host));",
        "signal": r"system\('ping.*\$host",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "CWE-95: Eval Injection — https://cwe.mitre.org/data/definitions/95.html",
            "PHP manual: escapeshellarg — https://www.php.net/manual/en/function.escapeshellarg.php",
            "PHP manual: eval — https://www.php.net/manual/en/function.eval.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.escapeshellarg.php",
    },
    {
        "num": "05",
        "title": "SQL Injection via mysqli/PDO String Interpolation",
        "platform": "PHP 7.4/8.x with PDO (MySQL driver emulates prepares by default: PDO::ATTR_EMULATE_PREPARES on) or mysqli",
        "mechanism": (
            "String interpolation composes the SQL text before the driver parses it, "
            "so a value containing a quote or SQL keyword is read as statement "
            "structure. PDO's MySQL driver additionally emulates prepared statements "
            "in the client by default, meaning the 'prepared' statement itself is "
            "assembled from the SQL string plus escaped values — historically "
            "exploitable when the escaping assumptions and the server sql_mode "
            "(e.g. NO_BACKSLASH_ESCAPES) disagree. Identifiers cannot be parameterized "
            "at all: ORDER BY, column and table names built by concatenation stay "
            "injection points even when values are bound."
        ),
        "source": (
            "Request parameters forming search values, sort keys, filter fields and "
            "pagination fragments passed into query text."
        ),
        "sink": (
            "$pdo->query / $pdo->exec / mysqli_query on interpolated strings; query "
            "builders receiving concatenated fragments for ORDER BY / LIMIT / column "
            "names"
        ),
        "guards": (
            "Require prepare() + execute() with bound parameters, and for MySQL "
            "require PDO::ATTR_EMULATE_PREPARES => false so prepares are real; "
            "require identifier parts to come from a fixed allowlist mapping client "
            "keys to column names; require LIMIT/OFFSET to pass through "
            "intval casting."
        ),
        "not_candidate_when": (
            "Values are bound through placeholders with server-side prepares, or the "
            "only interpolated parts are fixed allowlisted identifiers and "
            "integer-cast numbers, so no client text reaches the statement grammar."
        ),
        "vuln": "$pdo->query(\"SELECT * FROM users WHERE email = '$email'\");",
        "safe": "$stmt = $pdo->prepare(\"SELECT * FROM users WHERE email = ?\"); $stmt->execute([$email]);",
        "signal": r"\$pdo->query\(\"SELECT.*\$email",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "PHP manual: SQL injection — https://www.php.net/manual/en/security.database.sql-injection.php",
            "OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://www.php.net/manual/en/security.database.sql-injection.php",
    },
    {
        "num": "06",
        "title": "Global Variable Injection via extract() and parse_str()",
        "platform": "PHP 7.4/8.x; register_globals is gone since PHP 5.4 — extract() and one-argument parse_str() (deprecated since 7.2, still functional) are the remaining symbol-table import paths",
        "mechanism": (
            "extract() imports every array key as a variable in the current scope, and "
            "parse_str() called without a destination array registers query-string "
            "keys as local variables, so a POST body containing is_admin=1 creates "
            "$is_admin that later authorization code reads instead of application "
            "state. $_REQUEST merges GET, POST and COOKIE per the request_order ini, "
            "so a same-named GET parameter overrides a value the code believed it "
            "read from $_POST. Repeated parameters using the a[]= syntax arrive as "
            "arrays, producing type confusion where string functions are expected "
            "(strlen(array) returns NULL on PHP 7 with a warning), and "
            "$_FILES['x']['name'] is client-controlled text that stays dangerous "
            "when trusted for storage names."
        ),
        "source": (
            "Query strings, form bodies and cookies — any superglobal whose keys the "
            "attacker controls — plus multipart field names and client file names."
        ),
        "sink": (
            "extract() on superglobals; parse_str() without a destination array; "
            "security checks reading variables name-matched to request keys via "
            "$_REQUEST; code trusting $_FILES name/type fields"
        ),
        "guards": (
            "Require explicit key access ($_POST['k']) rather than symbol import; "
            "require the two-argument parse_str($s, $out) form; where extraction is "
            "unavoidable require EXTR_SKIP with a reserved prefix into a scope with "
            "no security-relevant variable names; require stored filenames to be "
            "regenerated server-side."
        ),
        "not_candidate_when": (
            "parse_str always writes into an explicit result array, extract imports "
            "into an isolated scope with EXTR_SKIP where no check variable names can "
            "collide, and upload names/paths are derived from server-side values "
            "rather than $_FILES metadata."
        ),
        "vuln": "extract($_POST); if ($is_admin) { ... }",
        "safe": "/* access $_POST['var'] explicitly */",
        "signal": r"extract\(\$_POST\)",
        "references": [
            "CWE-621: Variable Extraction Error — https://cwe.mitre.org/data/definitions/621.html",
            "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes — https://cwe.mitre.org/data/definitions/915.html",
            "PHP manual: extract — https://www.php.net/manual/en/function.extract.php",
            "PHP manual: parse_str — https://www.php.net/manual/en/function.parse-str.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.extract.php",
    },
    {
        "num": "07",
        "title": "Cross-Site Scripting via Unescaped echo",
        "platform": "PHP 7.4/8.x; htmlspecialchars escapes single quotes only with ENT_QUOTES (default flags leave them raw), and default_charset is UTF-8 since PHP 5.6 — escaping breaks when the output document charset differs",
        "mechanism": (
            "echo/print place the bytes into the HTML response verbatim, so markup "
            "in the input becomes live document structure. htmlspecialchars() with "
            "default flags escapes < > & and double quotes but not single quotes, so "
            "values landing inside single-quoted attributes (onmouseover='...') still "
            "execute; with a non-UTF-8 document charset, multi-byte sequences can "
            "consume the quote character and defeat the escaping. header('Location: "
            "'. $input) refuses to emit CR/LF since PHP 5.1.2, so the surviving "
            "defect there is the unvalidated open redirect — an attacker URL that "
            "launderes phishing and OAuth-style flows through the trusted origin."
        ),
        "source": (
            "Reflected query parameters, stored user content rendered into pages, "
            "and redirect target parameters."
        ),
        "sink": (
            "echo/print of unescaped request data; htmlspecialchars calls without "
            "ENT_QUOTES or with a charset mismatched to the document; header("
            "'Location: '.attacker_url)"
        ),
        "guards": (
            "Require htmlspecialchars($v, ENT_QUOTES, 'UTF-8') (flags explicit) for "
            "HTML body context and context-appropriate encoding elsewhere "
            "(urlencode in URLs, attribute-safe encoding in quoted attributes); "
            "require redirect targets validated against a fixed host allowlist or "
            "constrained to site-relative paths."
        ),
        "not_candidate_when": (
            "Output is escaped with ENT_QUOTES under a charset that matches the "
            "document, the response is non-HTML (JSON served with an explicit "
            "application/json Content-Type), or redirect targets are site-relative "
            "or allowlisted after validation."
        ),
        "vuln": "echo '<div class=\"comment\">' . $_GET['comment'] . '</div>';",
        "safe": "echo htmlspecialchars($_GET['comment'], ENT_QUOTES, 'UTF-8');",
        "signal": r"echo.*_GET\['comment'\]",
        "references": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html",
            "CWE-601: URL Redirection to Untrusted Site — https://cwe.mitre.org/data/definitions/601.html",
            "PHP manual: htmlspecialchars — https://www.php.net/manual/en/function.htmlspecialchars.php",
            "OWASP Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://www.php.net/manual/en/function.htmlspecialchars.php",
    },
    {
        "num": "08",
        "title": "Weak Cryptography and Deprecated Hash Functions",
        "platform": "PHP 7.4/8.x; password_hash (bcrypt/argon2) and random_bytes (CSPRNG) are available, md5/sha1 remain fast general-purpose hashes often misapplied to passwords",
        "mechanism": (
            "md5 and sha1 are unsalted and designed to be fast: after any leak of the "
            "stored digests, offline guessing runs at GPU speeds, so password "
            "digests computed with them fall to bulk cracking. password_hash applies "
            "bcrypt/argon2 with a per-hash salt and a cost factor that makes "
            "verification deliberately slow, which is what makes storage resistant. "
            "rand(), mt_rand() and uniqid() (microsecond time plus a small constant "
            "component by default) are predictable — mt_range state is recoverable "
            "from observed outputs — so tokens and reset codes drawn from them are "
            "guessable; random_bytes() draws from the CSPRNG. Comparing digests with "
            "== short-circuits at the first differing byte and leaks a timing oracle "
            "that recovers authenticators byte by byte."
        ),
        "source": (
            "Credential and token material itself: password values, session/reset "
            "tokens, API keys, MAC tags generated or compared by the application."
        ),
        "sink": (
            "md5/sha1 applied to passwords; rand/mt_rand/uniqid feeding security "
            "tokens; == / != comparisons of digests or MACs; missing "
            "session_regenerate_id() after authentication state changes"
        ),
        "guards": (
            "Require password_hash + password_verify for credentials; require "
            "random_bytes for any security token; require hash_equals for "
            "authenticator comparison; require session_regenerate_id(true) at login "
            "and privilege escalation points."
        ),
        "not_candidate_when": (
            "The fast hash digests non-secret content (file checksums, cache keys), "
            "the PRNG output feeds non-security features such as sampling or "
            "nonces for display, or the session ID is already regenerated at every "
            "privilege transition."
        ),
        "vuln": "$hash = md5($password);",
        "safe": "$hash = password_hash($password, PASSWORD_BCRYPT);",
        "signal": r"md5\(\$password\)",
        "references": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "PHP manual: password_hash — https://www.php.net/manual/en/function.password-hash.php",
            "PHP manual: random_bytes — https://www.php.net/manual/en/function.random-bytes.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.password-hash.php",
    },
    {
        "num": "09",
        "title": "XML External Entity Injection in simplexml",
        "platform": "PHP 7.4/8.x linked against libxml2; external entity loading is disabled by default in libxml2 >= 2.9, so LIBXML_NOENT mainly re-enables substitution — verify the linked libxml version before judging exploitability",
        "mechanism": (
            "Passing LIBXML_NOENT makes the parser substitute entity definitions while "
            "parsing: with libxml2 builds where external entity loading is enabled "
            "(< 2.9 behavior, or explicit flags), a DTD can declare entities that "
            "resolve to file:// or http:// targets, embedding local files into the "
            "document or issuing outbound requests. Independent of external loading, "
            "recursive entity definitions enable billion-laughs amplification that "
            "exhausts memory on one request. SoapClient fetches and parses the WSDL "
            "URL passed to its constructor, making it an SSRF primitive when that URL "
            "is request-derived, and curl honors many protocols (file://, dict://, "
            "ftp://) and follows redirects when CURLOPT_FOLLOWLOCATION is set, so a "
            "URL allowlist without CURLOPT_PROTOCOLS/CURLOPT_REDIR_PROTOCOLS pins is "
            "insufficient."
        ),
        "source": (
            "Client-posted XML documents, WSDL/endpoint URLs from requests, and "
            "outbound fetch URLs."
        ),
        "sink": (
            "simplexml_load_string / DOMDocument::loadXML with LIBXML_NOENT; SoapClient "
            "constructed with an input URL; curl transfers with input URLs and "
            "unrestricted protocol/redirect options"
        ),
        "guards": (
            "Require that untrusted XML is parsed without LIBXML_NOENT (keep "
            "LIBXML_NONET, restrict DTD processing) and check the linked libxml2 "
            "version; require SoapClient URLs to come from configuration; require "
            "curl with CURLOPT_PROTOCOLS limited to https/http and "
            "CURLOPT_REDIR_PROTOCOLS set before any redirect following."
        ),
        "not_candidate_when": (
            "The XML originates from trusted internal producers that emit no DTDs and "
            "LIBXML_NOENT is absent, the linked libxml2 is >= 2.9 with external "
            "loading disabled and expansion depth is bounded, or curl targets are "
            "allowlisted https hosts with protocols and redirects pinned by option."
        ),
        "vuln": "$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);",
        "safe": "$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NONET);",
        "signal": r"simplexml_load_string\(.*LIBXML_NOENT",
        "references": [
            "CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html",
            "CWE-776: Improper Restriction of Recursive Entity References in DTDs — https://cwe.mitre.org/data/definitions/776.html",
            "CWE-918: Server-Side Request Forgery (SSRF) — https://cwe.mitre.org/data/definitions/918.html",
            "PHP manual: simplexml_load_string — https://www.php.net/manual/en/function.simplexml-load-string.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.simplexml-load-string.php",
    },
    {
        "num": "10",
        "title": "strpos False vs Zero Comparison Hazard",
        "platform": "PHP 7.4/8.x; preg_match returns false instead of 0 when pcre.backtracking_limit (default 1,000,000) is exceeded",
        "mechanism": (
            "strpos() returns the match offset — 0 for a prefix match — and false when "
            "there is none; because 0 == false under loose comparison, "
            "if (strpos($url, $prefix) == false) treats the exactly-matching "
            "attacker-chosen input as a failure while accepting everything else, "
            "inverting the check. Similar quirks compose into fail-open gates: @ "
            "suppresses the error from a failed call so execution continues on an "
            "invalid value, intval()/(int) stop at the first non-digit ('123abc' "
            "becomes 123), and is_numeric accepts exponential notation ('1e3'). "
            "preg_match returns false — not 0 — when the backtrack limit is hit, so "
            "an adversarial subject makes a validator's return indistinguishable "
            "from 'no match' unless the caller compares === 1, and a pattern "
            "ending in $ still matches before a trailing newline because $ anchors "
            "to the end-or-before-final-newline position."
        ),
        "source": (
            "Any attacker-controlled scalar flowing into these idioms: URLs validated "
            "by strpos prefixes, filter inputs validated by preg_match, numeric "
            "strings passed through (int)/is_numeric."
        ),
        "sink": (
            "Loose == / != tests of strpos results on security gates; @-suppressed "
            "calls whose results feed checks; (int)/intval coercion before "
            "authorization decisions; preg_match validators not compared with === 1"
        ),
        "guards": (
            "Require !== false / !== 0 three-way comparisons with explicit handling "
            "of both outcomes; require that no @ operator sits on a security-relevant "
            "call and that null/false results are handled; require preg_match(...) "
            "=== 1 with \\A...\\z anchors and explicit newline rejection; require "
            "strict type validation before numeric coercion."
        ),
        "not_candidate_when": (
            "Return values are tested with !== and both the false and 0 cases are "
            "handled explicitly with the intended meaning, @ is confined to "
            "non-security cleanup whose results are validated afterwards, or the "
            "validator anchors with \\A/\\z, rejects trailing newlines, and compares "
            "preg_match results with === 1."
        ),
        "vuln": "if (strpos($url, 'https://example.com') == false) { reject(); }",
        "safe": "if (strpos($url, 'https://example.com') !== 0) { reject(); }",
        "signal": r"strpos\(.*==\s*false",
        "references": [
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
            "CWE-252: Unchecked Return Value — https://cwe.mitre.org/data/definitions/252.html",
            "PHP manual: strpos — https://www.php.net/manual/en/function.strpos.php",
            "PHP manual: preg_match — https://www.php.net/manual/en/function.preg-match.php",
        ],
        "doc_url": "https://www.php.net/manual/en/function.strpos.php",
    },
]
