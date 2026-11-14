"""Substantive per-card content for the Go knowledge cards (go-01..go-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, pkg.go.dev standard-library documentation, OWASP).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Go section).
"""

LANGUAGE = {
    "name": "Go",
    "prefix": "go",
}

CARDS = [
    {
        "num": "01",
        "title": "Data Race on Unsynchronized Shared Maps",
        "platform": "Go 1.x standard library; applies to all build targets (race detector requires -race builds)",
        "mechanism": (
            "The Go runtime deliberately detects concurrent writes to a built-in map "
            "and aborts the process with 'fatal error: concurrent map writes' — not a "
            "recoverable panic — so one unsynchronized map access in a goroutine takes "
            "down the whole service. Beyond the crash, the Go memory model guarantees "
            "nothing for unsynchronized access: a goroutine that reads a flag another "
            "goroutine wrote without a happens-before edge (channel, mutex, atomic) "
            "may observe a stale or zero value, so a security check performed by one "
            "goroutine and a privileged action performed by another can interleave "
            "into a check-then-act race. Closures capturing the loop variable "
            "(pre-Go 1.22 per-loop variable semantics) additionally make every "
            "spawned goroutine observe the same final iteration value."
        ),
        "source": (
            "Concurrent request handlers, background workers, and callbacks sharing "
            "maps, flags, or captured loop variables without synchronization."
        ),
        "sink": (
            "go func() { ... m[key] = val }() on a built-in map; unsynchronized reads "
            "of shared state guarding authorization or session decisions; check-"
            "then-act sequences split across goroutines"
        ),
        "guards": (
            "Check that shared maps are either replaced by sync.Map or confined behind "
            "a sync.Mutex/RWMutex taken on both read and write paths; check "
            "cross-goroutine security decisions use channels or sync/atomic with a "
            "happens-before edge; run -race builds in CI to observe actual races "
            "rather than reasoning about them."
        ),
        "not_candidate_when": (
            "The map is confined to a single goroutine and other goroutines communicate "
            "only via channels ('share memory by communicating'), every access path "
            "holds the same mutex, the variable is captured per-iteration on Go 1.22+ "
            "or via an explicit parameter, or the shared value is immutable after "
            "publication with a proper happens-before edge."
        ),
        "vuln": "go func() { m[key] = val }()",
        "safe": "var mu sync.Mutex; mu.Lock(); m[key] = val; mu.Unlock()",
        "signal": r"go\s+func\(\)\s*\{\s*m\[key\]",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') — https://cwe.mitre.org/data/definitions/362.html",
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "Go Memory Model — https://go.dev/ref/mem",
            "Go standard library: sync — https://pkg.go.dev/sync",
        ],
        "doc_url": "https://go.dev/ref/mem",
    },
    {
        "num": "02",
        "title": "Ignored Error Leading to Fail-Open Authorization",
        "platform": "Go 1.x standard library; applies to all build targets",
        "mechanism": (
            "Go surfaces failures as values, and the zero value of a bool/struct is "
            "indistinguishable in syntax from a legitimate result. Discarding err with "
            "_ (or shadowing it with := in an inner scope) leaves the zero value in "
            "the variable that the security decision then consumes: verifyToken's "
            "(valid, err) becomes valid=false on error, but the same pattern with an "
            "inverted convention (err-only helpers returning a session struct) yields "
            "an empty-but-non-nil value that downstream code treats as authenticated. "
            "Error shadowing across a function boundary means a later assignment can "
            "overwrite the failure before it is checked, so the review must trace the "
            "specific variable instance."
        ),
        "source": (
            "Authentication, signature verification, certificate validation, and "
            "permission-check calls whose error results are discarded or shadowed."
        ),
        "sink": (
            "valid, _ := verifyToken(token); err := ... with := re-declaration "
            "shadowing an outer err; if err == nil checks placed after the variable "
            "was reassigned; authorization flows that treat a zero-value session or "
            "claims struct as valid"
        ),
        "guards": (
            "Check the specific failure path: on verification error the code must "
            "return/deny, not fall through to a zero value; check for := shadowing of "
            "err inside if/for blocks whose scope reaches the security decision; check "
            "that errors are compared with errors.Is/!= nil before any use of the "
            "paired result."
        ),
        "not_candidate_when": (
            "Every error from the verification call is checked with != nil and the "
            "handler returns before using the result, the discarded error comes from a "
            "call whose failure cannot affect the decision (e.g. closing an already-"
            "closed resource on a non-security path), or the shadowed variable is a "
            "distinct local that never feeds the authorization outcome."
        ),
        "vuln": "valid, _ := verifyToken(token); if valid { grantAccess() }",
        "safe": "valid, err := verifyToken(token); if err != nil || !valid { return false }; grantAccess()",
        "signal": r"valid,\s*_\s*:=\s*verifyToken\(token\)",
        "references": [
            "CWE-252: Unchecked Return Value — https://cwe.mitre.org/data/definitions/252.html",
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "Go standard library: errors — https://pkg.go.dev/errors",
        ],
        "doc_url": "https://pkg.go.dev/errors",
    },
    {
        "num": "03",
        "title": "Untrusted Input Triggering Nil Panic in Shared Service",
        "platform": "Go 1.x standard library; applies to all build targets (net/http recovers handler panics, but panics in user-spawned goroutines and non-net/http servers terminate the process)",
        "mechanism": (
            "A failed type assertion without the ok form (x := v.(T)) panics; a write "
            "to a nil map panics; a nil pointer dereference panics. Unlike exceptions, "
            "a panic crosses goroutine boundaries unrecovered: net/http recovers "
            "panics inside its own handler goroutine, but any panic in a goroutine the "
            "handler spawned, or in a non-net/http service loop (custom TCP servers, "
            "gRPC streaming handlers), terminates the whole process. Because the "
            "input comes from the request, one malformed payload becomes a remote "
            "kill switch for every in-flight request."
        ),
        "source": (
            "Request bodies, headers, and decoded JSON/interface{} fields whose type "
            "or presence the client controls; missing fields decoded as nil."
        ),
        "sink": (
            "val := req.Body.(string) style single-value type assertions; writes to "
            "possibly-nil maps; index/slice expressions over untrusted indexes; "
            "goroutines spawned inside request handling without a recover"
        ),
        "guards": (
            "Require the comma-ok assertion form (v, ok := x.(T)) with an explicit "
            "ok check before use; require nil-map initialization before writes; "
            "require untrusted-index bounds checks or get-with-ok accessors; require "
            "either a recover in every spawned goroutine or no goroutines on request "
            "paths that process untrusted data."
        ),
        "not_candidate_when": (
            "All assertions on untrusted values use the comma-ok form, the map is "
            "proven non-nil at write sites (initialized in the same function), the "
            "server recovers panics around every goroutine it spawns, or the value's "
            "type is guaranteed by an upstream decode into a concrete struct."
        ),
        "vuln": "val := req.Body.(string)",
        "safe": "val, ok := req.Body.(string); if !ok { return nil, errors.New(\"invalid\") }",
        "signal": r"req\.Body\.\(string\)",
        "references": [
            "CWE-755: Improper Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/755.html",
            "CWE-476: NULL Pointer Dereference — https://cwe.mitre.org/data/definitions/476.html",
            "Go standard library: builtin (type assertions, panic) — https://pkg.go.dev/builtin",
        ],
        "doc_url": "https://pkg.go.dev/builtin",
    },
    {
        "num": "04",
        "title": "Integer Conversion Truncation in Boundary Checks",
        "platform": "Go 1.x standard library; applies to all build targets (untyped constant conversions are compile-time checked, variable conversions are not)",
        "mechanism": (
            "strconv.Atoi returns int (64-bit on mainstream platforms); converting "
            "that result to int16 or int32 silently keeps only the low bits, so "
            "32768 becomes -32768 and a negative-injected value flips sign. The check "
            "the developer wrote runs on the pre-conversion value, while the "
            "allocation or index uses the truncated one, so the guard and the use "
            "disagree. The same shape appears when len() (int) is compared against or "
            "converted to uint types — a negative-to-unsigned conversion produces a "
            "huge value that passes 'size > 0' style reasoning — and when two's-"
            "complement wraparound in an accumulator drives a bounds computation."
        ),
        "source": (
            "Numeric request fields, header values (Content-Length, protocol size "
            "fields), and IDs from query strings parsed with strconv."
        ),
        "sink": (
            "int16(idx) / int32(idx) / uint(n) conversions applied to strconv results "
            "or lengths; arithmetic on mixed int/uint operands feeding allocations, "
            "slices, or access-control comparisons"
        ),
        "guards": (
            "Require the range check to run on the value AFTER conversion (or use "
            "try-style helpers that reject out-of-range values) so the checked and "
            "used values are identical; require explicit sign checks before any "
            "unsigned conversion; prefer int throughout and reject values outside the "
            "target width via comparison instead of truncating."
        ),
        "not_candidate_when": (
            "The conversion is followed by an immediate range check on the converted "
            "value, the value was already constrained to the target range before "
            "conversion (e.g. <= 32767), or the arithmetic operates in constant-"
            "typed values that cannot exceed the target width by construction."
        ),
        "vuln": "idx, _ := strconv.Atoi(s); shortIdx := int16(idx)",
        "safe": "idx, _ := strconv.Atoi(s); if idx < 0 || idx > 32767 { return }; shortIdx := int16(idx)",
        "signal": r"shortIdx\s*:=\s*int16\(idx\)",
        "references": [
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-197: Numeric Truncation Error — https://cwe.mitre.org/data/definitions/197.html",
            "Go standard library: strconv — https://pkg.go.dev/strconv",
        ],
        "doc_url": "https://pkg.go.dev/strconv",
    },
    {
        "num": "05",
        "title": "Unbounded Resource Consumption via io.ReadAll",
        "platform": "Go 1.x standard library (net/http, io, bufio); applies to all build targets",
        "mechanism": (
            "io.ReadAll grows its buffer without limit, so a client that streams "
            "gigabytes (or lies with a small Content-Length while sending more) "
            "exhausts server memory one request at a time. http.Server with zero "
            "ReadHeaderTimeout/ReadTimeout/IdleTimeout accepts connections that never "
            "finish, enabling slowloris-style socket exhaustion; missing "
            "http.MaxBytesReader removes the platform's per-request cap. The pattern "
            "generalizes: make([]byte, n) or make([]T, n) with n from a header "
            "allocates attacker-chosen memory instantly, and goroutines or channels "
            "spawned per request with no bound leak until the process is killed."
        ),
        "source": (
            "Request bodies, declared sizes in headers or protocol fields, and the "
            "request rate itself."
        ),
        "sink": (
            "io.ReadAll(req.Body) / io/ioutil.ReadAll with no LimitReader; http.Server"
            "{...} without ReadHeaderTimeout/ReadTimeout/IdleTimeout; make([]byte, n) "
            "with n from input; per-request goroutines or channels with no bound"
        ),
        "guards": (
            "Require io.LimitReader or http.MaxBytesReader around every request-body "
            "read; require http.Server timeout fields be set; require allocation "
            "sizes be validated against fixed constants before make; require "
            "worker-pool or semaphore bounding for per-request concurrency."
        ),
        "not_candidate_when": (
            "The read is wrapped in a LimitReader/MaxBytesReader cap sized to the "
            "data's real need, the server sets all relevant http.Server timeouts, "
            "the allocation length is clamped to a constant before make, or the "
            "endpoint is internal-only behind an enforced network boundary that "
            "attacker traffic cannot reach."
        ),
        "vuln": "body, _ := io.ReadAll(req.Body)",
        "safe": "body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))",
        "signal": r"io\.ReadAll\(req\.Body\)",
        "references": [
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "CWE-770: Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html",
            "Go standard library: net/http (Server timeouts, MaxBytesReader) — https://pkg.go.dev/net/http",
            "Go standard library: io — https://pkg.go.dev/io",
        ],
        "doc_url": "https://pkg.go.dev/net/http",
    },
    {
        "num": "06",
        "title": "Command and SQL Injection via fmt.Sprintf",
        "platform": "Go 1.x standard library (os/exec, text/template, database/sql); applies to all build targets",
        "mechanism": (
            "os/exec does not invoke a shell: Command(name, args...) passes each "
            "element as one argv entry, so injection requires the developer to opt in "
            "by building a shell string (exec.Command(\"sh\", \"-c\", "
            "fmt.Sprintf(...))) or by letting an input beginning with '-' become an "
            "option of the target binary. The same confidence in fmt.Sprintf produces "
            "SQL when its output is passed to db.Query, since database/sql placeholders "
            "('?') are the only out-of-band channel. In templates, text/template never "
            "escapes and an explicit template.HTML(value) cast tells html/template to "
            "trust the value, defeating auto-escaping at exactly the attacker-"
            "controlled position."
        ),
        "source": (
            "Request parameters interpolated into shell command strings, SQL text, or "
            "template values cast to template.HTML."
        ),
        "sink": (
            "exec.Command(\"sh\", \"-c\", <formatted string>) or unguarded argv elements; "
            "db.Query/QueryRow with fmt.Sprintf-built SQL; text/template execution of "
            "user data; template.HTML(x) casts feeding html/template output"
        ),
        "guards": (
            "Require exec.Command with a fixed executable and the dynamic value as one "
            "separate argv argument (no sh -c); require SQL placeholders with args "
            "passed separately to Query/Exec; require html/template (not text/"
            "template) for HTML output and no template.HTML casts over untrusted "
            "values; require '--' or allowlist checks for values that may start with '-'."
        ),
        "not_candidate_when": (
            "The command is a constant executable with input as a single argv element "
            "and no option-parsing surface, SQL values bind through placeholders, "
            "html/template auto-escaping remains in effect with no template.HTML cast, "
            "or the interpolated fragment comes from a fixed server-side allowlist."
        ),
        "vuln": "query := fmt.Sprintf(\"SELECT * FROM items WHERE name = '%s'\", name)",
        "safe": "row := db.QueryRow(\"SELECT * FROM items WHERE name = ?\", name)",
        "signal": r"fmt\.Sprintf\(\"SELECT.*name\s*=",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements in SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "Go standard library: os/exec — https://pkg.go.dev/os/exec",
            "Go standard library: text/template — https://pkg.go.dev/text/template",
        ],
        "doc_url": "https://pkg.go.dev/os/exec",
    },
    {
        "num": "07",
        "title": "Path Traversal in Archive and File Serving",
        "platform": "Go 1.x standard library (path/filepath, net/http, archive/zip, archive/tar); applies to all build targets",
        "mechanism": (
            "filepath.Join concatenates and cleans, but Clean never removes leading "
            "'..' relative to the joined root, so Join(base, \"../../etc/passwd\") "
            "yields a path outside base; a guard written as strings.HasPrefix(clean, "
            "\"..\") on the cleaned relative path also misses encoded or absolute "
            "variants. http.Dir applies Clean and rejects '..' path elements in URL "
            "form, but it follows symlinks inside the served root, so a symlink placed "
            "there (e.g. via an upload or archive extraction earlier) escapes to "
            "arbitrary files. Archive extraction reintroduces the same flaw: zip/tar "
            "entry names with absolute paths or '..' segments (Zip Slip) escape the "
            "extraction directory unless each entry name is validated against the "
            "destination root."
        ),
        "source": (
            "File path parameters, archive entry names from uploaded zips/tars, and "
            "URL path segments reaching file-serving handlers."
        ),
        "sink": (
            "filepath.Join(baseDir, userInput) feeding os.Open/ReadFile or archive "
            "extraction targets; http.FileServer/http.Dir over directories that "
            "contain or receive attacker-influenced symlinks; zip/tar entry extraction "
            "using f.Name unvalidated"
        ),
        "guards": (
            "Require a containment check after Join: filepath.Clean then confirm the "
            "result is still within baseDir (e.g. filepath.Rel and absence of '..' or "
            "an EvalSymlinks-based prefix comparison); require archive extraction to "
            "reject entry names that are absolute, contain '..', or whose joined path "
            "escapes the destination; prefer serving from an allowlist of files."
        ),
        "not_candidate_when": (
            "The joined path is verified to remain inside baseDir after cleaning and "
            "symlink resolution, archive entries are validated against the destination "
            "root before extraction, the file list is a fixed server-side allowlist, "
            "or the path component is generated server-side (UUID) with no client "
            "input in the path."
        ),
        "vuln": "target := filepath.Join(baseDir, userInput)",
        "safe": "clean := filepath.Clean(userInput); if strings.HasPrefix(clean, \"..\") { return }; target := filepath.Join(baseDir, clean)",
        "signal": r"filepath\.Join\(baseDir,\s*userInput\)",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "Go standard library: path/filepath — https://pkg.go.dev/path/filepath",
            "Go standard library: archive/zip — https://pkg.go.dev/archive/zip",
        ],
        "doc_url": "https://pkg.go.dev/path/filepath",
    },
    {
        "num": "08",
        "title": "Unsafe and cgo Lifetime and Pointer Boundary",
        "platform": "Go 1.x standard library (unsafe, cgo via C toolchain; unsafe.String and unsafe.Slice require Go 1.20+); applies to all build targets including GOARCH-specific layouts",
        "mechanism": (
            "unsafe.String(&b[0], len(b)) builds a string header over the existing "
            "byte slice without copying: the result aliases a mutable buffer, so "
            "later writes to b change a 'constant' string (breaking map keys and "
            "interning assumptions), and if b is reallocated or escapes the pointer "
            "becomes dangling. unsafe.Slice(ptr, len) trusts the caller-supplied "
            "length entirely — a length from a C call or a decoded header yields an "
            "out-of-bounds slice the GC and bounds checker will not catch. At the cgo "
            "boundary, C code cannot keep Go pointers, buffer lengths agreed between "
            "Go and C drift apart, and the runtime's cgocheck only catches some of "
            "these classes."
        ),
        "source": (
            "Lengths and pointers from C return values, binary protocol fields, and "
            "decoded headers that reach unsafe constructors."
        ),
        "sink": (
            "unsafe.String / unsafe.Slice with input-derived pointer/length; unsafe."
            "Pointer arithmetic between Go and C buffers; reflect with unsafe.Pointer "
            "to forge values"
        ),
        "guards": (
            "Require lengths used in unsafe constructors be validated against the real "
            "allocation immediately before the call; prefer an explicit copy (string(b)) "
            "over aliasing when the bytes cross a trust boundary; at cgo boundaries "
            "check buffers are allocated on the C side or pinned (runtime.Pinner, "
            "Go 1.21+) and that both sides agree on the length contract."
        ),
        "not_candidate_when": (
            "The unsafe conversion's length comes from the same local allocation whose "
            "lifetime provably covers the use, the string is copied (string(b)) rather "
            "than aliased, the cgo buffer is allocated and sized entirely on the C "
            "side with a pinned pointer, or the code path is an isolated reviewed "
            "helper unreachable from untrusted input."
        ),
        "vuln": "str := unsafe.String(&b[0], len(b))",
        "safe": "str := string(b) // Safe copy allocation avoiding unsafe pointer escape",
        "signal": r"unsafe\.String\(",
        "references": [
            "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer — https://cwe.mitre.org/data/definitions/119.html",
            "Go standard library: unsafe — https://pkg.go.dev/unsafe",
        ],
        "doc_url": "https://pkg.go.dev/unsafe",
    },
    {
        "num": "09",
        "title": "Cryptography and TLS Insecure Configuration",
        "platform": "Go 1.x standard library (crypto/tls, crypto/subtle, math/rand); applies to all build targets",
        "mechanism": (
            "Setting tls.Config{InsecureSkipVerify: true} disables the entire "
            "certificate chain and hostname verification, turning every TLS "
            "connection into an active-MITM target; the vet linter flags it precisely "
            "because no compensating check exists in the struct. Tokens and keys "
            "drawn from math/rand are predictable: the generator is deterministic from "
            "a small seed and its outputs leak state. Comparing MACs or signatures "
            "with == leaks a timing oracle that crypto/subtle.ConstantTimeCompare "
            "exists to prevent; reusing an AEAD nonce (GCM or ChaCha20-Poly1305) with "
            "the same key collapses the cipher's security, allowing message forgery "
            "after two ciphertexts share a nonce."
        ),
        "source": (
            "TLS configurations in client/server code, security values produced by "
            "math/rand, authenticator comparisons in handlers, and nonce generation "
            "for AEAD encryption."
        ),
        "sink": (
            "tls.Config{InsecureSkipVerify: true}; math/rand/rand for keys, tokens, or "
            "nonces; == / bytes.Equal on MACs or signature digests; AES-GCM/ChaCha20 "
            "Seal calls reusing a nonce"
        ),
        "guards": (
            "Require InsecureSkipVerify be absent (or documented and compensated with "
            "a pinned fingerprint verification in VerifyPeerCertificate); require "
            "crypto/rand for security values; require subtle.ConstantTimeCompare/"
            "hmac.Equal for authenticator comparison; require nonces from a counter or "
            "crypto/rand with per-key uniqueness."
        ),
        "not_candidate_when": (
            "The skip-verify flag appears only in an explicitly labeled test fixture "
            "never executed against production peers, math/rand feeds only non-"
            "security sampling, comparison uses subtle/hmac primitives, or nonces are "
            "random per message from crypto/rand with negligible collision risk "
            "documented for the message volume."
        ),
        "vuln": "tlsConfig := &tls.Config{InsecureSkipVerify: true}",
        "safe": "tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}",
        "signal": r"InsecureSkipVerify:\s*true",
        "references": [
            "CWE-295: Improper Certificate Validation — https://cwe.mitre.org/data/definitions/295.html",
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "Go standard library: crypto/tls — https://pkg.go.dev/crypto/tls",
            "Go standard library: crypto/subtle — https://pkg.go.dev/crypto/subtle",
        ],
        "doc_url": "https://pkg.go.dev/crypto/tls",
    },
    {
        "num": "10",
        "title": "Encoding and Parser Discrepancies in JSON and URLs",
        "platform": "Go 1.x standard library (encoding/json, net/url, net/http); applies to all build targets",
        "mechanism": (
            "encoding/json matches struct field names case-insensitively when the "
            "exact name is absent, so a payload key 'isadmin' populates a field "
            "declared as isAdmin — an authorization field the API contract never "
            "exposed. Duplicate JSON keys are resolved last-wins with no error, and "
            "unknown fields are silently ignored, letting an attacker add privileged "
            "fields that a strict decoder would reject. Decoding into interface{} "
            "turns every number into float64, so 64-bit IDs above 2^53 lose precision "
            "and can collide with another resource's identifier. On the URL side, "
            "net/url parses and normalizes differently from browsers and proxies "
            "(percent-encoding, backslashes, embedded control characters), and "
            "http.Client follows redirects by default, so an allowlist checked on the "
            "first request is not enforced on the destination."
        ),
        "source": (
            "JSON request bodies, upstream API responses parsed into interface{}, and "
            "URLs from clients that pass through redirects or proxies."
        ),
        "sink": (
            "json.Unmarshal into structs holding security-relevant fields "
            "(roles/flags) without DisallowUnknownFields; numeric IDs decoded via "
            "interface{} into float64; authorization decisions on net/url-parsed "
            "values; http.Client requests that follow redirects from untrusted responses"
        ),
        "guards": (
            "Require json.Decoder with DisallowUnknownFields for payloads feeding "
            "authorization decisions, and case-sensitive field handling (renamed "
            "fields or explicit checks) for privilege-bearing names; require int64/"
            "json.Number decoding for 64-bit IDs; require redirect policy that re-"
            "applies the host allowlist per hop (CheckRedirect returning an error)."
        ),
        "not_candidate_when": (
            "The struct carries no privilege-relevant fields or unknown fields are "
            "rejected, IDs decode as exact-width integers (json.Number/int64), the "
            "redirect policy re-validates every hop, or the parsed URL host matches a "
            "fixed allowlist after canonicalization on each redirect target."
        ),
        "vuln": "json.Unmarshal(data, &adminObj)",
        "safe": "dec := json.NewDecoder(data); dec.DisallowUnknownFields(); dec.Decode(&adminObj)",
        "signal": r"json\.Unmarshal\(data,\s*&adminObj\)",
        "references": [
            "CWE-436: Interpretation Conflict — https://cwe.mitre.org/data/definitions/436.html",
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-601: URL Redirection to Untrusted Site — https://cwe.mitre.org/data/definitions/601.html",
            "Go standard library: encoding/json — https://pkg.go.dev/encoding/json",
            "Go standard library: net/url — https://pkg.go.dev/net/url",
        ],
        "doc_url": "https://pkg.go.dev/encoding/json",
    },
]
