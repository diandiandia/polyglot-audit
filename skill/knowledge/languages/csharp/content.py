"""Substantive per-card content for the C# knowledge cards (csharp-01..csharp-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, Microsoft/official .NET documentation, OWASP).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (C# section).
"""

LANGUAGE = {
    "name": "C#",
    "prefix": "csharp",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsafe Deserialization via BinaryFormatter",
        "platform": ".NET Framework 4.x and modern .NET; BinaryFormatter is obsolete and throws by default in .NET 5+ unless explicitly re-enabled, and is disabled outright in .NET 8+",
        "mechanism": (
            "BinaryFormatter.Deserialize reads the .NET Remoting binary format, resolves "
            "the types named inside the payload through the loaded assemblies, "
            "instantiates them without running normal constructors, and invokes "
            "deserialization callbacks (OnDeserialization, ISerializable constructors). "
            "An attacker who controls the stream therefore only needs to name a gadget "
            "type reachable in the process (or in any loaded library) whose callbacks "
            "lead to Process.Start, delegate invocation, or file/system access; the "
            "deserializer executes them itself. Microsoft's guidance is that a "
            "SerializationBinder alone is not a security boundary and the only real "
            "fix is to stop using BinaryFormatter for untrusted data."
        ),
        "source": (
            "View-state/session blobs, cache files, IPC or named-pipe payloads, "
            "message-queue bodies, and any stream an attacker can write that is later "
            "deserialized in-process."
        ),
        "sink": (
            "BinaryFormatter.Deserialize / UnsafeDeserialize on attacker-influenced "
            "streams; NetDataContractSerializer and LosFormatter with the same payload "
            "shapes; JSON/XML deserializers configured with a type-resolution callback"
        ),
        "guards": (
            "Check the payload format: a data-only deserializer "
            "(System.Text.Json / XmlSerializer over a fixed type) is the guard; a "
            "SerializationBinder or assembly allowlist is explicitly not sufficient "
            "per Microsoft's BinaryFormatter security guide. Verify any legacy "
            "BinaryFormatter call is unreachable from input and that EnableUnsafeBinary"
            "FormatterSerialization is not flipped on in project settings."
        ),
        "not_candidate_when": (
            "The stream is produced and consumed inside one trust domain with no "
            "network/shared-storage exposure, the payload is protected by an "
            "authenticated-encryption envelope whose key the attacker cannot read "
            "(verified before Deserialize), or deserialization uses a fixed concrete "
            "type with a data-only serializer and no type resolution from the stream."
        ),
        "vuln": "BinaryFormatter bf = new BinaryFormatter(); object o = bf.Deserialize(stream);",
        "safe": "JsonSerializer.Deserialize<SafeModel>(stream);",
        "signal": r"BinaryFormatter.*Deserialize\(",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "Microsoft: BinaryFormatter security guide (migration and risk) — https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide",
    },
    {
        "num": "02",
        "title": "SQL Injection via ADO.NET String Interpolation",
        "platform": ".NET Framework 4.x and modern .NET with ADO.NET providers (SqlClient, Npgsql, MySqlConnector, Microsoft.Data.Sqlite)",
        "mechanism": (
            "The ADO.NET parameter mechanism (SqlParameterCollection) ships values to "
            "the server out-of-band so they can never alter statement structure. C# "
            "string interpolation ($\"...\", concatenation, string.Format) composes the "
            "user value into CommandText before the provider parses it, so a single "
            "quote or SQL token inside the value is interpreted as statement syntax. "
            "The same flaw reaches raw-SQL helpers of ORMs and any SqlCommand built "
            "from an interpolated string, including stored-procedure invocation "
            "through Exec/EXECUTE composed at runtime."
        ),
        "source": (
            "Request route/query/body fields, filter and sort names from the client, "
            "and any value concatenated into CommandText."
        ),
        "sink": (
            "SqlCommand / NpgsqlCommand.CommandText (or the provider's raw-SQL API) "
            "assigned from an interpolated or concatenated string, then ExecuteReader/"
            "ExecuteNonQuery/ExecuteScalar"
        ),
        "guards": (
            "Verify every dynamic value travels as a SqlParameter with @name "
            "placeholders in the text (AddWithValue or explicit SqlParameter objects); "
            "for identifiers that cannot be parameterized (column names, sort "
            "direction) require an allowlist dictionary mapping client keys to fixed "
            "SQL fragments rather than quoting the client string."
        ),
        "not_candidate_when": (
            "All values bind through SqlParameter objects, the only interpolated "
            "fragments come from a fixed server-side mapping (never raw client text), "
            "or the CommandText is a compile-time constant with parameters."
        ),
        "vuln": "SqlCommand cmd = new SqlCommand($\"SELECT * FROM Users WHERE Name = '{name}'\");",
        "safe": "SqlCommand cmd = new SqlCommand(\"SELECT * FROM Users WHERE Name = @name\"); cmd.Parameters.AddWithValue(\"@name\", name);",
        "signal": r"SqlCommand.*SELECT.*\{name\}",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "Microsoft: SqlCommand class (parameters) — https://learn.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand",
            "OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand",
    },
    {
        "num": "03",
        "title": "XML External Entity (XXE) and Insecure DTD",
        "platform": ".NET Framework 4.x resolves external entities by default (XmlUrlResolver); modern .NET (Core) defaults to no resolver — the card applies to .NET Framework defaults and to any reader explicitly configured with DtdProcessing.Parse or an XmlResolver on either runtime",
        "mechanism": (
            "XmlDocument.Load and XmlTextReader construct an underlying reader whose "
            "DtdProcessing and XmlResolver decide whether DTDs are parsed and whether "
            "external entities are fetched. On .NET Framework the default XmlResolver "
            "is XmlUrlResolver, so an entity pointing at file:/// or http:// targets "
            "reads local files or performs SSRF and the result is echoed back when the "
            "parser expands it into content. Even with external resolution off, "
            "DtdProcessing.Parse still permits recursive internal entities (billion "
            "laughs) that exhaust memory; XslCompiledTransform compiled with "
            "enableScript=true additionally runs embedded C# inside transforms."
        ),
        "source": (
            "XML documents received from clients: SOAP bodies, SAML or integration "
            "payloads, uploaded configuration files, webhooks posting XML."
        ),
        "sink": (
            "XmlDocument.Load/LoadXml, XmlTextReader/XmlReader created with "
            "DtdProcessing.Parse or a non-null XmlResolver, XslCompiledTransform.Load "
            "with enableScript=true, all fed untrusted XML"
        ),
        "guards": (
            "Check the reader settings that reach the parse: DtdProcessing.Prohibit (or "
            "Ignore) and XmlResolver = null on every XmlReaderSettings used for "
            "untrusted documents; on .NET Framework confirm no "
            "XmlDocument.XmlResolver = new XmlUrlResolver() re-enables resolution; "
            "confirm XSLT does not enable script."
        ),
        "not_candidate_when": (
            "The XML comes from a trusted internal producer and DTDs are absent by "
            "construction, the reader runs with DtdProcessing.Prohibit and a null "
            "resolver on both runtimes, or the payload is envelope-verified (signed "
            "SAML with strict schema validation) before parsing."
        ),
        "vuln": "XmlDocument doc = new XmlDocument(); doc.Load(xmlStream);",
        "safe": "XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };",
        "signal": r"doc\.Load\(xmlStream\)",
        "references": [
            "CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html",
            "CWE-776: Improper Restriction of Recursive Entity References in DTDs — https://cwe.mitre.org/data/definitions/776.html",
            "OWASP XML External Entity Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "04",
        "title": "Process and Dynamic Assembly Execution",
        "platform": ".NET Framework 4.x and modern .NET (UseShellExecute semantics differ: shell-resolved on Windows when true, exec-family style when false)",
        "mechanism": (
            "Process.Start with UseShellExecute=true hands the arguments to the OS "
            "shell (cmd.exe / Explorer), so metacharacters and additional commands "
            "inside an interpolated argument are executed by the shell rather than "
            "passed as data to the target program; even with UseShellExecute=false an "
            "argument beginning with '-' becomes an option of the spawned tool. The "
            "dynamic-execution family has a second axis: Assembly.Load and "
            "Type.GetType(name) followed by reflection (Activator.CreateInstance, "
            "MethodInfo.Invoke) turn an attacker-supplied type or assembly name into "
            "arbitrary object construction and method invocation inside the process."
        ),
        "source": (
            "Request fields used as command arguments, tool names, file paths passed "
            "to helper executables, and attacker-influenced type/assembly names "
            "resolved via reflection or plugin loading."
        ),
        "sink": (
            "Process.Start(ProcessStartInfo with UseShellExecute=true) or interpolated "
            "arguments; Assembly.Load / Assembly.LoadFrom with dynamic names; "
            "Type.GetType plus Activator.CreateInstance / MethodInfo.Invoke"
        ),
        "guards": (
            "Require a fixed executable path with UseShellExecute=false and each "
            "dynamic value as a separate element of ArgumentList; verify values that "
            "could start with '-' are passed after '--' or rejected; for reflection, "
            "require an allowlist of type/assembly names resolved from a fixed mapping "
            "instead of from input."
        ),
        "not_candidate_when": (
            "The executable path is constant, UseShellExecute is false, and dynamic "
            "values travel as single ArgumentList elements to a tool with no option "
            "parsing; reflection targets come from a compiled-in allowlist; or the "
            "argument is validated against a strict grammar that cannot introduce "
            "shell syntax or option characters."
        ),
        "vuln": "Process.Start(new ProcessStartInfo(\"cmd.exe\", \"/c \" + userInput) { UseShellExecute = true });",
        "safe": "Process.Start(\"trusted.exe\", new[] { userInput });",
        "signal": r"Process\.Start\(.*UseShellExecute",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-88: Argument Injection or Modification — https://cwe.mitre.org/data/definitions/88.html",
            "CWE-470: Use of Externally-Controlled Input to Select Classes or Code — https://cwe.mitre.org/data/definitions/470.html",
            "Microsoft: Process.Start — https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start",
    },
    {
        "num": "05",
        "title": "Path Traversal via Path.Combine Absolute Override",
        "platform": ".NET Framework 4.x and modern .NET; behavior identical on Windows and Unix apart from drive-letter/root syntax",
        "mechanism": (
            "Path.Combine is a string joiner with one documented trap: if the second "
            "argument is rooted (an absolute path like /etc/passwd or C:\\Windows\\x, "
            "or even a drive-relative \\\\path), Combine returns the second argument "
            "unchanged and the base directory is silently discarded. '..', '.', and "
            "reserved-device names pass through untouched, so a single Combine never "
            "confines the result to the base; File.Open/StreamReader then operate on "
            "an attacker-chosen path. Archive extraction (ZipArchiveEntry.FullName) "
            "reintroduces the same shape because entry names may carry '..' or rooted "
            "paths that Combine happily accepts."
        ),
        "source": (
            "Uploaded filenames, archive entry FullName values, download/path "
            "parameters, and any path component derived from a request."
        ),
        "sink": (
            "Path.Combine(baseDir, attackerPath) whose result feeds File/Directory/"
            "StreamReader APIs; ZipFile.ExtractToFile(entry, Path.Combine(dest, entry."
            "FullName)) on untrusted archives"
        ),
        "guards": (
            "Check for Path.GetFileName (or GetFullPath with a containment test) "
            "before Combine, and require the full-path containment check: "
            "Path.GetFullPath(candidate) must start with the base's GetFullPath plus "
            "the directory separator; for archives require entry-name validation that "
            "rejects rooted names and '..' segments before ExtractToFile."
        ),
        "not_candidate_when": (
            "The path component is generated server-side (GUID or sequence number), "
            "GetFileName strips directories and the GetFullPath containment check "
            "rejects escapes, or archive entries are validated/rejected for rooted "
            "and '..' names before extraction."
        ),
        "vuln": "string path = Path.Combine(\"/base/dir\", userPath);",
        "safe": "string clean = Path.GetFileName(userPath); string path = Path.Combine(\"/base/dir\", clean);",
        "signal": r"Path\.Combine\(\"/base/dir\"",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "Microsoft: Path.Combine remarks — https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine",
    },
    {
        "num": "06",
        "title": "ASP.NET Over-Posting and Mass Assignment",
        "platform": "ASP.NET Core and ASP.NET (MVC/API) model binding; applies where request data is bound directly to domain objects",
        "mechanism": (
            "The model binder enumerates every public settable property whose name "
            "matches a form-field, route, or query key and assigns the supplied value, "
            "regardless of what the UI sends. Binding directly to a domain/EF entity "
            "lets an attacker add isadmin=true or rowversion fields to an ordinary "
            "form post and promote or corrupt records; the same shape appears when a "
            "controller accepts the entity type and passes it straight to "
            "DbContext.Update. Authorization/antiforgery filters declared on a base "
            "class are silently not inherited when overridden, so a controller that "
            "re-declares its own attributes can drop protections without any diff at "
            "the action level."
        ),
        "source": (
            "Form bodies, query strings, route values, and JSON bodies whose keys the "
            "attacker chooses (the request itself)."
        ),
        "sink": (
            "Action parameters bound directly to entity types ([FromForm] User entity, "
            "User entity) followed by DbContext.Add/Update or direct persistence; "
            "controller classes whose [Authorize]/[ValidateAntiForgeryToken] attributes "
            "are re-declared and thereby overridden"
        ),
        "guards": (
            "Check the bound model is a narrow DTO containing only editable fields "
            "(plus [Bind] attribute inclusion lists on legacy MVC); check the service "
            "layer maps DTO to entity field-by-field; check that authorization and "
            "antiforgery attributes exist on the concrete controller/action actually "
            "reached, not only on a base class."
        ),
        "not_candidate_when": (
            "The action binds a DTO without sensitive setters, an explicit [Bind] "
            "include list excludes security-relevant properties, the service layer "
            "copies only whitelisted fields onto the persisted entity, or the field "
            "the attacker could set is recomputed server-side before saving."
        ),
        "vuln": "public IActionResult Update([FromForm] User entity) { _db.Users.Update(entity); }",
        "safe": "public IActionResult Update([FromForm] UserUpdateDto dto) { _service.Update(dto); }",
        "signal": r"\[FromForm\]\s*User\s+entity",
        "references": [
            "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes — https://cwe.mitre.org/data/definitions/915.html",
            "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
        ],
    },
    {
        "num": "07",
        "title": "Raw HTML Output Leading to XSS",
        "platform": "ASP.NET (MVC/Razor) and Blazor; applies to any view engine with Razor-style auto-encoding plus explicit opt-out APIs",
        "mechanism": (
            "Razor encodes every emitted expression unless the developer marks the "
            "string as trusted. Html.Raw (Razor), HtmlString/MarkupString, and "
            "IHtmlContent-typed properties short-circuit that encoder, so markup in "
            "the string is parsed as HTML by the browser; a stored value containing "
            "<script> or an event-handler attribute therefore executes in every "
            "victim's session. The encoded-opt-out also covers attribute and "
            "javascript:-URL positions the default encoder does not reach when the "
            "value is already an IHtmlContent."
        ),
        "source": (
            "Stored user content (bios, comments, rich-text fields), request "
            "parameters echoed back, and any third-party HTML accepted into the "
            "content pipeline."
        ),
        "sink": (
            "@Html.Raw(...), new HtmlString(...), [MarkupString]-decorated Blazor "
            "fields, and direct @model-to-IHtmlContent assignments rendered into a page"
        ),
        "guards": (
            "Check whether the raw-markup path runs untrusted content through a "
            "sanitizer with an allowlist policy before rendering; check the content "
            "is produced by the server from fixed templates rather than user text; "
            "in attribute and URL positions require scheme validation (http/https "
            "only) even for trusted fragments."
        ),
        "not_candidate_when": (
            "The string is server-generated markup from a fixed template with no "
            "user-derived fragment, an allowlist sanitizer (with a hardened policy) "
            "processes the content before Raw, or the field only ever holds values "
            "written by trusted administrators within a trusted-content model."
        ),
        "vuln": "@Html.Raw(Model.UserBio)",
        "safe": "@Html.DisplayFor(m => m.UserBio)",
        "signal": r"Html\.Raw\(Model\.UserBio\)",
        "references": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html",
            "OWASP Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "08",
        "title": "Cryptography and Randomness Misuse",
        "platform": ".NET Framework 4.x and modern .NET; CryptographicOperations.FixedTimeEquals requires .NET Core 2.1+",
        "mechanism": (
            "System.Random is a time-seeded subtractive generator whose outputs reveal "
            "enough internal state to predict future draws, so tokens, reset codes, or "
            "keys taken from rnd.Next() are guessable from a handful of observed "
            "values. CipherMode defaults and hand-rolled parameters reintroduce "
            "classical breaks: ECB leaks equality of plaintext blocks, a fixed IV with "
            "CBC makes the first block deterministic for identical inputs, and "
            "certificate-validation callbacks that return true ("
            "RemoteCertificateValidationCallback / ServerCertificateValidationCallback) "
            "switch TLS into accept-anything mode. Comparing MACs or digests with == "
            "compares byte arrays via looped equality, leaking a timing oracle that "
            "recovers authenticator bytes."
        ),
        "source": (
            "The security value itself: session tokens, password reset codes, API "
            "keys, MAC tags, and the crypto parameters (mode, IV, callbacks) chosen "
            "in code."
        ),
        "sink": (
            "new Random() feeding security values; Aes/DESCryptoServiceProvider "
            "configured with CipherMode.ECB or a constant IV; certificate-validation "
            "callbacks that return true; == / SequenceEqual on digests or MACs"
        ),
        "guards": (
            "Require RandomNumberGenerator.GetBytes for any security value; require "
            "CipherMode.CBC/GCM with a random per-message IV from RNGCryptoServiceProvider "
            "(or AesGcm); require validation callbacks to inspect the certificate and "
            "ssl policy errors rather than returning true unconditionally; require "
            "CryptographicOperations.FixedTimeEquals for authenticator comparison."
        ),
        "not_candidate_when": (
            "Random is confined to non-security uses (sampling, jitter, simulations), "
            "ECB/fixed-IV applies only to non-secret, non-repeating data with no "
            "confidentiality requirement, the callback's unconditional-true branch is "
            "gated to a documented test environment, or comparison already uses "
            "FixedTimeEquals."
        ),
        "vuln": "Random rnd = new Random(); string token = rnd.Next().ToString();",
        "safe": "byte[] token = RandomNumberGenerator.GetBytes(32);",
        "signal": r"new\s+Random\(\);.*rnd\.Next\(",
        "references": [
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "CWE-295: Improper Certificate Validation — https://cwe.mitre.org/data/definitions/295.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "Microsoft: RandomNumberGenerator — https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator",
    },
    {
        "num": "09",
        "title": "Unsafe Code and Span Memory Boundary Violations",
        "platform": ".NET Framework 4.x and modern .NET; stackalloc in nested expressions requires C# 8+ / .NET Core, where the runtime may fall back to heap allocation",
        "mechanism": (
            "stackalloc allocates on the current thread's stack (about 1 MB by "
            "default); a length taken from input can push the stack pointer past the "
            "thread stack limit, and StackOverflowException is unrecoverable — the "
            "process dies with no catch handler. unsafe blocks plus pointers, "
            "Marshal.Copy/PtrToStructure with a length or size that does not match the "
            "real buffer, and reinterpretation of struct layouts through Marshal."
            "StructureToPtr corrupt adjacent memory when the declared and actual sizes "
            "disagree; a Span<T> built over an external buffer also outlives its "
            "owner's lifetime silently."
        ),
        "source": (
            "Request-declared lengths (Content-Length, protocol size fields), record "
            "sizes from binary payloads, and buffer sizes chosen from deserialized data."
        ),
        "sink": (
            "stackalloc byte[userLength] (or stackalloc Span with input length); "
            "Marshal.Copy/Marshal.PtrToStructure with input-derived counts; pointer "
            "arithmetic inside unsafe blocks over externally sized buffers"
        ),
        "guards": (
            "Check every input-derived stackalloc length is clamped to a small fixed "
            "constant (or replaced by a pooled heap allocation); check Marshal "
            "operations use sizes derived from Marshal.SizeOf<T> of the same type and "
            "lengths validated against the real buffer; check unsafe blocks are "
            "confined to reviewed helpers rather than request paths."
        ),
        "not_candidate_when": (
            "The stackalloc length is a compile-time constant or clamped to a small "
            "constant before allocation, the buffer length is bounded by the transport "
            "below the stack limit before the call, or the Marshal size comes from "
            "Marshal.SizeOf<T>() on the identical type being copied."
        ),
        "vuln": "Span<byte> buffer = stackalloc byte[userLength];",
        "safe": "byte[] buffer = new byte[Math.Min(userLength, 4096)];",
        "signal": r"stackalloc\s+byte\[userLength\]",
        "references": [
            "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer — https://cwe.mitre.org/data/definitions/119.html",
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "Microsoft: stackalloc operator — https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/stackalloc",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/stackalloc",
    },
    {
        "num": "10",
        "title": "Resource Exhaustion and Asynchronous Traps",
        "platform": ".NET Framework 4.x and modern .NET; Regex match timeout is opt-in per instance or app-domain wide",
        "mechanism": (
            "The .NET regex engine backtracks without any internal time limit unless a "
            "timeout is supplied, so one crafted subject against a nested-quantifier "
            "pattern pins a CPU core indefinitely inside Match/IsMatch/Replace. "
            "Unbounded request bodies and collection growth allocate server memory "
            "until OOM; async void methods route exceptions to the synchronously-"
            "invoked context where they crash the process unobserved; and C# defaults "
            "to unchecked integer arithmetic, so an overflow silently wraps a length "
            "or limit to a small value that then passes a downstream bounds check."
        ),
        "source": (
            "Request bodies, query-string values fed to regexes, uploaded collections, "
            "and arithmetic operands derived from request-declared sizes."
        ),
        "sink": (
            "Regex.Match/IsMatch/Replace on instances without a matchTimeout; reads "
            "and collections grown from request data with no cap; async void handlers "
            "on request paths; checked-arithmetic-free comparisons guarding sizes"
        ),
        "guards": (
            "Require Regex instances over untrusted input to carry a timeout (the "
            "TimeSpan constructor overload or Regex.MatchTimeout app-wide setting); "
            "require body/length caps before parsing; require async Task instead of "
            "async void on request handlers; require checked arithmetic or explicit "
            "range checks on security-relevant sizes."
        ),
        "not_candidate_when": (
            "The pattern is a constant without nested quantifiers and the subject is "
            "length-capped, the regex carries an explicit match timeout, request size "
            "limits are enforced by the platform before the code runs, or the async "
            "void is a UI event handler outside request processing."
        ),
        "vuln": "Regex reg = new Regex(pattern); reg.Match(input);",
        "safe": "Regex reg = new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1));",
        "signal": r"new\s+Regex\(pattern\);",
        "references": [
            "CWE-1333: Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html",
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "Microsoft: Regex.MatchTimeout — https://learn.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.matchtimeout",
        ],
        "doc_url": "https://learn.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.matchtimeout",
    },
]
