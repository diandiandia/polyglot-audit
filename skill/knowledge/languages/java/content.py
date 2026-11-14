"""Substantive per-card content for the Java knowledge cards (java-01..java-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, Oracle JDK/Java SE documentation, OWASP).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Java section).
"""

LANGUAGE = {
    "name": "Java",
    "prefix": "java",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsafe Deserialization via ObjectInputStream",
        "platform": "Java SE 8+ standard library; applies wherever Java serialization endpoints exist (servlet apps, RMI, JMS), independent of OS",
        "mechanism": (
            "ObjectInputStream.readObject reads the class descriptor named in the "
            "stream, loads that class through the classloader, instantiates it WITHOUT "
            "running its normal constructors, and invokes its readObject/defaultReadObject/"
            "readResolve hooks. An attacker who controls the stream therefore only needs "
            "a gadget class present on the classpath whose deserialization hooks (or "
            "subsequent toString/compare/equals invocations) chain into "
            "Runtime.exec or template/EL evaluation — the deserializer executes the "
            "attacker's chosen code path itself. XMLDecoder performs an analogous "
            "reconstruction from XML expression documents, and JSON/YAML binders with "
            "polymorphic type metadata (a @class/@type property) reach the same "
            "instantiation-through-input shape."
        ),
        "source": (
            "Serialized payloads an attacker can write: HTTP cookies/parameters, RMI "
            "or JMS endpoints, session stores, uploaded files, queue messages."
        ),
        "sink": (
            "ObjectInputStream.readObject / readUnshared on attacker-influenced "
            "streams; XMLDecoder.readObject; JSON/YAML deserializers configured with "
            "polymorphic type resolution from the payload"
        ),
        "guards": (
            "Check for a look-ahead deserialization filter: JEP 290 "
            "ObjectInputFilter (or a library like a validating ObjectInputStream) "
            "with a class allowlist applied BEFORE instantiation, or replacement by a "
            "data-only format (JSON into fixed types). Note that filters must reject "
            "by default (ALLOWLIST), and a blacklist is not a guard."
        ),
        "not_candidate_when": (
            "The stream is produced and consumed inside one trust domain with no "
            "network or shared-storage exposure, an ObjectInputFilter with an explicit "
            "class allowlist is installed on the stream, or the payload is covered by "
            "an integrity check (HMAC/signature) verified before deserialization with "
            "a key the attacker cannot read."
        ),
        "vuln": "ObjectInputStream ois = new ObjectInputStream(is); Object obj = ois.readObject();",
        "safe": "ValidatingObjectInputStream vois = new ValidatingObjectInputStream(is);",
        "signal": r"ois\.readObject\(",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "Oracle: Secure Coding Guidelines for Java SE, Object Deserialization section — https://www.oracle.com/java/technologies/javase/seccodeguide.html",
            "Java SE documentation: ObjectInputStream — https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html",
    },
    {
        "num": "02",
        "title": "Expression Language and JNDI Injection",
        "platform": "Java SE 8+ standard library (javax.naming, javax.script); servlet/EL behavior assumes Java EE or Jakarta EE containers",
        "mechanism": (
            "InitialContext.lookup resolves a URL-scheme name (ldap://, rmi://, "
            "dns://) against remote directories; a JNDI endpoint the attacker chooses "
            "can return a Reference whose factory class the client loads and "
            "instantiates, turning the lookup string into remote code execution on "
            "vulnerable JDK builds and object fabrication on patched ones. "
            "Expression-Language evaluators (javax.el) and script engines "
            "(javax.script.ScriptEngine.eval, e.g. Nashorn) "
            "execute the attacker's expression with access to Java objects, method "
            "invocation and reflection included, so the string is code, not data."
        ),
        "source": (
            "Request fields reaching lookup keys, EL expressions built from user "
            "values (message templates, sorting, rules engines), and script strings "
            "handed to ScriptEngine.eval."
        ),
        "sink": (
            "InitialContext.lookup(userInput) and variants of "
            "javax.naming.Context methods; ValueExpression/ELProcessor.eval with "
            "dynamic expressions; ScriptEngine.eval on attacker-influenced strings"
        ),
        "guards": (
            "Check the lookup name against a strict scheme and path allowlist before "
            "the call, and require the JNDI client disable remote codebase loading "
            "(com.sun.jndi.ldap.object.trustURLCodebase=false, the JDK default since "
            "late 2018, plus RMI equivalents); for EL and script engines require the "
            "expression come from fixed templates with only validated values "
            "substituted."
        ),
        "not_candidate_when": (
            "The lookup name is a compile-time constant or matched against a fixed "
            "allowlist, the naming provider is local-only with remote codebase loading "
            "disabled and reference factories restricted, or the EL/script input is a "
            "validated value substituted into a constant expression, never the "
            "expression text itself."
        ),
        "vuln": "Context ctx = new InitialContext(); ctx.lookup(userInput);",
        "safe": "if (!isAllowedJndi(userInput)) throw new SecurityException(); ctx.lookup(userInput);",
        "signal": r"ctx\.lookup\(userInput\)",
        "references": [
            "CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement — https://cwe.mitre.org/data/definitions/917.html",
            "CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') — https://cwe.mitre.org/data/definitions/74.html",
            "Java SE documentation: InitialContext — https://docs.oracle.com/javase/8/docs/api/javax/naming/InitialContext.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/javax/naming/InitialContext.html",
    },
    {
        "num": "03",
        "title": "XML External Entity Processing in DocumentBuilder",
        "platform": "Java SE 8+ (JAXP); the factory defaults differ across JDK releases and container configurations, so the effective settings must be read from code",
        "mechanism": (
            "DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, and "
            "TransformerFactory are created with defaults that historically keep DTD "
            "processing and external entity resolution enabled: without an explicit "
            "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) "
            "or a null-resolver/attribute set, an attacker-supplied DOCTYPE resolves "
            "entities to file:// or http:// targets and the parser inlines the "
            "fetched content into the document (local file read, SSRF, and echoed "
            "output). Recursive internal entities produce billion-laughs memory "
            "expansion independent of external resolution. The relevant setting lives "
            "on the factory, so a secure default in one helper does not protect a "
            "second factory created elsewhere in the same application."
        ),
        "source": (
            "XML documents from clients: SOAP/REST payloads, SAML assertions, "
            "uploaded configuration and integration files, webhooks posting XML."
        ),
        "sink": (
            "DocumentBuilder.parse / SAXParser.parse / XMLStreamReader (XMLInputFactory"
            "-created) / Transformer.transform on untrusted documents where the "
            "corresponding factory lacks disallow-doctype-decl, external-general-"
            "entities, and external-parameter-entities protections"
        ),
        "guards": (
            "Check the factory configuration BEFORE parse: "
            "setFeature(disallow-doctype-decl, true) or, where DTDs are required, "
            "setFeature for external-general/parameter-entities false plus "
            "setXIncludeAware(false) and an expansion limit; verify every factory "
            "instance in the request path carries the settings, not just one."
        ),
        "not_candidate_when": (
            "Doctype declarations are prohibited on every factory handling untrusted "
            "documents, the XML comes from a trusted internal producer with no DTD by "
            "construction, or schema validation with a fixed XSD rejects documents "
            "containing DTDs before entity processing."
        ),
        "vuln": "DocumentBuilder db = dbf.newDocumentBuilder(); db.parse(stream);",
        "safe": "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
        "signal": r"db\.parse\(stream\)",
        "references": [
            "CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html",
            "CWE-776: Improper Restriction of Recursive Entity References in DTDs — https://cwe.mitre.org/data/definitions/776.html",
            "Java SE documentation: DocumentBuilderFactory — https://docs.oracle.com/javase/8/docs/api/javax/xml/parsers/DocumentBuilderFactory.html",
            "OWASP XML External Entity Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/javax/xml/parsers/DocumentBuilderFactory.html",
    },
    {
        "num": "04",
        "title": "SQL and JPQL Injection in Statement Execution",
        "platform": "Java SE 8+ (JDBC java.sql / javax.persistence JPQL); applies to any JDBC driver and JPA provider",
        "mechanism": (
            "java.sql.Statement executes the string exactly as passed, so ' + id + ' "
            "concatenation composes the value into the SQL text before the database "
            "parses it; PreparedStatement instead sends the statement and parameters "
            "separately and the driver binds them after parsing, making the boundary "
            "structural rather than escaper-dependent. JPQL/SQL via "
            "EntityManager.createQuery or createNativeQuery has the same split: "
            "named/positional parameters (:id, ?1) are bound out-of-band, while "
            "string concatenation lets a quote in the value become query syntax. "
            "ORDER BY, table, and column names cannot be parameterized anywhere, so "
            "they must come from a server-side allowlist, never from client text."
        ),
        "source": (
            "Request parameters, filter/sort field names from the client, and values "
            "concatenated into Statement or JPQL strings."
        ),
        "sink": (
            "Statement.executeQuery/executeUpdate with concatenated SQL; "
            "EntityManager.createQuery/createNativeQuery with string concatenation; "
            "any raw-SQL helper composing ORDER BY or identifier fragments from input"
        ),
        "guards": (
            "Require PreparedStatement with ? placeholders and setString/setInt "
            "(or JPA parameter binding via setParameter) for every value; require "
            "non-parameterizable identifiers be mapped through a fixed allowlist "
            "dictionary from client keys to server-side constants; treat any "
            "concatenation in the query string as a candidate."
        ),
        "not_candidate_when": (
            "All values bind through PreparedStatement or JPA parameter binding, the "
            "only concatenated fragments come from a fixed server-side mapping, or the "
            "query string is a constant and parameters carry all dynamics."
        ),
        "vuln": "stmt.executeQuery(\"SELECT * FROM accounts WHERE id = '\" + id + \"'\");",
        "safe": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM accounts WHERE id = ?\"); ps.setString(1, id);",
        "signal": r"stmt\.executeQuery\(.*SELECT",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements in SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "Oracle Java Tutorials: Using Prepared Statements — https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html",
            "OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html",
    },
    {
        "num": "05",
        "title": "Path Traversal in File Construction and Zip Extraction",
        "platform": "Java SE 8+ standard library (java.io.File, java.nio.file.Path, java.util.zip); applies on all target operating systems",
        "mechanism": (
            "new File(baseDir, child) treats an absolute child as a full path on most "
            "platforms, discarding baseDir entirely, and both File and Paths.get keep "
            "'..' segments; a 'startsWith' check on raw strings also fails because "
            "./ and encoding variants normalize to the same file. ZipEntry.getName is "
            "attacker-chosen data: entries with absolute names or '..' segments "
            "(Zip Slip) escape the extraction directory unless each entry is resolved "
            "against the destination and verified to remain inside it. "
            "File.getCanonicalPath/Path.normalize/toRealPath are the mechanisms that "
            "actually collapse these variants, which is why the containment check "
            "must run on the canonical form."
        ),
        "source": (
            "Upload filenames, archive entry names, download/path parameters, and any "
            "path component from a request."
        ),
        "sink": (
            "new File(baseDir, userInput) / Paths.get(baseDir, userInput) feeding "
            "file APIs; ZipInputStream.getNextEntry with entry.getName used as the "
            "extraction target unvalidated"
        ),
        "guards": (
            "Require the containment check on the canonical/normalized path: "
            "baseDir.toAbsolutePath().normalize() must be a prefix of "
            "candidate.normalize() (or toRealPath for symlink-aware checks) before any "
            "file API is called; require archive extraction to validate each ZipEntry "
            "name (reject absolute and '..' forms) before writing."
        ),
        "not_candidate_when": (
            "The child component is server-generated (UUID) or passed through "
            "File.getName-equivalent stripping, the canonical containment check "
            "rejects escapes before the file API, archive entries are validated or "
            "extracted under a resolving guard, or the base directory is not attacker-"
            "influenced and the child is a fixed constant."
        ),
        "vuln": "File target = new File(baseDir, entry.getName());",
        "safe": "Path p = baseDir.resolve(entry.getName()).normalize(); if (!p.startsWith(baseDir)) throw new SecurityException();",
        "signal": r"new\s+File\(baseDir,\s*entry\.getName\(\)\)",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "Java SE documentation: ZipEntry — https://docs.oracle.com/javase/8/docs/api/java/util/zip/ZipEntry.html",
            "Java SE documentation: Path — https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html",
    },
    {
        "num": "06",
        "title": "Command Execution and Unsafe Reflection",
        "platform": "Java SE 8+ standard library (java.lang.Runtime, java.lang.ProcessBuilder, java.lang.Class); applies on all target operating systems",
        "mechanism": (
            "Runtime.getRuntime().exec(String) tokenizes the command with "
            "StringTokenizer on whitespace, so a single-string form splits arguments "
            "unpredictably, and any form that routes through a shell ('sh', '-c', "
            "concatenated) hands the whole string to shell interpretation, where ';', "
            "'|', and '$(...)' start attacker commands. Class.forName(name) plus "
            "Method.invoke turns a name from input into arbitrary class loading and "
            "method invocation in-process, and URLClassLoader with an attacker-"
            "influenced URL loads classes from a remote codebase directly."
        ),
        "source": (
            "Request fields used as command strings or arguments, class/method names "
            "from input resolved via reflection, and codebase URLs from config or "
            "requests."
        ),
        "sink": (
            "Runtime.exec / ProcessBuilder.start with shell-composed strings; "
            "Class.forName with a dynamic name followed by reflection; URLClassLoader "
            "with attacker-influenced URLs"
        ),
        "guards": (
            "Require ProcessBuilder with a fixed executable and an argument list "
            "where each dynamic value is one element (no shell, no concatenated "
            "single string); require reflection targets be resolved from a compiled-"
            "in allowlist mapping rather than from input; require any classloader "
            "URL come from validated internal locations."
        ),
        "not_candidate_when": (
            "The command is a fixed executable with input as a single argv element "
            "and no shell involvement, reflected class names come from a fixed "
            "allowlist, the classloader loads only from the application's own sealed "
            "artifacts, or the input is validated to a grammar that cannot contain "
            "whitespace, shell metacharacters, or option prefixes."
        ),
        "vuln": "Runtime.getRuntime().exec(\"sh -c \" + cmd);",
        "safe": "ProcessBuilder pb = new ProcessBuilder(\"/bin/safe\", arg); pb.start();",
        "signal": r"Runtime\.getRuntime\(\)\.exec\(",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-470: Use of Externally-Controlled Input to Select Classes or Code — https://cwe.mitre.org/data/definitions/470.html",
            "Java SE documentation: Runtime — https://docs.oracle.com/javase/8/docs/api/java/lang/Runtime.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/lang/Runtime.html",
    },
    {
        "num": "07",
        "title": "Concurrency and Mutable State in Servlets",
        "platform": "Jakarta/Javax servlet containers (Tomcat, Jetty, WebSphere); the container creates ONE servlet instance serving all requests concurrently",
        "mechanism": (
            "The servlet specification keeps a single instance per servlet, so every "
            "instance field is shared by all concurrent requests: a currentUser field "
            "written by one request is read by another, letting a victim inherit an "
            "attacker's identity or vice versa. SimpleDateFormat stores intermediate "
            "parsing state in its instance and corrupts output or throws under "
            "concurrency; HashMap without synchronization loses updates and (in older "
            "JDKs) can loop under concurrent resize. A check-then-act pattern on an "
            "instance field ('if (this.session == null) create') races two requests "
            "into double initialization with mismatched credentials."
        ),
        "source": (
            "Concurrent HTTP requests handled by the same servlet/filter/bean "
            "instance; per-request values stored in instance fields."
        ),
        "sink": (
            "Mutable instance fields in HttpServlet/Filter/singletons holding "
            "request or identity data; shared SimpleDateFormat/HashMap instances used "
            "from request threads; check-then-act sequences on instance state"
        ),
        "guards": (
            "Check that per-request values live in local variables or request/session "
            "attributes rather than instance fields; check shared utility instances "
            "are replaced by ThreadLocal or immutable/thread-safe types "
            "(DateTimeFormatter, ConcurrentHashMap); check check-then-act sequences "
            "are atomic under a lock orCAS."
        ),
        "not_candidate_when": (
            "The fields are read-only after container initialization (safe publication "
            "with final/initialization-on-demand), the servlet is explicitly single-"
            "threaded (SingleThreadModel-era or one instance per request), shared "
            "state is confined to ConcurrentHashMap/Atomic types, or the field holds "
            "immutable configuration only."
        ),
        "vuln": "public class UserServlet extends HttpServlet { private String currentUser; }",
        "safe": "public class UserServlet extends HttpServlet { /* use local variables */ }",
        "signal": r"public\s+class\s+UserServlet.*private\s+String\s+currentUser",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') — https://cwe.mitre.org/data/definitions/362.html",
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "Java SE documentation: SimpleDateFormat — https://docs.oracle.com/javase/8/docs/api/java/text/SimpleDateFormat.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/text/SimpleDateFormat.html",
    },
    {
        "num": "08",
        "title": "Boxed Primitive Comparison and Silent Numerical Overflow",
        "platform": "Java SE 8+ standard library (java.lang autoboxing cache, String.split, int/long arithmetic); applies on all target operating systems",
        "mechanism": (
            "== between two boxed Integers compares references: values in the "
            "-128..127 autobox cache compare equal, while the same numeric value "
            "outside the cache compares unequal, so a role-ID check can pass in one "
            "environment and fail in another purely by cache range. String.split "
            "drops trailing empty strings, so splitting an ID list or path and "
            "checking 'element count' silently miscounts on inputs with trailing "
            "separators. Arithmetic on int silently wraps (Integer.MAX_VALUE + 1 "
            "becomes negative), so an attacker-chosen size that overflows a limit "
            "computation passes a 'less than' bounds check as a negative number."
        ),
        "source": (
            "Request-supplied numeric IDs boxed into wrapper types, delimited strings "
            "from clients parsed with split, and size/count fields feeding arithmetic "
            "on security paths."
        ),
        "sink": (
            "== / != on Integer/Long wrappers guarding authorization; String.split-"
            "derived arrays indexed or counted for access decisions; int arithmetic "
            "(sums, multiplies) whose result feeds bounds or quota checks"
        ),
        "guards": (
            "Require Objects.equals or unboxing to int primitives for numeric "
            "comparisons on security paths; require split with a negative limit "
            "argument (-1) when trailing empties matter, or explicit counting logic; "
            "require long/checked arithmetic (Math.addExact/subtractExact/multiplyExact) "
            "or explicit range validation before comparisons on sizes."
        ),
        "not_candidate_when": (
            "The comparison uses Objects.equals or primitives, the split result's "
            "empty-trailing behavior is irrelevant to the decision (membership tests "
            "not counts), the arithmetic operands are bounded far below overflow by "
            "prior validation, or the boxed values are canonicalized (e.g. from an "
            "enum or interned constants)."
        ),
        "vuln": "if (roleId1 == roleId2) { grantAccess(); }",
        "safe": "if (Objects.equals(roleId1, roleId2)) { grantAccess(); }",
        "signal": r"if\s*\(roleId1\s*==\s*roleId2\)",
        "references": [
            "CWE-595: Comparison of Object References Instead of Object Contents — https://cwe.mitre.org/data/definitions/595.html",
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-252: Unchecked Return Value — https://cwe.mitre.org/data/definitions/252.html",
            "Java SE documentation: Integer cache and boxing — https://docs.oracle.com/javase/8/docs/api/java/lang/Integer.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/lang/Integer.html",
    },
    {
        "num": "09",
        "title": "Cryptography and Weak PRNG Misuse",
        "platform": "Java SE 8+ standard library (java.util.Random, java.security.SecureRandom, javax.crypto.Cipher, javax.net.ssl); applies on all target operating systems",
        "mechanism": (
            "java.util.Random is a 48-bit LCG seeded from nanotime; outputs reveal "
            "state and the seed space is small enough to brute force, so tokens, "
            "reset codes, or keys from nextInt are reconstructable from a few "
            "observations. Cipher.getInstance(\"AES\") requests the (deprecated) "
            "default transformation, which resolves to AES/ECB/PKCS5Padding — ECB "
            "leaks plaintext equality block-wise; a developer-supplied static IV in "
            "CBC makes ciphertexts deterministic. An X509TrustManager whose "
            "checkServerTrusted is empty and a HostnameVerifier that returns true "
            "accept any certificate, silently turning TLS into plaintext; comparing "
            "digests with Arrays.equals/== leaks a timing oracle that "
            "MessageDigest.isEqual (constant-time since JDK 6u17) exists to prevent."
        ),
        "source": (
            "Security values produced in code: session tokens, reset codes, keys, "
            "MAC tags, and the crypto/TLS configuration chosen by the developer."
        ),
        "sink": (
            "new Random() / Math.random() feeding security values; Cipher.getInstance"
            "(\"AES\") or explicit ECB or a fixed IV; TrustManager implementations with "
            "empty check methods and HostnameVerifier returning true; ==/Arrays.equals "
            "on MessageDigest outputs"
        ),
        "guards": (
            "Require SecureRandom for security values; require explicit transformations "
            "(AES/GCM/NoPadding or AES/CBC/PKCS5Padding) with a fresh random IV per "
            "message; require TrustManager/HostnameVerifier implementations to "
            "actually validate chains and hostnames; require MessageDigest.isEqual "
            "for authenticator comparison."
        ),
        "not_candidate_when": (
            "Random feeds only non-security purposes, the transformation names the "
            "full mode with a per-message random IV, the TrustManager is a documented "
            "test-only class excluded from production builds, or comparisons already "
            "run through MessageDigest.isEqual."
        ),
        "vuln": "Random r = new Random(); int token = r.nextInt();",
        "safe": "SecureRandom sr = new SecureRandom(); byte[] token = new byte[32]; sr.nextBytes(token);",
        "signal": r"Random\s+r\s*=\s*new\s+Random\(\);",
        "references": [
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "CWE-295: Improper Certificate Validation — https://cwe.mitre.org/data/definitions/295.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "Java SE documentation: Cipher — https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html",
    },
    {
        "num": "10",
        "title": "Servlet and URL Discrepancies in Security Filters",
        "platform": "Jakarta/Javax servlet containers (Tomcat, Jetty, Undertow); exact normalization differences depend on container version, which is why the review must confirm the container's rules",
        "mechanism": (
            "A security filter that decides on getRequestURI() sees the RAW request "
            "path while the container later maps the SERVLET path after decoding and "
            "normalizing, so /admin;%2fadmin, //admin, /./admin, and %-encoded "
            "variants pass the prefix check yet land on the protected resource — the "
            "checker and the dispatcher disagree about which resource is being "
            "accessed. java.net.URL additionally treats a URL as a string with "
            "equals/openStream semantics differing from java.net.URI's RFC-3986 "
            "parsing (URL equals resolves hostnames via DNS, URI does not), and "
            "URL.openConnection dispatches on the scheme (file:, jar:, http:) so an "
            "attacker-controlled URL can pick the file handler; redirects and "
            "RequestDispatcher.forward re-enter the filter chain with a different "
            "path than the one originally checked."
        ),
        "source": (
            "Request paths, query strings, forward/include targets, and URLs taken "
            "from requests or configuration for outbound fetches."
        ),
        "sink": (
            "Security filters making allow/deny decisions on "
            "HttpServletRequest.getRequestURI() / getRequestURL() string prefixes; "
            "URL/URI comparisons guarding redirects or fetches; "
            "URL.openConnection on attacker-influenced URLs; forward/redirect targets "
            "validated only on the original path"
        ),
        "guards": (
            "Require the decision be made on the container-decoded, normalized path "
            "(getServletPath/getPathInfo or the matched mapping) rather than the raw "
            "URI, and re-run the check after any forward; require URL allowlist "
            "checks on a canonicalized URI with the scheme fixed to https and "
            "redirect targets re-validated per hop; confirm container-level encoding "
            "rules with the actual container version."
        ),
        "not_candidate_when": (
            "Authorization is enforced at the resource/mapping level (container or "
            "framework security constraints) rather than by string prefixes on the "
            "raw URI, the path is decoded and normalized before comparison and "
            "re-checked after forwards, or the outbound URL's scheme and host are "
            "matched against a fixed allowlist on canonical form."
        ),
        "vuln": "if (request.getRequestURI().startsWith(\"/admin\")) { checkAdmin(); }",
        "safe": "if (request.getServletPath().startsWith(\"/admin\")) { checkAdmin(); }",
        "signal": r"request\.getRequestURI\(\)\.startsWith",
        "references": [
            "CWE-436: Interpretation Conflict — https://cwe.mitre.org/data/definitions/436.html",
            "CWE-601: URL Redirection to Untrusted Site — https://cwe.mitre.org/data/definitions/601.html",
            "Java SE documentation: URL — https://docs.oracle.com/javase/8/docs/api/java/net/URL.html",
            "OWASP Authentication Cheat Sheet (authorization enforcement points) — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/net/URL.html",
    },
]
