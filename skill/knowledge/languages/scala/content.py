"""Substantive per-card content for the Scala knowledge cards (scala-01..scala-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card carries real mechanism, source/sink, guard, and
disqualification text. Entries cite only public references believed to exist
(CWE pages, JVM/Oracle documentation, OWASP cheat sheets).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Scala section).
"""

LANGUAGE = {
    "name": "Scala",
    "prefix": "scala",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsafe Java Deserialization via ObjectInputStream",
        "platform": "Scala 2.13 / Scala 3 standard library on the JVM; inherits Java serialization semantics of the underlying JVM",
        "mechanism": (
            "readObject does not parse data -- it executes Java serialization's "
            "reconstruction protocol, invoking readObject/defaultReadObject and "
            "readResolve on whatever classes the stream names, so any class on "
            "the classpath with gadget behavior becomes reachable from the "
            "payload alone. Scala code inherits this wholesale: Java "
            "serialization is the default wire format for several Scala remote-"
            "messaging and remoting stacks unless explicitly switched to a "
            "schema format, and polymorphic JSON binding that encodes a class "
            "name ('className'/'type' fields) resolves and instantiates "
            "attacker-named types the same way."
        ),
        "source": (
            "Network streams, message-queue payloads, caches, and RPC frames "
            "that carry Java-serialized bytes or type-tagged JSON."
        ),
        "sink": (
            "ObjectInputStream.readObject on attacker-influenced streams; "
            "remote-message pipelines left on default Java serialization; "
            "polymorphic JSON decoders resolving class names from the payload"
        ),
        "guards": (
            "Check the stream is protected by a resolving ObjectInputFilter "
            "(JEP 290 serial filter or a validating wrapper) with an explicit "
            "class allowlist, an integrity check (HMAC) is verified before "
            "readObject, or the wire format is schema-based (protobuf/Jackson "
            "with type restriction disabled)."
        ),
        "not_candidate_when": (
            "The bytes are produced and consumed within one trust boundary "
            "with no network exposure, a serial filter allowlists the exact "
            "application classes, or a MAC over the payload is verified "
            "before deserialization with a non-readable key."
        ),
        "vuln": "val obj = ois.readObject()",
        "safe": "/* Use Jackson or Protobuf serialization */",
        "signal": r"ois\.readObject\(\)",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "Java SE documentation: ObjectInputStream — https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html",
            "OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html",
    },
    {
        "num": "02",
        "title": "Command Injection via scala.sys.process Interpolator",
        "platform": "Scala 2.13 / Scala 3 standard library (scala.sys.process, scala.tools reflection) on the JVM",
        "mechanism": (
            "scala.sys.process converts a plain String into a shell command "
            "line: the string form (\"cmd\".!) hands the text to the platform "
            "shell, so an interpolated value containing ';' or '|' becomes a "
            "second command. Building the string with an interpolator "
            "(s\"sh -c $x\") is exactly the dangerous form, while Seq(\"cmd\", "
            "arg) constructs an argv vector with no shell involved. On the "
            "code-execution side, the reflection ToolBox (scala.tools."
            "reflect.ToolBox) compiles and evaluates a source string, and a "
            "script-engine eval in Scala/JVM syntax executes it identically."
        ),
        "source": (
            "Request parameters, filenames, or configuration values "
            "interpolated into process command strings or reflection-"
            "evaluated source text."
        ),
        "sink": (
            "String-typed scala.sys.process builders (\"...\".! / .!! / "
            "Process(\"...\")) with interpolation; ToolBox.eval; ScriptEngine."
            "eval on attacker text"
        ),
        "guards": (
            "Check the process is built from Seq(executable, args...) with a "
            "fixed executable path and the dynamic value as one element; "
            "check '--' or equivalent option-terminators precede attacker "
            "arguments; check no ToolBox/eval path is reachable from input."
        ),
        "not_candidate_when": (
            "The command is a constant with no interpolation, the dynamic "
            "value is validated against a strict grammar (numeric/identifier) "
            "before use, or the call takes the Seq argv form."
        ),
        "vuln": "s\"sh -c $userInput\".!",
        "safe": "Seq(\"/bin/safe\", userInput).!",
        "signal": r"s\"sh -c \$userInput\"\.!",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "Scala standard library: scala.sys.process (no stable deep-link cited)",
        ],
    },
    {
        "num": "03",
        "title": "SQL Injection in String Interpolation Queries",
        "platform": "Scala 2.13 / Scala 3 on the JVM; applies to JDBC and database-access libraries built over string interpolation",
        "mechanism": (
            "The s-interpolator performs plain string substitution before the "
            "driver sees the text, so s\"SELECT * FROM t WHERE id = $id\" sends "
            "the attacker's quote/syntax as statement structure and the "
            "database parses it as SQL. The same hole exists inside "
            "database-library interpolators when a raw fragment is spliced in: "
            "an s-interpolated sub-expression embedded into an sql\"...\" query, "
            "or string concatenation for identifiers and ORDER BY clauses, "
            "bypasses the parameter binding the library would otherwise apply."
        ),
        "source": (
            "Request parameters, sort/column names, and filter values fed "
            "into s-interpolated or concatenated query text."
        ),
        "sink": (
            "statement.execute / prepareStatement on s-interpolated strings; "
            "query interpolators receiving raw string fragments; identifier/"
            "ORDER BY concatenation"
        ),
        "guards": (
            "Check values are bound through the library's parameter "
            "mechanism (placeholders, the sql interpolator's binder, "
            "PreparedStatement.setString); check identifiers and sort "
            "directions come from a fixed allowlist map keyed by validated "
            "client values."
        ),
        "not_candidate_when": (
            "The query uses the database library's parameterized interpolator "
            "exclusively, interpolated parts come only from server-side "
            "allowlist constants, or the query text is entirely static."
        ),
        "vuln": "statement.execute(s\"SELECT * FROM t WHERE id = $id\")",
        "safe": "sql\"SELECT * FROM t WHERE id = $id\".query[Row]",
        "signal": r"statement\.execute\(s\"SELECT",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements in SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "Java SE documentation: PreparedStatement — https://docs.oracle.com/javase/8/docs/api/java/sql/PreparedStatement.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "04",
        "title": "Implicit Conversion Changing Security Semantics",
        "platform": "Scala 2.13 implicits / Scala 3 given-using resolution; a compile-time mechanism whose effect appears in the emitted JVM bytecode",
        "mechanism": (
            "An implicit conversion (implicit def, or Scala 3 Conversion "
            "given) rewrites the expression tree at compile time, so a value "
            "can be transformed -- trimmed, coerced, wrapped into a "
            "privileged type -- without any visible call at the audit point. "
            "When the conversion maps toward a type the authorization logic "
            "trusts (User -> Admin-like wrappers, canonicalized strings), the "
            "check runs on the transformed value, not the attacker's. given "
            "resolution has the same shape for ExecutionContext: a wrong "
            "implicit context can serialize sensitive work onto an "
            "unrestricted pool. Universal equality compounds it: comparing "
            "different types with == compiles (Scala 3 allows it unless "
            "strict equality is enabled) and is always false, silently "
            "short-circuiting a deny branch."
        ),
        "source": (
            "Externally derived values that cross implicit conversion or "
            "given boundaries before reaching authorization checks."
        ),
        "sink": (
            "implicit def / Conversion givens defined on security-relevant "
            "types; implicit ExecutionContext selection for privileged work; "
            "== comparisons across unrelated types in decision logic"
        ),
        "guards": (
            "Check no implicit conversion is defined between untrusted input "
            "types and authorization-relevant types, check the execution "
            "context is passed explicitly for privileged operations, and "
            "check comparisons compile under strict-equality (-source:future "
            "or explicit ===)."
        ),
        "not_candidate_when": (
            "Conversions are confined to value types with no security "
            "semantics and reviewed as such, the execution context is "
            "explicit at every sensitive call site, or both compared operands "
            "are provably the same type."
        ),
        "vuln": "implicit def toAdmin(u: User): Admin = Admin(u.name)",
        "safe": "/* explicit conversion functions only */",
        "signal": r"implicit\s+def\s+toAdmin",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
        ],
    },
    {
        "num": "05",
        "title": "Non-Exhaustive Pattern Matching and Option.get Panic",
        "platform": "Scala 2.13 / Scala 3 standard library on the JVM; MatchError and NoSuchElementException are JVM exceptions terminating request handling",
        "mechanism": (
            "Option.get, head, and Try.get throw on the empty/failure case, so "
            "a parsed-and-validated value is assumed present on the strength "
            "of a match that never happened -- an attacker who sends the "
            "malformed shape causes NoSuchElementException at the guard, and "
            "depending on handler wiring the request either dies or, in a "
            "catch-all recovery path, proceeds with defaults. A non-exhaustive "
            "match throws MatchError for the uncovered case; when the default "
            "branch of an exhaustive match grants rather than denies, the "
            "unexpected input fails open. Java interop nulls bypass Option "
            "semantics entirely: a null returned from a Java method flows "
            "into Scala code typed as non-null and detonates later."
        ),
        "source": (
            "Payload-derived parse results (Option/Try/Either), enums and "
            "sealed hierarchies built from input discriminants, and Java "
            "method returns that may be null."
        ),
        "sink": (
            "Option.get / .head / Try.get / .apply on parsed values; "
            "non-exhaustive match on input-driven variants; fail-open default "
            "branches in authorization matches"
        ),
        "guards": (
            "Check parsed values are consumed via match/map/getOrElse with an "
            "explicit deny path, matches over input-driven variants are "
            "exhaustive with a deny-all default, and null-prone Java results "
            "are wrapped with Option(...) before use."
        ),
        "not_candidate_when": (
            "The empty case is handled by an explicit deny/default branch, "
            "the match is exhaustive over a sealed hierarchy the attacker "
            "cannot extend, or the accessor operates on server-constructed "
            "values that cannot be empty."
        ),
        "vuln": "val result = parseInput(data).get",
        "safe": "parseInput(data) match { case Some(v) => v; case None => return }",
        "signal": r"parseInput\(data\)\.get",
        "references": [
            "CWE-755: Improper Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/755.html",
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
        ],
    },
    {
        "num": "06",
        "title": "Concurrency: Escaping Mutable State in Actor Futures",
        "platform": "Scala 2.13 / Scala 3 standard library (scala.concurrent.Future, scala.actors-successor stacks) on JVM thread pools",
        "mechanism": (
            "Future { ... } submits its thunk to an ExecutionContext and may "
            "run on any thread at any interleaving: a closure capturing a var "
            "or mutable collection performs unsynchronized reads/writes, so "
            "two concurrent requests observe or clobber each other's "
            "security-relevant state (session flags, quota counters, ACL "
            "caches). The same escape occurs when an Actor's internal state "
            "is captured by a Future the handler spawns -- the state leaves "
            "the actor's serialized processing guarantee. Blocking calls "
            "inside the default ExecutionContext starve its bounded thread "
            "pool, delaying or never running scheduled authorization work, "
            "and an uncomputed lazy val deadlocks under concurrent first "
            "access on synchronized initialization."
        ),
        "source": (
            "Concurrent request handlers sharing mutable fields, actor "
            "handlers spawning Futures over their own state, and blocking "
            "IO inside pooled execution contexts."
        ),
        "sink": (
            "Future { ... } closures referencing vars/mutable collections or "
            "actor state; blocking operations on the default dispatcher; "
            "lazy val first-touch under contention"
        ),
        "guards": (
            "Check shared state is confined to immutable messages, atomic "
            "references, or actor-serialized access with no Future capture; "
            "check blocking work runs on a dedicated dispatcher; check lazy "
            "vals used on request paths are initialized eagerly or under a "
            "non-blocking construction."
        ),
        "not_candidate_when": (
            "The captured state is immutable or thread-confined per request, "
            "the mutation is a single atomic CAS with no compound check, or "
            "the Future runs on an isolated single-thread executor "
            "guaranteeing serialization."
        ),
        "vuln": "Future { mutableState += msg }",
        "safe": "/* Send immutable messages to self */",
        "signal": r"Future\s*\{\s*mutableState\s*\+=",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
        ],
    },
    {
        "num": "07",
        "title": "XML External Entity Processing in scala.xml.XML",
        "platform": "Scala 2.13 / Scala 3 standard library (scala.xml) on the JVM; delegates to the JVM SAX parser underneath",
        "mechanism": (
            "scala.xml.XML.load and loadString parse with defaults that "
            "resolve external entities, so a document declaring an entity "
            "with a file:// or http:// system identifier makes the parser "
            "fetch and inline its contents -- local file read and SSRF from "
            "the payload, with the inlined data echoed back through "
            "downstream rendering. Recursive internal entities amplify a "
            "tiny document into memory exhaustion. The related Scala-only "
            "sink is XML literals in code: interpolating an attacker string "
            "into XML literal syntax emits it unescaped into the parsed "
            "tree, injecting elements or text into the produced document."
        ),
        "source": (
            "XML documents posted by clients, configuration feeds fetched "
            "from peers, and string values interpolated into XML literals."
        ),
        "sink": (
            "scala.xml.XML.load / loadString / withSAXParser on untrusted "
            "documents; XML literal construction with interpolated values"
        ),
        "guards": (
            "Check parsing goes through a factory with external entities and "
            "DTDs disabled (SAXParserFactory features "
            "external-general-entities=false, disallow-doctype-decl=true) "
            "rather than the scala.xml convenience entry points; check XML "
            "literal content is escaped or built from validated nodes."
        ),
        "not_candidate_when": (
            "The XML comes from a trusted internal producer that never emits "
            "DTDs, parsing runs with entity resolution explicitly disabled, "
            "or interpolated values are escaped/encoded before entering "
            "literal markup."
        ),
        "vuln": "val xml = scala.xml.XML.load(inputStream)",
        "safe": "val parser = saxParserFactory.newSAXParser(); parser.parse(...)",
        "signal": r"scala\.xml\.XML\.load\(",
        "references": [
            "CWE-611: Improper Restriction of XML External Entity Reference — https://cwe.mitre.org/data/definitions/611.html",
            "CWE-776: Improper Restriction of Recursive Entity References in DTDs — https://cwe.mitre.org/data/definitions/776.html",
            "OWASP XML External Entity Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "08",
        "title": "Unbounded Stream and LazyList Resource Exhaustion",
        "platform": "Scala 2.13 / Scala 3 standard library (LazyList, Iterator, scala.util.matching.Regex) on the JVM",
        "mechanism": (
            "LazyList memoizes every evaluated element, so a long-running "
            "transform over an unbounded or client-driven stream retains all "
            "computed cells -- memory grows monotonically with request "
            "volume even though the code reads as lazy. Stream-processing "
            "pipelines without a frame-length limit or backpressure accept "
            "declared sizes from the wire and allocate ahead of validation; "
            "an unbounded actor mailbox queues attacker messages without "
            "limit. The collection-side '.r' RichString regex recompiles a "
            "pattern on every call and, combined with a nested-quantifier "
            "pattern, drives JVM regex backtracking to full CPU on one "
            "request thread."
        ),
        "source": (
            "Client-driven stream/frame volumes, message rates into actor "
            "mailboxes, and subject strings matched against collection-"
            "built regexes."
        ),
        "sink": (
            "LazyList.from(...)/memoized chains over request data; "
            "stream/frame reads sized from wire headers without caps; "
            "unbounded mailbox receive; .r regex over untrusted strings"
        ),
        "guards": (
            "Check frame lengths against fixed caps before allocation, "
            "streams are consumed without retaining heads (or use "
            "backpressured stream libraries), mailboxes are bounded, and "
            "regex patterns are precompiled constants with bounded subjects."
        ),
        "not_candidate_when": (
            "The lazy sequence is finite and bounded by construction, "
            "backpressure or bounded queues are in place upstream, or the "
            "regex is a linear pattern over length-capped input."
        ),
        "vuln": "val stream = LazyList.from(0).map(process)",
        "safe": "/* use Akka/FS2 streams with backpressure */",
        "signal": r"LazyList\.from\(0\)",
        "references": [
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "CWE-770: Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html",
            "CWE-1333: Inefficient Regular Expression Complexity — https://cwe.mitre.org/data/definitions/1333.html",
        ],
    },
    {
        "num": "09",
        "title": "Path Traversal via scala.io.Source",
        "platform": "Scala 2.13 / Scala 3 standard library (scala.io.Source) on the JVM; URL handlers follow JVM protocol resolution",
        "mechanism": (
            "scala.io.Source.fromURL accepts any java.net.URL-legal scheme, "
            "so an attacker-supplied 'file:///etc/passwd' or 'http://169.254."
            "169.254/...' string makes the read API itself the SSRF/local-"
            "file primitive -- no separate network call is needed and the "
            "content comes back through the same return value. fromFile with "
            "a traversal path ('../../..') escapes the intended directory "
            "because Source performs no confinement check, and archive entry "
            "names carrying absolute paths or '..' do the same at extraction "
            "time via JVM file APIs."
        ),
        "source": (
            "Path or URL strings from requests, import/export parameters, "
            "and archive member names."
        ),
        "sink": (
            "scala.io.Source.fromURL / fromFile over attacker-influenced "
            "strings; JVM File/Paths operations over archive entry names"
        ),
        "guards": (
            "Check URL reads restrict the scheme to an allowlist and the "
            "host to a validated set resolved before the request; check file "
            "reads normalize the candidate and verify containment under the "
            "base directory (startsWith on canonical paths); check archive "
            "entry names reject absolute paths and '..' segments."
        ),
        "not_candidate_when": (
            "The path is generated server-side, a canonical-path containment "
            "check rejects escapes before reading, or the URL is restricted "
            "to an allowlisted scheme+host with redirects disabled."
        ),
        "vuln": "val content = Source.fromFile(userPath).mkString",
        "safe": "val clean = sanitize(userPath); Source.fromFile(clean).mkString",
        "signal": r"Source\.fromFile\(userPath\)",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "CWE-918: Server-Side Request Forgery (SSRF) — https://cwe.mitre.org/data/definitions/918.html",
            "OWASP Server Side Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        "doc_url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    {
        "num": "10",
        "title": "Secret Leakage via case class toString()",
        "platform": "Scala 2.13 / Scala 3 standard library on the JVM (scala.util.Random delegates to java.util.Random; case class toString is compiler-generated)",
        "mechanism": (
            "scala.util.Random wraps java.util.Random's 48-bit LCG: its state "
            "is fully determined by a small number of observed outputs, so "
            "tokens or reset codes drawn from it are reconstructible from a "
            "few samples. Secret-bearing values leak through compiler-"
            "generated code the author did not write: case class toString "
            "includes every field, so logging or exception-wrapping a "
            "credentials case class prints passwords into logs and error "
            "pages. Digest comparisons written with == short-circuit on the "
            "first differing byte, giving a timing oracle byte-by-byte over "
            "MessageDigest output; MessageDigest.isEqual is the "
            "constant-time counterpart on the JVM."
        ),
        "source": (
            "The secret values themselves: generated tokens, credential case "
            "class instances, and digest/MAC byte arrays compared in "
            "decision code."
        ),
        "sink": (
            "scala.util.Random for security values; case class toString / "
            "productElement access exposing secret fields into logs and "
            "responses; == / != over digest arrays"
        ),
        "guards": (
            "Check tokens come from java.security.SecureRandom or a CSPRNG "
            "wrapper; check credential types override toString (or keep "
            "secrets out of case classes) and never reach logger calls "
            "whole; check digest comparisons use MessageDigest.isEqual."
        ),
        "not_candidate_when": (
            "Random drives only non-security sampling, the printed type "
            "carries no secret fields and never reaches logs, or the "
            "comparison is over non-sensitive nonces with no attacker "
            "oracle."
        ),
        "vuln": "case class UserCredentials(username: String, pass: String)",
        "safe": "case class UserCredentials(...) { override def toString = ... }",
        "signal": r"case\s+class\s+UserCredentials\(",
        "references": [
            "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator — https://cwe.mitre.org/data/definitions/338.html",
            "CWE-532: Insertion of Sensitive Information into Log File — https://cwe.mitre.org/data/definitions/532.html",
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "Java SE documentation: MessageDigest.isEqual — https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html",
    },
]
