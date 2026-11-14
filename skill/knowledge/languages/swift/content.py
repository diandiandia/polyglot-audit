"""Substantive per-card content for the Swift knowledge cards (swift-01..swift-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, official Apple framework documentation).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Swift section).
"""

LANGUAGE = {
    "name": "Swift",
    "prefix": "swift",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsafe Pointer Escape and Buffer Bounds",
        "platform": (
            "Swift runtime language semantics (Unsafe pointer family); applies wherever "
            "Swift runs (iOS/macOS and server-side Swift on Linux)"
        ),
        "mechanism": (
            "withUnsafeBytes/withUnsafeMutableBytes hand the closure a pointer that is "
            "only valid for the duration of the call: the buffer's backing storage can "
            "be reallocated or freed the moment the closure returns, so storing the "
            "pointer in an outer variable and dereferencing it later is use-after-free "
            "by construction, not just a style warning. bindMemory and "
            "assumingMemoryBound reinterpret raw bytes as a typed T; if the real bytes "
            "were attacker-influenced or the alignment/stride assumption is wrong, "
            "reads return type-confused values and writes corrupt unrelated memory. "
            "Unmanaged retains the pre-ARC calling convention: a mismatched "
            "retain/release pair (retain().release() vs toOpaque()/fromOpaque()) "
            "produces a leak or a double release that attackers can groom."
        ),
        "source": (
            "External data whose length or content determines the buffer's lifetime or "
            "interpretation: network packets, parsed files, IPC messages fed into "
            "pointer-based processing."
        ),
        "sink": (
            "withUnsafeBytes { ptr = $0.baseAddress } and any escape of the closure-"
            "scoped pointer; bindMemory / assumingMemoryBound on externally sized raw "
            "buffers; UnsafeMutablePointer / UnsafeRawBufferPointer arithmetic with "
            "input-derived offsets; Unmanaged retain/release imbalance"
        ),
        "guards": (
            "Check every unsafe pointer is consumed inside its with* closure (no "
            "assignment to outer scope, no stored baseAddress); check lengths used for "
            "pointer arithmetic or bindMemory counts are validated against the real "
            "allocation size before use; check Unmanaged pairs are balanced (or "
            "takeRetainedValue/takeUnretainedValue used correctly) at every path."
        ),
        "not_candidate_when": (
            "The pointer is used only within the withUnsafeBytes closure on a buffer "
            "sized from compile-time constants, the reinterpretation is on internal "
            "fixed-layout structs never fed by external bytes, or the value is fully "
            "bridged through safe Swift collections before any use outside the closure."
        ),
        "vuln": "var ptr: UnsafeRawPointer?; data.withUnsafeBytes { ptr = $0.baseAddress }",
        "safe": "data.withUnsafeBytes { use($0) }",
        "signal": r"withUnsafeBytes\s*\{\s*ptr\s*=",
        "references": [
            "CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html",
            "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer — https://cwe.mitre.org/data/definitions/119.html",
            "Swift Programming Language guide: Unsafe Pointer (Memory Safety chapter)",
        ],
    },
    {
        "num": "02",
        "title": "Objective-C Interop and NSKeyedUnarchiver",
        "platform": "iOS/macOS SDK (Apple frameworks: Foundation NSKeyedUnarchiver, NSPredicate, KVC)",
        "mechanism": (
            "NSKeyedUnarchiver.unarchiveObject(with:) reconstructs whatever class names "
            "the serialized data names; because the archive is attacker-supplied bytes, "
            "any class conforming to NSSecureCoding-agnostic NSCoder decoding becomes a "
            "deserialization gadget, and Foundation classes with side-effecting "
            "initWithCoder implementations have a long history of exploitable use. "
            "The typed replacement unarchivedObject(ofClass:from:) refuses classes that "
            "do not implement NSSecureCoding, closing the class-confusion hole. The "
            "same trust mismatch appears across the ObjC bridge: 'as!' downcasts a "
            "bridged AnyObject to a concrete type and traps (or worse, mis-types) when "
            "the runtime object differs; KVC setValue(_:forKeyPath:) with an external "
            "key path reaches arbitrary setters; NSPredicate(format:) with an "
            "interpolated string parses the input as a predicate expression language "
            "(injection in its own grammar); String(format:) with an external format "
            "string is printf-style format injection."
        ),
        "source": (
            "Serialized archives from other apps/IPC/pasteboard/network, external "
            "strings feeding predicate or format templates, and external key paths."
        ),
        "sink": (
            "NSKeyedUnarchiver.unarchiveObject(with:); 'as!' on bridged runtime objects; "
            "setValue(_:forKeyPath:) with external keys; NSPredicate(format:)/"
            "NSExpression(expressionWithFormat:) with interpolated strings; "
            "String(format: externalFormat)"
        ),
        "guards": (
            "Check deserialization uses NSKeyedUnarchiver.unarchivedObject(ofClass:from:) "
            "with an explicit NSSecureCoding class or rejects archives whose classes are "
            "not allowlisted; check downcasts use conditional 'as?' with handled failure; "
            "check predicate/format strings are built from constants with values bound "
            "as arguments (NSPredicate(value:) is still a format — require escaping or "
            "constant formats) and key paths come from a fixed allowlist."
        ),
        "not_candidate_when": (
            "The archive was produced and consumed inside the same app with no IPC/"
            "pasteboard exposure, decoding is constrained to one NSSecureCoding data "
            "class of plain properties, or the predicate/format templates are compile-"
            "time constants and only argument values are dynamic."
        ),
        "vuln": "let obj = NSKeyedUnarchiver.unarchiveObject(with: data)",
        "safe": "let obj = try NSKeyedUnarchiver.unarchivedObject(ofClass: SafeClass.self, from: data)",
        "signal": r"NSKeyedUnarchiver\.unarchiveObject\(",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "Apple developer documentation: NSKeyedUnarchiver — https://developer.apple.com/documentation/foundation/nskeyedunarchiver",
            "Apple developer documentation: NSPredicate — https://developer.apple.com/documentation/foundation/nspredicate",
        ],
        "doc_url": "https://developer.apple.com/documentation/foundation/nskeyedunarchiver",
    },
    {
        "num": "03",
        "title": "Runtime Traps and Force Unwrapping DoS",
        "platform": (
            "Swift runtime language semantics (optional unwrapping, overflow trapping, "
            "preconditions); applies wherever Swift runs (iOS/macOS and server-side Swift)"
        ),
        "mechanism": (
            "Several Swift constructs are defined to abort the process rather than "
            "return an error: '!' on nil and 'as!' on a wrong dynamic type trap; "
            "subscripting an array out of bounds traps; '+'/'*' on integers overflow-"
            "trap in every build configuration; 'try!' rethrows the error as a fatal; "
            "precondition/fatalError are unconditional aborts. One attacker-chosen "
            "value reaching any of them — a missing JSON field, a number above Int64, "
            "an index past the end — kills the whole process (on iOS the app crashes "
            "for the user; on a Swift server the worker dies), so a single malformed "
            "request becomes a reliable remote denial of service with no memory "
            "corruption needed. unowned references trap the same way when the target "
            "was deallocated by an earlier request's cleanup."
        ),
        "source": (
            "Fields of decoded JSON/protobuf messages, query parameters, headers, and "
            "any numeric or array value the attacker can set (including 0, negative, "
            "or >Int64.max values that trigger arithmetic traps)."
        ),
        "sink": (
            "'!' force unwrap and 'as!' forced downcast on decoded values; 'try!' on "
            "parsing calls; array/collection subscripts on untrusted indices; "
            "arithmetic on attacker-supplied integers without &+ / &* / checked "
            "variants; precondition/fatalError reachable from input; unowned access "
            "after await"
        ),
        "guards": (
            "Check every input-derived optional uses guard let/if let with a handled "
            "failure path, conditional 'as?', and get(index) or bounds checks instead "
            "of forced forms; check numeric inputs use Int64-clamped parsing or "
            "overflow-checked operators; check precondition/fatalError appear only on "
            "truly impossible internal invariants not influenced by request data."
        ),
        "not_candidate_when": (
            "The forced unwrap sits on a value the app itself just constructed "
            "(non-nil by construction, e.g. a just-registered dependency), the decode "
            "path already rejects malformed payloads before the subscript, or the "
            "crash aborts only an attacker's own single-user session with no shared "
            "state (still a hardening note, not a candidate)."
        ),
        "vuln": "let token = json[\"token\"] as! String",
        "safe": "guard let token = json[\"token\"] as? String else { return }",
        "signal": r"json\[\"token\"\]\s+as!\s+String",
        "references": [
            "CWE-617: Reachable Assertion — https://cwe.mitre.org/data/definitions/617.html",
            "CWE-755: Improper Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/755.html",
            "Swift Programming Language guide: Optional unwrapping and error handling",
        ],
    },
    {
        "num": "04",
        "title": "Data Race in Concurrency and Actor Reentrancy",
        "platform": (
            "Swift runtime concurrency semantics (actors, Sendable, structured "
            "concurrency); applies wherever Swift runs, including iOS/macOS and "
            "server-side Swift"
        ),
        "mechanism": (
            "An actor suspends at every await and is free to run other messages before "
            "the suspended one resumes, so a check performed before an await no longer "
            "describes the state when the awaited work returns — the balance check "
            "passes twice for two concurrent messages, and both deduct. Marking a type "
            "@unchecked Sendable or a property nonisolated(unsafe) silences the "
            "compiler's data-race analysis without adding synchronization, turning "
            "shared mutable state into a classic unsynchronized race across queues or "
            "Tasks. Weaker atomic-ordering mistakes (relaxed ordering where "
            "acquire/release was required in the underlying C/ObjC primitives) and "
            "lock poisoning/deadlock in mixed GCD/async code complete the same class."
        ),
        "source": (
            "Concurrent requests or UI events reaching the same actor/queue; attacker-"
            "controlled values that drive two interleaved check-then-act sequences "
            "(double-spend, double-redeem, TOCTOU on permission flags)."
        ),
        "sink": (
            "State checks separated from the mutation by an await inside an actor; "
            "@unchecked Sendable conformance on stateful types; nonisolated(unsafe) on "
            "mutable properties; shared vars mutated from multiple Tasks/DispatchQueues "
            "without a lock"
        ),
        "guards": (
            "Check the security-relevant condition is re-validated after every await "
            "(or the read-check-write sequence is a single non-suspending critical "
            "section); check @unchecked Sendable types actually serialize access with a "
            "lock or confinement; check permission/authorization flags are not "
            "cached in mutable shared state that another request can flip."
        ),
        "not_candidate_when": (
            "The actor method performs its check and mutation without any intervening "
            "await, the shared state is immutable or actor-isolated with no "
            "@unchecked escape, or the operation is idempotent so an interleaved "
            "second execution cannot change the security outcome."
        ),
        "vuln": "if balance >= amount { await deduct(); balance -= amount }",
        "safe": "/* re-check balance after await */",
        "signal": r"if\s+balance\s*>=\s*amount\s*\{\s*await\s+deduct\(\)",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition — https://cwe.mitre.org/data/definitions/367.html",
            "Swift Programming Language guide: Concurrency (actors and Sendable)",
        ],
    },
    {
        "num": "05",
        "title": "WKWebView JavaScript String Concatenation Injection",
        "platform": "iOS/macOS SDK (WebKit framework: WKWebView, WKScriptMessageHandler)",
        "mechanism": (
            "evaluateJavaScript compiles and runs the given string as JavaScript inside "
            "the page's context with the page's origin; splicing an external value into "
            "that string (\"setUser('\\(userParam)')\") lets a quote or newline in the "
            "value terminate the intended call and execute attacker-authored script "
            "with full page privileges — DOM access, storage, and any native bridge the "
            "page exposes via WKScriptMessageHandler. The same trust inversion appears "
            "at the entry side: custom URL schemes and universal links hand their "
            "parameters to the app, and NSAppleScript executes an AppleScript string "
            "compiled from input, which is code execution on macOS by definition. "
            "Trusting postMessage content arriving on the script-message bridge without "
            "origin/content checks gives the loaded page a native-call primitive."
        ),
        "source": (
            "Remote deep-link/universal-link parameters, user-controlled URL fragments, "
            "web content loaded into the WebView, and messages posted over the "
            "WKScriptMessageHandler bridge."
        ),
        "sink": (
            "wkWebView.evaluateJavaScript with an interpolated script string; "
            "NSAppleScript(source: externalString).executeAndReturnError; "
            "WKScriptMessageHandler message bodies used without validation; custom "
            "scheme handlers acting on unvalidated parameters"
        ),
        "guards": (
            "Check script invocations pass parameters as data, not code: JSON-encode "
            "the argument and have the page parse it, or route values through "
            "WKScriptMessageHandler with a JSON body; check message handlers validate "
            "the expected message name and schema and never dispatch on raw strings; "
            "check custom scheme/deep-link parameters are allowlist-validated before "
            "driving navigation or script; check NSAppleScript input is a constant."
        ),
        "not_candidate_when": (
            "The evaluated script is a compile-time constant with no interpolation, "
            "parameters cross the bridge as JSON-encoded data validated on the native "
            "side, or the WebView loads only bundled static content with no user or "
            "remote influence."
        ),
        # Note: literal backslash-quote characters preserved verbatim from the
        # original catalog JSON (signals/admission must hit this exact string).
        "vuln": 'webView.evaluateJavaScript(\\"setUser(\'\\(userParam)\')\\")',
        "safe": "/* pass parameters via message handler or JSON */",
        "signal": r"webView\.evaluateJavaScript\(",
        "references": [
            "CWE-79: Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html",
            "CWE-94: Improper Control of Generation of Code — https://cwe.mitre.org/data/definitions/94.html",
            "Apple developer documentation: WKWebView — https://developer.apple.com/documentation/webkit/wkwebview",
        ],
        "doc_url": "https://developer.apple.com/documentation/webkit/wkwebview",
    },
    {
        "num": "06",
        "title": "Insecure Storage in UserDefaults and ATS Bypass",
        "platform": "iOS/macOS SDK (Foundation UserDefaults, Security Keychain Services, App Transport Security in URLSession/NSAppTransportSecurity)",
        "mechanism": (
            "UserDefaults writes an unencrypted plist inside the app container (or "
            "shared with an app group); on jailbroken devices, from iTunes/iCloud "
            "backups, and via any container read primitive the file is recoverable, so "
            "tokens and credentials stored there are dumped offline. Keychain items "
            "are encrypted at rest, but the accessibility level matters: "
            "kSecAttrAccessibleAlways / WhenUnlockedThisDeviceOnly-vs-Always tradeoffs "
            "determine whether the item migrates to backups or other devices and when "
            "it is readable. On the transport side, URLSessionDelegate methods "
            "(urlSession(_:didReceive:completionHandler:)) that call "
            "completionHandler(.useCredential, URLCredential(trust:)) unconditionally "
            "accept any presented certificate, disabling server authentication; "
            "NSAppTransportSecurity exceptions (NSAllowsArbitraryLoads) re-enable "
            "cleartext and weak TLS for the whole app."
        ),
        "source": (
            "The credential material itself plus any network position able to present a "
            "substitute certificate once validation is disabled."
        ),
        "sink": (
            "UserDefaults.standard.set / plist writes of tokens or keys; Keychain "
            "queries with kSecAttrAccessibleAlways; URLSessionDelegate accepting every "
            "server trust challenge; NSAppTransportSecurity with "
            "NSAllowsArbitraryLoads; CommonCrypto calls with ECB mode or a fixed IV"
        ),
        "guards": (
            "Check secrets go to Keychain with a device-only accessibility level "
            "(kSecAttrAccessibleWhenUnlockedThisDeviceOnly or better) instead of "
            "UserDefaults; check server trust challenges evaluate the trust object "
            "(SecTrustEvaluateWithError) and only pin to expected keys; check "
            "Info.plist contains no NSAllowsArbitraryLoads in release; check "
            "CommonCrypto specifies GCM/CBC with random IV and correct buffer sizes."
        ),
        "not_candidate_when": (
            "Only non-sensitive preferences are stored in UserDefaults, the Keychain "
            "item's accessibility restricts it to this device and unlocked use, the "
            "ATS exception is scoped to a documented non-sensitive domain, or the "
            "trust delegate rejects challenges it cannot verify against pinned keys."
        ),
        "vuln": "UserDefaults.standard.set(secretToken, forKey: \"token\")",
        "safe": "/* use Keychain Services */",
        "signal": r"UserDefaults\.standard\.set\(secretToken",
        "references": [
            "CWE-312: Cleartext Storage of Sensitive Information — https://cwe.mitre.org/data/definitions/312.html",
            "CWE-295: Improper Certificate Validation — https://cwe.mitre.org/data/definitions/295.html",
            "Apple developer documentation: Keychain Services — https://developer.apple.com/documentation/security/keychain_services",
            "Apple developer documentation: UserDefaults — https://developer.apple.com/documentation/foundation/userdefaults",
            "Apple developer documentation: URLSessionDelegate — https://developer.apple.com/documentation/foundation/urlsessiondelegate",
        ],
        "doc_url": "https://developer.apple.com/documentation/security/keychain_services",
    },
    {
        "num": "07",
        "title": "Path Traversal via URL appendingPathComponent",
        "platform": "iOS/macOS SDK (Foundation URL/FileManager) with Swift runtime semantics; sandbox boundary rules are iOS/macOS specific",
        "mechanism": (
            "URL.appendingPathComponent(percentEncoded:) percent-encodes '/' only when "
            "the API notices it, and the string-based variants historically kept '../' "
            "sequences intact, so a name like '../../Private/doc' appended to a sandbox "
            "container URL escapes the intended directory once FileManager resolves the "
            "path. Symbolic links inside a writable directory (downloads, documents "
            "imported from other apps, archive members) redirect writes outside the "
            "sandbox even when the resolved prefix was checked earlier — the check and "
            "the write race. Archive extraction trusting member names repeats the "
            "class; security-scoped bookmarks resolving to attacker-influenced paths "
            "can widen the sandbox boundary the app was granted."
        ),
        "source": (
            "File names from other apps (open-in, share extensions), archive entry "
            "names, server-supplied download names, and document provider inputs."
        ),
        "sink": (
            "baseDir.appendingPathComponent(userInput) / FileManager contentsOfDirectory "
            "and copyItem at the resolved path; symlink-following writes; archive entry "
            "extraction without member validation; predictable temp names in shared "
            "containers"
        ),
        "guards": (
            "Check the incoming name is stripped to its lastPathComponent or "
            "re-validated against a strict pattern before appending; check the final "
            "URL's path, after resolving (URL(fileURLWithPath:).standardized / "
            "resolvingSymlinksInPath), still has the intended base as its prefix at "
            "write time; check archive extraction validates each entry name and the "
            "temporary names come from a random generator."
        ),
        "not_candidate_when": (
            "Names are generated server/app-side (UUIDs) and never taken from the "
            "client, the component is reduced to lastPathComponent plus a post-append "
            "prefix check on the resolved path, or the destination directory contains "
            "no attacker-writable symlinks and the app verified it at write time."
        ),
        "vuln": "let dest = baseDir.appendingPathComponent(userInput)",
        "safe": "let clean = (userInput as NSString).lastPathComponent; let dest = baseDir.appendingPathComponent(clean)",
        "signal": r"baseDir\.appendingPathComponent\(userInput\)",
        "references": [
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "CWE-59: Improper Link Resolution Before File Access — https://cwe.mitre.org/data/definitions/59.html",
            "Apple developer documentation: FileManager — https://developer.apple.com/documentation/foundation/filemanager",
        ],
        "doc_url": "https://developer.apple.com/documentation/foundation/filemanager",
    },
    {
        "num": "08",
        "title": "Decoding and Type Coercion Inconsistencies",
        "platform": (
            "Swift runtime semantics (Codable, Any/NSNumber bridging); applies wherever "
            "Swift runs, with JSONSerialization bridging behavior defined by the Apple "
            "Foundation / swift-corelibs-foundation implementations"
        ),
        "mechanism": (
            "JSONSerialization returns Any dictionaries whose values are NSNumber, and "
            "NSNumber bridges to Bool in a way that surprises: 0/1 and true/false are "
            "interchangeable through CFBoolean bridging, so an 'isAdmin': 1 numeric "
            "field can satisfy a Bool check written against a different shape. "
            "'as?' chains over Any give silent fallbacks per level, so a payload that "
            "shifts a field from String to [String] takes a different (often "
            "unvalidated) branch instead of failing. try? JSONDecoder().decode(...) "
            "collapses every decode error into nil, indistinguishable from 'field "
            "absent', so authorization code cannot tell a malformed attacker payload "
            "from a missing permission and may default to allow. A lenient custom "
            "init(from:) that returns defaults for unparseable values has the same "
            "allow-by-default effect, and raw-value enum initialization (Role(rawValue: x) ?? .member) "
            "falls back to a benign-looking role on out-of-range input."
        ),
        "source": (
            "JSON/protobuf request bodies, push and deep-link payloads, and any "
            "attacker-chosen field type variations (number vs bool vs array vs null)."
        ),
        "sink": (
            "try? JSONDecoder().decode on authorization-relevant models; 'as?' chains "
            "over JSONSerialization Any output; NSNumber-to-Bool/Int bridges compared "
            "in security checks; custom init(from:) with default-value fallbacks; "
            "enum Role(rawValue:) ?? .default on role fields"
        ),
        "guards": (
            "Check decode errors are surfaced and rejected (do/catch with a denial "
            "path), not folded into nil-by-default; check decoded models pin field "
            "types strictly (no Any, explicit types) and role/state enums decode via "
            "throws rather than rawValue fallback; check NSNumber comparisons go "
            "through an explicit type test (obj is Bool / obj is Int) before any "
            "security comparison."
        ),
        "not_candidate_when": (
            "The decoded model only feeds display rendering with no security decision, "
            "the payload originates from the app's own backend with a fixed schema "
            "verified by tests, or the decode failure path explicitly denies rather "
            "than defaulting."
        ),
        "vuln": "let user = try? JSONDecoder().decode(User.self, from: data)",
        "safe": "do { let user = try JSONDecoder().decode(User.self, from: data) } catch { ... }",
        "signal": r"try\?\s+JSONDecoder\(\)\.decode\(",
        "references": [
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "Swift Programming Language guide: Codable and type casting (as?)",
        ],
    },
    {
        "num": "09",
        "title": "String Index and Unicode Normalization Discrepancies",
        "platform": (
            "Swift runtime string semantics (String, Unicode normalization, NSString "
            "bridging); applies wherever Swift runs; NSRange/NSString specifics come "
            "from the Foundation framework on Apple platforms and swift-corelibs-"
            "foundation elsewhere"
        ),
        "mechanism": (
            "Swift String indexes characters (grapheme clusters) while NSString.length "
            "counts UTF-16 code units and utf8.count counts bytes, so the same string "
            "has three different lengths; slicing a String with an NSRange computed "
            "from utf8.count or NSString.length selects the wrong region or crashes, "
            "and validation that checked one representation can be applied to another "
            "in the security decision. Unicode normalization makes distinct byte "
            "sequences equal-looking and equal-looking sequences distinct: a username "
            "or identifier in NFC vs NFD form, or containing a confusable character, "
            "can pass a blocklist check as 'different' and collide with a privileged "
            "account downstream, or bypass a duplicate-name check. Integer conversions "
            "complete the class: Int(truncatingIfNeeded:) silently drops high bits and "
            "Int('4294967297') traps, so an attacker-supplied numeric string either "
            "aborts the process or wraps into a different ID."
        ),
        "source": (
            "User identifiers, filenames, and numeric strings from requests or payloads "
            "that contain multi-byte graphemes, combining characters, or values outside "
            "the target integer range."
        ),
        "sink": (
            "NSRange constructed from String.count/utf8.count/NSString.length and used "
            "to slice validated content; equality/containment checks without "
            "predefinedNormalizationForm (precomposedStringWithCanonicalMapping); "
            "Int(truncatingIfNeeded:) / Int(string) on untrusted numerics driving IDs "
            "or lengths"
        ),
        "guards": (
            "Check range math uses one consistent representation (String.Index ranges, "
            "or utf16 offsets with String.UTF16View end-to-end); check identifiers are "
            "normalized to a single form (NFC via precomposedStringWithCanonicalMapping) "
            "before comparison and uniqueness checks; check numeric strings parse with "
            "bounded Int.init and range validation, never truncatingIfNeeded."
        ),
        "not_candidate_when": (
            "The validated strings are pure ASCII so all representations agree, "
            "normalization is applied before every comparison so confusables collapse "
            "deterministically, or the numeric conversion is range-checked with a "
            "handled failure instead of truncating."
        ),
        "vuln": "let range = NSRange(location: 0, length: 10)",
        "safe": "/* validate using Swift Native Index */",
        "signal": r"NSRange\(location:\s*0,\s*length:\s*10\)",
        "references": [
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-176: Dependence on Encoding and Representation (string representation mismatch)",
            "Apple developer documentation: NSRange — https://developer.apple.com/documentation/foundation/nsrange",
        ],
        "doc_url": "https://developer.apple.com/documentation/foundation/nsrange",
    },
    {
        "num": "10",
        "title": "Unbounded Buffer Allocation in Network Streams",
        "platform": (
            "Swift runtime semantics (Data, streams); applies wherever Swift runs, "
            "including iOS/macOS clients and server-side Swift services"
        ),
        "mechanism": (
            "Data(capacity:) reserves the requested capacity up front, so a length taken "
            "from a header ('content-length', a protocol length prefix) turns a few "
            "attacker bytes into a multi-gigabyte allocation — the memory commit fails "
            "or the process is OOM-killed before any data arrives. read loops that "
            "append into Data without a cap have the same effect for compressed or "
            "chunked bodies, and a decompression step (zlib/Compression framework) "
            "multiplies the amplification. On server-side Swift the blocking variant "
            "is CPU: a synchronous read or a large JSON decode on the event-loop thread "
            "stalls every concurrent connection while the allocation/parse completes."
        ),
        "source": (
            "Declared lengths in protocol headers, chunked/compressed bodies, and "
            "length prefixes in binary payloads from clients."
        ),
        "sink": (
            "Data(capacity: remoteSize) / Array(repeating:count:) sized from external "
            "lengths; read loops appending into Data/String with no byte budget; "
            "decompression without output limits; unbounded request-body reads before "
            "the Content-Length cap is enforced"
        ),
        "guards": (
            "Check every input-derived length is compared to a fixed constant before "
            "allocation; check reads accumulate incrementally with a total-byte budget "
            "that aborts the connection; check decompression tracks output size and "
            "stops at the limit; check the framework's body-size limit is configured "
            "for server frameworks rather than left at 'unlimited'."
        ),
        "not_candidate_when": (
            "The transport layer already rejects bodies above a small cap before the "
            "handler runs and that cap is enforced on every path, the allocation size "
            "is a compile-time constant, or the stream is consumed incrementally with "
            "an enforced output budget."
        ),
        "vuln": "var buf = Data(capacity: remoteSize)",
        "safe": "guard remoteSize <= MAX_LIMIT else { return }; var buf = Data(capacity: remoteSize)",
        "signal": r"Data\(capacity:\s*remoteSize\)",
        "references": [
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "CWE-770: Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html",
            "CWE-409: Improper Handling of Highly Compressed Data (Data Amplification) — https://cwe.mitre.org/data/definitions/409.html",
        ],
    },
]
