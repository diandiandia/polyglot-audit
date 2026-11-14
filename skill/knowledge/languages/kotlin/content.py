"""Substantive per-card content for the Kotlin knowledge cards (kotlin-01..kotlin-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, official Android / Kotlin / JDK documentation).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Kotlin section).
"""

LANGUAGE = {
    "name": "Kotlin",
    "prefix": "kotlin",
}

CARDS = [
    {
        "num": "01",
        "title": "Java Interop Null-Safety Gaps Leading to Panic",
        "platform": (
            "Kotlin/JVM language semantics; applies wherever Kotlin compiles to JVM "
            "bytecode (server JVM and Android runtime both)"
        ),
        "mechanism": (
            "Kotlin's null safety is a compile-time type system, and every value coming "
            "from Java code arrives as a platform type (String!), a type the compiler "
            "neither null-checks nor forbids dereferencing. The null-safety invariant is "
            "therefore only as good as the assumption the Kotlin call site asserts: '!!' "
            "compiles to an intrinsic that throws KotlinNullPointerException at runtime "
            "when the Java callee returned null, and assigning a platform type to a "
            "non-null Kotlin variable throws an implicit NullPointerException later at "
            "the first use. On request-reachable paths this turns one unexpected Java "
            "return value into a guaranteed crash rather than a rejected input; "
            "lateinit val reads behave the same way, throwing "
            "UninitializedPropertyAccessException when initialization was skipped."
        ),
        "source": (
            "Any Java-side value crossing into Kotlin: return values of Java methods fed "
            "by request data, Java framework callbacks, deserialized Java objects whose "
            "fields the attacker controls to be null."
        ),
        "sink": (
            "'!!' non-null assertions on platform types, implicit assignment of platform "
            "types to non-null Kotlin types, and lateinit property reads on "
            "attacker-influenced paths"
        ),
        "guards": (
            "Check the call site handles the platform type explicitly: elvis with a safe "
            "fallback ('?: return null' / '?: throw'), safe-call chains ('?.'), or a "
            "requireNotNull(...) check with a handled failure before any further use; "
            "verify lateinit properties have an ::isInitialized guard or are replaced "
            "by nullable types on input-driven paths."
        ),
        "not_candidate_when": (
            "The Java callee is contractually non-null and locally verified (returns a "
            "freshly constructed object, never null), the assertion sits on a value the "
            "server itself produced rather than on request data, or the failure is "
            "handled (elvis/requireNotNull) and cannot crash a shared process on a "
            "request path."
        ),
        "vuln": "val user = javaApi.getUser()!!",
        "safe": "val user = javaApi.getUser() ?: return null",
        "signal": r"javaApi\.getUser\(\)!!",
        "references": [
            "CWE-476: NULL Pointer Dereference — https://cwe.mitre.org/data/definitions/476.html",
            "Kotlin documentation: calling Java from Kotlin and platform types — https://kotlinlang.org/docs/java-interop.html",
            "Kotlin documentation: null safety — https://kotlinlang.org/docs/null-safety.html",
        ],
        "doc_url": "https://kotlinlang.org/docs/java-interop.html",
    },
    {
        "num": "02",
        "title": "Android Exported Component Intent Redirection",
        "platform": "Android runtime (API level 1+; component export semantics tightened in Android 12 / API 31, which requires an explicit android:exported declaration)",
        "mechanism": (
            "An exported Activity/Service/Receiver is invokable by any app on the device. "
            "A common redirection pattern reads an Intent (or a URI) out of the incoming "
            "Intent's extras and hands it to startActivity()/sendBroadcast()/bindService() "
            "without checking the embedded component. A malicious app then supplies an "
            "explicit Intent targeting one of YOUR privileged non-exported components, "
            "or carrying extras those components trust; because the forwarding app is "
            "the caller of record, the privileged component's permission and identity "
            "checks pass even though the payload originated from the attacker. Mutable "
            "PendingIntents (FLAG_MUTABLE absent) have the same shape: the filling app "
            "can rewrite the wrapped Intent's extras before it fires."
        ),
        "source": (
            "An attacker-controlled Intent delivered to the exported component: extras, "
            "the embedded Intent object itself, or a deep-link URI parsed from it."
        ),
        "sink": (
            "startActivity/getParcelableExtra(\"forward\")-style forwarding to "
            "startActivity(), startActivityForResult(), sendBroadcast(), "
            "bindService(); PendingIntent.getActivity/getBroadcast with a "
            "non-immutable (FLAG_IMMUTABLE missing) wrapped Intent"
        ),
        "guards": (
            "Check the forwarded Intent is validated before use: its component/class "
            "compared against an allowlist, its action/data URI scheme checked, extras "
            "re-validated, and the wrapper PendingIntent created with FLAG_IMMUTABLE; "
            "check the manifest marks components non-exported unless externally "
            "reachable (android:exported=\"false\" or the absence of intent-filters on "
            "internal components); check the component sets "
            "Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or otherwise defends when "
            "forwarding is genuinely required."
        ),
        "not_candidate_when": (
            "The component is not exported (no intent-filter and "
            "android:exported=\"false\"), so no other app can deliver the Intent; the "
            "forwarded Intent is constructed entirely inside the app from validated "
            "fields; or the embedded Intent is resolved against a fixed allowlist of "
            "in-app components before startActivity is called."
        ),
        "vuln": "startActivity(intent.getParcelableExtra(\"forward\"))",
        "safe": "val target = intent.getParcelableExtra<Intent>(\"forward\"); if (isValid(target)) startActivity(target)",
        "signal": r"startActivity\(intent\.getParcelableExtra",
        "references": [
            "CWE-926: Improper Export of Android Application Components — https://cwe.mitre.org/data/definitions/926.html",
            "CWE-927: Use of Implicit Intent for Sensitive Communication — https://cwe.mitre.org/data/definitions/927.html",
            "Android developer documentation: security tips (Intents and PendingIntents) — https://developer.android.com/privacy-and-security/security-tips",
            "Android developer documentation: activity element (android:exported) — https://developer.android.com/guide/topics/manifest/activity-element.html",
            "Android developer documentation: PendingIntent — https://developer.android.com/reference/android/app/PendingIntent.html",
        ],
        "doc_url": "https://developer.android.com/privacy-and-security/security-tips",
    },
    {
        "num": "03",
        "title": "Unsafe Deserialization in Intent Extras",
        "platform": "Android runtime (API level 1+ for getSerializableExtra/getParcelableExtra; the type-checked variants getSerializableExtra(name, Class) exist from API 33)",
        "mechanism": (
            "Intent extras carrying Serializable/Parcelable objects are deserialized by "
            "the OS from the Parcel the sending app wrote, so any app that can reach the "
            "component chooses both the class and the field values of the reconstructed "
            "object. getSerializableExtra instantiates whatever class name the attacker "
            "encoded, which turns every serializable helper class into a gadget: a class "
            "whose readObject/equals/toString performs file, network, or command "
            "operations is invoked during deserialization or later use. The same trust "
            "shape appears with reflection-based binding frameworks that populate Kotlin "
            "non-null fields from untrusted bundles, yielding null in fields the type "
            "system promised are non-null."
        ),
        "source": (
            "Extras of Intents delivered by other apps (exported components), deep-link "
            "URIs, or bundles restored from untrusted storage/notifications."
        ),
        "sink": (
            "intent.getSerializableExtra / getParcelableExtra without class validation; "
            "Bundle.getSerializable on attacker-supplied bundles; reflective "
            "bundle-to-object binding that bypasses constructors"
        ),
        "guards": (
            "Check the deserialized object's runtime type against an expected class "
            "before use (the API 33+ typed getSerializableExtra(name, MyClass::class.java) "
            "variant, or an instanceof check on older levels); check the receiving "
            "component is not exported or rejects Intents from untrusted packages "
            "(callingPackage checks / signature permissions); check no gadget classes "
            "with side-effecting Serializable implementations are reachable."
        ),
        "not_candidate_when": (
            "The component only receives Intents the app itself created and sends "
            "(non-exported, or PendingIntent it filled itself with FLAG_IMMUTABLE), the "
            "extra is read with the type-checked API-33+ variant constrained to a "
            "concrete data class, or the deserialized object is a plain data holder "
            "whose every field is validated before any sensitive use."
        ),
        "vuln": "val data = intent.getSerializableExtra(\"data\")",
        "safe": "val data = IntentCompat.getSerializableExtra(intent, \"data\", MyClass::class.java)",
        "signal": r"intent\.getSerializableExtra\(",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "Android developer documentation: security tips — https://developer.android.com/privacy-and-security/security-tips",
        ],
        "doc_url": "https://developer.android.com/privacy-and-security/security-tips",
    },
    {
        "num": "04",
        "title": "WebView Javascript Interface and File Scheme Hazards",
        "platform": "Android runtime (API level 1+ for WebView; @JavascriptInterface-annotated bridge methods are enforced from API 17+, which is why pre-17 bridges expose every public method)",
        "mechanism": (
            "addJavascriptInterface publishes a Java/Kotlin object into every frame of "
            "the page as window.<name>, and any JavaScript running in the WebView can "
            "call its public methods; from API 17+ only @JavascriptInterface methods "
            "are reachable, but on older levels ALL public methods — including "
            "inherited Class reflection helpers — are invokable. When "
            "setJavaScriptEnabled is combined with allowFileAccess/setAllowFileAccessFromFileURLs "
            "or setAllowUniversalAccessFromFileURLs, script in a file:// context can "
            "read the app's private files and issue same-origin-free requests. Loading "
            "an attacker-influenced URL (open redirect, user content, MITM on http) "
            "then gives the attacker's script the native bridge as a primitive."
        ),
        "source": (
            "Remote web content loaded into the WebView (user URLs, attacker-modified "
            "responses, injected iframe content) and anything that content can induce "
            "the bridge to do."
        ),
        "sink": (
            "webView.addJavascriptInterface(bridge, \"name\") combined with "
            "settings.javaScriptEnabled = true; settings.allowFileAccess / "
            "allowFileAccessFromFileURLs / allowUniversalAccessFromFileURLs = true; "
            "webView.loadUrl with an unvalidated remote URL"
        ),
        "guards": (
            "Check the bridge object exposes only @JavascriptInterface-annotated methods "
            "that validate their arguments and never return secrets or accept file "
            "paths; check file access switches are disabled (allowFileAccess=false, "
            "both FromFileURLs flags=false) and content is loaded over https from an "
            "allowlisted host; check setWebContentsDebuggingEnabled is off in release "
            "builds."
        ),
        "not_candidate_when": (
            "The WebView loads only bundled local help content with JavaScript disabled, "
            "or the bridge methods are inert (pure UI callbacks validating their "
            "arguments) and file access flags are off, or the loaded URL is a "
            "compile-time constant https endpoint the app controls."
        ),
        "vuln": "webView.addJavascriptInterface(bridge, \"nativeApp\")",
        "safe": "webView.settings.allowFileAccess = false; /* restrict bridge */",
        "signal": r"webView\.addJavascriptInterface\(",
        "references": [
            "CWE-749: Exposed Dangerous Method or Function — https://cwe.mitre.org/data/definitions/749.html",
            "Android developer documentation: WebView — https://developer.android.com/reference/android/webkit/WebView.html",
        ],
        "doc_url": "https://developer.android.com/reference/android/webkit/WebView.html",
    },
    {
        "num": "05",
        "title": "Coroutine Concurrency and Shared Mutable State",
        "platform": (
            "Kotlin/JVM with kotlinx.coroutines; applies on both server JVM and Android "
            "runtime (Dispatchers.Default/IO share worker threads on both)"
        ),
        "mechanism": (
            "Coroutines do not serialize memory: a suspend call can resume on a different "
            "worker thread, so a plain var or shared collection touched across a "
            "suspension point is a data race, not just a logic bug. GlobalScope.launch "
            "escapes structured concurrency — the work outlives its scope, cannot be "
            "cancelled with the caller, and its failures surface as an unhandled "
            "exception in a process-wide handler (on Android this crashes the app; on a "
            "server it can bypass the request's error path). launch/async swallow the "
            "body's exception until join/await is called, so a failed authorization "
            "write can disappear silently when the returned Deferred is never awaited."
        ),
        "source": (
            "Concurrent requests or UI events driving the same shared state; attacker-"
            "shaped inputs that race two interleaved coroutine runs against one "
            "check-then-act sequence."
        ),
        "sink": (
            "GlobalScope.launch / GlobalScope.async; reads and writes of shared vars or "
            "collections inside coroutines without Mutex/actor/confined dispatcher; "
            "check-then-act sequences separated by a suspension point (withContext, "
            "delay, network calls)"
        ),
        "guards": (
            "Check shared state is confined: Mutex.withLock, atomic types, an actor/"
            "Channel serialized to one coroutine, or a single-threaded dispatcher "
            "owning the state; check coroutines run inside lifecycle- or request-scoped "
            "CoroutineScope instead of GlobalScope; check every async() result is "
            "awaited or its exception explicitly handled (supervisorScope + handler)."
        ),
        "not_candidate_when": (
            "The state is immutable or constructed per-coroutine, the shared value is a "
            "confined single-threaded dispatcher's data, or the launch is an isolated "
            "fire-and-forget task with no shared memory and a handled failure path."
        ),
        "vuln": "GlobalScope.launch { counter++ }",
        "safe": "val mutex = Mutex(); launch { mutex.withLock { counter++ } }",
        "signal": r"GlobalScope\.launch\s*\{\s*counter\+\+",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "Kotlin documentation: coroutines overview — https://kotlinlang.org/docs/coroutines-overview.html",
        ],
        "doc_url": "https://kotlinlang.org/docs/coroutines-overview.html",
    },
    {
        "num": "06",
        "title": "SQL Injection via String Template in rawQuery",
        "platform": "Android runtime (API level 1+ for SQLiteDatabase.rawQuery and execSQL)",
        "mechanism": (
            "SQLiteDatabase.rawQuery and execSQL execute the statement text as given; a "
            "Kotlin string template ('... WHERE id = \\'$id\\'') splices the value into "
            "the SQL before the database parser sees it, so a value containing a quote "
            "or SQL syntax changes the statement structure. Local SQLite injection is "
            "not limited to one app's rows: providers and databases often hold "
            "cross-user or synced data, and injection in a query feeding "
            "CursorAdapter/content-provider results leaks rows the caller should not "
            "read. The '?' placeholder + selectionArgs form binds the value out-of-band "
            "and cannot alter the parse."
        ),
        "source": (
            "Deep-link parameters, Intent extras, content-provider URIs, or IPC values "
            "from other apps that reach the query through uri.lastPathSegment or "
            "query parameters."
        ),
        "sink": (
            "db.rawQuery / db.execSQL / SQLiteQueryBuilder query built with Kotlin "
            "string templates or concatenation instead of selectionArgs"
        ),
        "guards": (
            "Check the statement uses the placeholder form (rawQuery(sql with '?', "
            "arrayOf(value)) or SQLiteQueryBuilder with selectionArgs); identifiers that "
            "cannot be bound (column names, ORDER BY) must come from a fixed allowlist; "
            "for ContentProvider openFile/query, check uri.lastPathSegment is validated "
            "against an allowlist or pattern before being spliced into a path or query."
        ),
        "not_candidate_when": (
            "The value travels in selectionArgs (placeholder binding), the interpolated "
            "part is a server/app-internal constant chosen from an allowlist, or the "
            "input is strictly validated to a narrow grammar (integer ID) before "
            "reaching the query."
        ),
        "vuln": "db.rawQuery(\"SELECT * FROM items WHERE id = '$id'\", null)",
        "safe": "db.rawQuery(\"SELECT * FROM items WHERE id = ?\", arrayOf(id))",
        "signal": r"rawQuery\(\"SELECT.*\$id",
        "references": [
            "CWE-89: Improper Neutralization of Special Elements in SQL Command — https://cwe.mitre.org/data/definitions/89.html",
            "Android developer documentation: SQLiteDatabase — https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html",
        ],
        "doc_url": "https://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html",
    },
    {
        "num": "07",
        "title": "Process Execution via String Template Commands",
        "platform": (
            "Kotlin/JVM semantics over java.lang.Runtime / java.lang.ProcessBuilder; "
            "applies on server JVM and Android runtime (Runtime.exec available since "
            "API level 1)"
        ),
        "mechanism": (
            "Runtime.getRuntime().exec(String) tokenizes the whole command line with "
            "StringTokenizer (whitespace splitting, no shell quoting rules), so a value "
            "containing spaces or shell metacharacters either breaks into extra argv "
            "elements or — when the string is passed through 'sh -c' — is interpreted "
            "by the shell with full metacharacter semantics (';', '|', '$(...)'). "
            "Kotlin string templates make this splice invisible at the call site: "
            "\"sh -c $cmd\" looks like one fixed command while $cmd contributes the "
            "actual program. Argument injection also occurs without a shell when an "
            "input starting with '-' becomes an option of the launched program."
        ),
        "source": (
            "Deep-link/Intent parameters, exported-component extras, or server-side "
            "request data that reach the executed command string or an argv element."
        ),
        "sink": (
            "Runtime.getRuntime().exec with a template or concatenated string, "
            "ProcessBuilder with a single shell string, and any exec wrapped in "
            "'sh -c' or 'su -c'"
        ),
        "guards": (
            "Check the process is started with ProcessBuilder and an argv list with a "
            "fixed executable and the dynamic value as one element (never through a "
            "shell); if a shell is unavoidable, verify quoting/escaping and strict "
            "allowlist validation of the value; check '-'-prefixed inputs cannot reach "
            "a program that parses options (positional separator '--' or validation)."
        ),
        "not_candidate_when": (
            "The command is a fixed constant with no interpolation, the dynamic value "
            "is one argv element to a program that takes no options, or the value is "
            "validated against a strict allowlist grammar that excludes metacharacters "
            "before the call."
        ),
        "vuln": "Runtime.getRuntime().exec(\"sh -c $cmd\")",
        "safe": "ProcessBuilder(\"/bin/safe\", arg).start()",
        "signal": r"Runtime\.getRuntime\(\)\.exec\(\"sh -c \$cmd\"\)",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-88: Argument Injection or Modification — https://cwe.mitre.org/data/definitions/88.html",
            "JDK documentation: java.lang.Runtime.exec — https://docs.oracle.com/javase/8/docs/api/java/lang/Runtime.html",
            "JDK documentation: java.lang.ProcessBuilder — https://docs.oracle.com/javase/8/docs/api/java/lang/ProcessBuilder.html",
        ],
        "doc_url": "https://docs.oracle.com/javase/8/docs/api/java/lang/ProcessBuilder.html",
    },
    {
        "num": "08",
        "title": "Insecure Storage and Hardcoded Cryptographic Keys",
        "platform": "Android runtime (API level 1+ for SharedPreferences; the AndroidKeyStore provider exists from API 18)",
        "mechanism": (
            "SharedPreferences writes a plaintext XML file in the app sandbox; on "
            "rooted devices, in backups (android:allowBackup), and through any sandbox "
            "escape the file is readable, so auth tokens and keys stored there are "
            "recoverable offline. Keys compiled into the app ship in the APK/dex and "
            "are extracted with static analysis by anyone who downloads it, so "
            "'encrypted with a hardcoded key' is only obfuscation. Cipher.getInstance(\"AES\") "
            "without a transformation returns AES/ECB/PKCS5Padding, which encrypts "
            "equal plaintext blocks to equal ciphertext and leaks structure; keys "
            "generated outside the AndroidKeyStore provider stay extractable from the "
            "filesystem."
        ),
        "source": (
            "The stored material itself: session tokens, refresh tokens, user data, "
            "and keys/constants embedded in the app binary."
        ),
        "sink": (
            "prefs.edit().putString(\"token\", ...) for secrets; hardcoded key strings/"
            "byte arrays passed to SecretKeySpec; Cipher.getInstance(\"AES\") or any "
            "ECB transformation; writes to external storage"
        ),
        "guards": (
            "Check secrets live in the Android Keystore (AndroidKeyStore provider, "
            "KeyGenParameterSpec with ENCRYPT_MODE purposes) or in "
            "EncryptedSharedPreferences/AndroidX security-crypto backed by it, not in "
            "plain SharedPreferences; check no key material appears as a string or "
            "literals in the source/APK; check Cipher.getInstance names a full "
            "transformation with GCM or CBC + random IV and MAC; check "
            "android:allowBackup=\"false\" or backup rules exclude the secrets store."
        ),
        "not_candidate_when": (
            "The stored value is non-sensitive (UI prefs, cache), the key is generated "
            "inside AndroidKeyStore and never leaves secure hardware, or the cipher is "
            "fully specified (AES/GCM/NoPadding) with keys from the Keystore and the "
            "only plaintext values are non-secret."
        ),
        "vuln": "prefs.edit().putString(\"auth_token\", token).apply()",
        "safe": "EncryptedSharedPreferences.create(...).edit().putString(\"token\", token).apply()",
        "signal": r"prefs\.edit\(\)\.putString\(\"auth_token\"",
        "references": [
            "CWE-312: Cleartext Storage of Sensitive Information — https://cwe.mitre.org/data/definitions/312.html",
            "CWE-798: Use of Hard-coded Credentials — https://cwe.mitre.org/data/definitions/798.html",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "Android developer documentation: Android Keystore system — https://developer.android.com/training/articles/keystore.html",
            "Android developer documentation: KeyStore — https://developer.android.com/reference/java/security/KeyStore.html",
            "Android developer documentation: Cipher — https://developer.android.com/reference/javax/crypto/Cipher.html",
        ],
        "doc_url": "https://developer.android.com/training/articles/keystore.html",
    },
    {
        "num": "09",
        "title": "TLS and TrustManager Bypass in Network Callbacks",
        "platform": (
            "javax.net.ssl on JVM and Android runtime (API level 1+ for "
            "SSLSocketFactory/X509TrustManager; Network Security Config requires "
            "API 24+)"
        ),
        "mechanism": (
            "A custom X509TrustManager whose checkServerTrusted body is empty (or only "
            "logs) makes every certificate chain accepted, so a machine with a hostile "
            "network position — attacker AP, compromised router, malicious proxy — "
            "terminates TLS invisibly; a HostnameVerifier returning true removes the "
            "hostname match the same way. This is usually added to silence a "
            "self-signed-certificate exception in debug and then shipped. Because the "
            "trust decision is inside the app, TLS loses its endpoint-authentication "
            "property entirely: tokens, session cookies, and user data flow in "
            "plaintext to the attacker while the UI still shows a secure connection."
        ),
        "source": (
            "The network position itself: any response the attacker substitutes on the "
            "path between device and server, accepted because the app disabled chain "
            "and hostname validation."
        ),
        "sink": (
            "sslSocketFactory(untrustedFactory, trustAllManager) / "
            "hostnameVerifier { _, _ -> true } / X509TrustManager with empty "
            "checkServerTrusted / SSLSocketFactory created from a null-trust SSLContext; "
            "cleartext http:// endpoints enabled via usesCleartextTraffic or an ATS-style "
            "networkSecurityConfig exception"
        ),
        "guards": (
            "Check the installed trust manager actually verifies the chain and throws "
            "on failure (or that no custom manager is installed at all); check "
            "HostnameVerifier is absent or delegates to the default; check network "
            "security config does not blanket-disable cleartext or add user-added CAs "
            "for release builds; check certificate pinning (CertificatePinner / "
            "networkSecurityConfig pins) for high-value endpoints."
        ),
        "not_candidate_when": (
            "The trust-all factory is confined to unit tests or debug variants and "
            "cannot ship in release builds, the custom manager genuinely validates the "
            "chain against a pinned set (self-signed pinning is a legitimate use), or "
            "the endpoint carries no secret and only fetches public static content."
        ),
        "vuln": "builder.sslSocketFactory(trustAllSslSocketFactory, trustAllManager)",
        "safe": "builder.certificatePinner(pinner)",
        "signal": r"builder\.sslSocketFactory\(trustAll",
        "references": [
            "CWE-295: Improper Certificate Validation — https://cwe.mitre.org/data/definitions/295.html",
            "Android developer documentation: security tips (networking) — https://developer.android.com/privacy-and-security/security-tips",
            "Android developer documentation: Network Security Config — https://developer.android.com/training/articles/security-config.html",
        ],
        "doc_url": "https://developer.android.com/training/articles/security-config.html",
    },
    {
        "num": "10",
        "title": "Kotlin Language Traps: copy() Bypassing Validation",
        "platform": (
            "Kotlin/JVM language semantics (data classes, smart casts, runCatching, "
            "when-exhaustiveness); applies to JVM and Android targets alike"
        ),
        "mechanism": (
            "Data classes generate a public copy() that constructs a new instance "
            "without running the primary constructor's require()/init checks, so "
            "invariants enforced at construction ('role must be USER unless promoted') "
            "evaporate on the first copy(role = \"admin\"). Smart casts on shared var "
            "properties re-read the field after the check, so another thread's write "
            "between 'if (x is Admin)' and the use invalidates the cast's premise. "
            "runCatching { }.getOrNull() and '?: default' convert any authorization "
            "failure — including deliberate denial exceptions — into a silent null that "
            "downstream code may treat as 'unprivileged but valid', and a non-exhaustive "
            "when over a sealed hierarchy compiles to a fall-through that leaves "
            "unexpected roles at the else branch's (often permissive) behavior."
        ),
        "source": (
            "Request-derived user/role objects, deserialized models, and concurrent "
            "request threads mutating shared state used by authorization checks."
        ),
        "sink": (
            "user.copy(role = ...) on objects carrying authorization state; smart casts "
            "on shared mutable properties guarding security decisions; "
            "runCatching{}.getOrNull() / '?:' defaults around authentication or "
            "permission calls; non-exhaustive when on role/state enums"
        ),
        "guards": (
            "Check privileged state transitions go through explicit validated functions "
            "rather than generated copy(); check security-relevant types are immutable "
            "vals (or custom classes without copy) whose init blocks validate; check "
            "auth failures propagate as thrown/returned denials instead of being "
            "collapsed by runCatching/elvis; check when blocks are exhaustive over the "
            "sealed hierarchy or end in a denying else."
        ),
        "not_candidate_when": (
            "copy() is used on DTOs with no authorization invariants and the privileged "
            "transition is gated server-side, the smart cast targets a local immutable "
            "value or the property is confined to one thread, or the when covers all "
            "cases with a default that denies rather than grants."
        ),
        "vuln": "val unauthorized = user.copy(role = \"admin\")",
        "safe": "fun User.promote(auth: Auth) = ...",
        "signal": r"user\.copy\(role\s*=\s*\"admin\"\)",
        "references": [
            "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
            "Kotlin documentation: data classes (generated copy) — https://kotlinlang.org/docs/data-classes.html",
            "Kotlin documentation: null safety and smart casts — https://kotlinlang.org/docs/null-safety.html",
        ],
        "doc_url": "https://kotlinlang.org/docs/data-classes.html",
    },
]
