"""Substantive per-card content for the TypeScript knowledge cards (ts-01..ts-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card carries real mechanism, source/sink, guard, and
disqualification text. Entries cite only public references believed to exist
(CWE pages, official TypeScript handbook documentation).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (TypeScript section).
TypeScript's defect class is fundamentally different from JavaScript's: most
of its guarantees exist only in the type checker and are erased by tsc, so
several cards here are compile-time-only constructs whose abuse manifests at
runtime in the emitted JavaScript.
"""

LANGUAGE = {
    "name": "TypeScript",
    "prefix": "ts",
}

CARDS = [
    {
        "num": "01",
        "title": "Type Erasure: Confusing Compile-Time Type with Runtime Validation",
        "platform": "Type annotations erased by tsc at emit time; the runtime behavior is plain JavaScript wherever the compiled output runs",
        "mechanism": (
            "A type assertion (req.body as UserProfile) adds no runtime "
            "instruction: tsc emits the value unchanged and the annotation "
            "exists only in the checker. Every property the interface declares "
            "-- required fields, string-typed role, numeric ID -- is simply "
            "absent, of another type, or attacker-chosen at runtime, and "
            "downstream code that 'trusted' the annotation dereferences "
            "undefined or compares attacker strings against privileged values. "
            "The assertion also silences exactly the checker error that would "
            "have flagged the missing validation, so the defect is invisible "
            "at compile time by construction."
        ),
        "source": (
            "Request bodies, JSON payloads, and any external data bound with "
            "'as T' or annotated as T without a runtime schema pass."
        ),
        "sink": (
            "'as T' assertions and typed parameters on data that crossed the "
            "network boundary without runtime validation feeding "
            "authorization, persistence, or business logic"
        ),
        "guards": (
            "Check the boundary parses through a runtime schema validator "
            "(zod/valibot-style .parse, io-ts, or hand-written narrowing) "
            "before the value is treated as T; check unknown is used at the "
            "boundary instead of any/as."
        ),
        "not_candidate_when": (
            "The asserted value was produced by an already-validated parse in "
            "the same module, the type describes data the code itself "
            "constructed (constants), or a validated schema decode is the "
            "first operation on the value."
        ),
        "vuln": "const body = req.body as UserProfile;",
        "safe": "const body = UserProfileSchema.parse(req.body);",
        "signal": r"req\.body\s+as\s+UserProfile",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "TypeScript Handbook: Narrowing — https://www.typescriptlang.org/docs/handbook/2/narrowing.html",
            "TypeScript Handbook: Everyday Types — https://www.typescriptlang.org/docs/handbook/2/everyday-types.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/2/narrowing.html",
    },
    {
        "num": "02",
        "title": "Type Escape Hatches at Security Boundaries",
        "platform": "Type-checker behavior only; any/as/!/@ts-ignore leave no runtime trace and apply wherever the compiled JavaScript runs",
        "mechanism": (
            "any disables checking for every expression derived from it, so one "
            "'const user: any = JSON.parse(data)' makes the entire downstream "
            "call graph unchecked while reading as type-safe. The double "
            "assertion 'as unknown as T' converts between unrelated types "
            "without an error, non-null '!' suppresses the undefined check "
            "exactly where null arrives from attacker-shaped payloads, and "
            "@ts-ignore deletes the diagnostic rather than fixing the cause. "
            "On an authorization path these constructs let a mis-typed role or "
            "missing field flow unchecked into grant/deny decisions."
        ),
        "source": (
            "External payloads entering through any-typed variables, double "
            "assertions, non-null assertions, or @ts-ignore-suppressed lines."
        ),
        "sink": (
            "any / as unknown as T / ! / @ts-ignore on values that feed "
            "authentication, authorization, or privilege fields"
        ),
        "guards": (
            "Check the boundary value flows through an explicit validation "
            "step rather than a type escape; check strict mode is enabled and "
            "escape hatches are counted in CI (no-explicit-any, no-non-null-"
            "assertion lint rules); check each suppressed diagnostic has a "
            "recorded justification."
        ),
        "not_candidate_when": (
            "The escape hatch sits on internal glue code whose value was "
            "validated at entry, the '!' guards a field that is structurally "
            "guaranteed non-null by a preceding validated parse, or the value "
            "is a test fixture never deployed."
        ),
        "vuln": "const user: any = JSON.parse(data); grant(user.role);",
        "safe": "const user = parseValidatedUser(data);",
        "signal": r"const\s+user:\s*any\s*=",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
            "TypeScript Handbook: Everyday Types (any and unknown) — https://www.typescriptlang.org/docs/handbook/2/everyday-types.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/2/everyday-types.html",
    },
    {
        "num": "03",
        "title": "Flawed Type Guards and Discriminated Union Bypass",
        "platform": "Type-checker behavior only; the guard body is plain JavaScript at runtime wherever the compiled output runs",
        "mechanism": (
            "A user-defined type guard ('x is Admin') is trusted unconditionally "
            "by the checker: whatever the body returns becomes the compiler's "
            "truth, so a guard that returns true (or tests a field the attacker "
            "controls) makes every later access type-correct at compile time "
            "and arbitrary at runtime. Discriminated unions have the same "
            "failure when the discriminant field (kind/type/role) comes from "
            "the payload: the attacker picks the variant, and narrowing "
            "selects the privileged branch of a switch written for internal "
            "values. Spread of an attacker object into a typed target also "
            "carries extra properties silently (excess property checks do not "
            "apply to spreads), performing batch assignment under a narrow type."
        ),
        "source": (
            "Request payloads and decoded JSON whose shape is decided by the "
            "client, then narrowed by guards or discriminant fields."
        ),
        "sink": (
            "'x is T' guard functions with permissive bodies; switch/match on "
            "payload-supplied discriminants gating privileged branches; "
            "spread of attacker objects into strongly-typed targets"
        ),
        "guards": (
            "Check each type guard body actually validates the fields it "
            "asserts (typeof/=== per member), check discriminant values are "
            "validated against a fixed set before narrowing drives privilege "
            "decisions, and check target objects are built field-by-field "
            "from validated input instead of spread."
        ),
        "not_candidate_when": (
            "The guard performs full field-level validation, the discriminant "
            "is computed server-side from validated data, or the narrowed "
            "branch is non-privileged and cannot affect authorization state."
        ),
        "vuln": "function isAdmin(x: any): x is Admin { return true; }",
        "safe": "function isAdmin(x: any): x is Admin { return x && x.role === 'admin'; }",
        "signal": r"function\s+isAdmin.*x\s+is\s+Admin\s*\{\s*return\s+true;",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "CWE-697: Incorrect Comparison — https://cwe.mitre.org/data/definitions/697.html",
            "TypeScript Handbook: Narrowing (type predicates) — https://www.typescriptlang.org/docs/handbook/2/narrowing.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/2/narrowing.html",
    },
    {
        "num": "04",
        "title": "Index Signatures Enabling Prototype Pollution",
        "platform": "Compiles to plain JavaScript property assignment; prototype-chain semantics of the runtime apply wherever the emitted JS runs",
        "mechanism": (
            "Record<string, T> and index-signature types tell the checker any "
            "key is acceptable, so map[userKey] = value compiles without "
            "question even when userKey is '__proto__'; at runtime that "
            "assignment re-points the object's prototype exactly as in the "
            "JavaScript prototype-pollution class. Without "
            "noUncheckedIndexedAccess, reading users[attackerId] is typed as "
            "T rather than T | undefined, so the undefined a miss returns "
            "propagates into authorization code as if it were a real record "
            "-- and a falsy-but-typed value can pass the wrong check."
        ),
        "source": (
            "Client-supplied keys (field names, column names, path segments) "
            "used to index or write into typed dictionaries."
        ),
        "sink": (
            "obj[attackerKey] = value on plain objects typed with index "
            "signatures; unguarded reads typed T from Record<string, T> "
            "feeding security decisions"
        ),
        "guards": (
            "Check keys are validated against an allowlist or matched against "
            "a key-pattern grammar before indexing; check storage uses "
            "Object.create(null) or Map<string, T>; check "
            "noUncheckedIndexedAccess is enabled so reads are T | undefined "
            "and handled."
        ),
        "not_candidate_when": (
            "The key comes from a fixed enum or allowlist, the container is a "
            "Map or null-prototype object immune to prototype writes, or the "
            "indexed value is re-validated after the read."
        ),
        "vuln": "const map: Record<string, any> = {}; map[userKey] = value;",
        "safe": "const map = new Map<string, any>(); map.set(userKey, value);",
        "signal": r"map\[userKey\]\s*=\s*value",
        "references": [
            "CWE-1321: Improperly Controlled Modification of Dynamically-Determined Object Attributes — https://cwe.mitre.org/data/definitions/1321.html",
            "TypeScript Handbook: More on Functions & Object Types (index signatures) — https://www.typescriptlang.org/docs/handbook/2/objects.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/2/objects.html",
    },
    {
        "num": "05",
        "title": "Numeric Enum Traps and Unchecked Literal Unions",
        "platform": "Numeric enums survive into emitted JS as reverse-mapping objects; const enums are erased -- both behaviors are tsc emit rules, runtime is the compiled JavaScript",
        "mechanism": (
            "A numeric enum parameter is only checked to be 'some number' at "
            "runtime: setRole(3.7) or setRole(-1) compiles when the caller "
            "holds the value as any/number, and because regular enums emit a "
            "lookup object, the runtime value never matches a declared member. "
            "const enums are fully erased, so a payload that claims a const-"
            "enum-typed field supplies any number with no runtime evidence. "
            "String literal unions used for roles or states have the same gap "
            "on the wire: the union exists only in the checker, so unvalidated "
            "'admin' strings arrive from payloads and drive privilege checks."
        ),
        "source": (
            "Decoded request fields typed as numeric enums, const enums, or "
            "string literal unions without a runtime membership check."
        ),
        "sink": (
            "Functions taking enum/literal-union parameters fed from external "
            "data; privilege and state checks comparing against enum members"
        ),
        "guards": (
            "Check every enum/literal-union value crossing the boundary is "
            "validated with a runtime membership test (a schema enum, "
            "Object.values includes, or exhaustive parse) before use; prefer "
            "string literal unions validated at parse time over numeric enums."
        ),
        "not_candidate_when": (
            "The enum value originates in server-side constants and never "
            "crosses deserialization, the value passed a validated schema "
            "enum parse, or the member cannot affect authorization."
        ),
        "vuln": "enum Role { User = 1, Admin = 2 }; function setRole(r: Role) { ... }",
        "safe": "type Role = 'User' | 'Admin';",
        "signal": r"enum\s+Role\s*\{.*User\s*=\s*1",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
            "TypeScript Handbook: Enums — https://www.typescriptlang.org/docs/handbook/enums.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/enums.html",
    },
    {
        "num": "06",
        "title": "Decorator-Driven Validation Gaps",
        "platform": "Experimental decorators and emitDecoratorMetadata are compile-time transforms; validation only runs if the framework reads that metadata at runtime",
        "mechanism": (
            "Validation declared purely as decorators (@ValidateRole) is inert "
            "data attached to the class: it executes only if the runtime "
            "actually loads reflect-metadata, imports the decorator's "
            "registering module, and invokes a validation pipeline over the "
            "metadata. Omit any of those -- enableMetadata off, tree-shaken "
            "side-effect import, no validation bootstrap -- and the compiled "
            "handler accepts anything while the source still reads as if a "
            "check exists. Missing metadata also fails silently: the "
            "validator sees no rules and returns 'valid' rather than erroring."
        ),
        "source": (
            "Request bodies and DTOs bound to decorator-annotated classes "
            "whose declared rules never execute at runtime."
        ),
        "sink": (
            "Validation/authorization decorators on properties or handlers "
            "that are trusted as enforced without verifying a runtime "
            "pipeline consumes them"
        ),
        "guards": (
            "Check a runtime validator is bootstrapped (metadata reflect "
            "polyfill imported, validation middleware invoked per request) "
            "and fails closed; check a test or integration point asserts "
            "invalid payloads are actually rejected."
        ),
        "not_candidate_when": (
            "A test in the same tree demonstrates invalid input is rejected "
            "at runtime, validation runs in explicit middleware independent "
            "of decorator metadata, or the annotation is documentation-only "
            "on an internal type with no external entry point."
        ),
        "vuln": "@ValidateRole userRole: string;",
        "safe": "@ValidateRole userRole: string; // ensure reflect-metadata enabled",
        "signal": r"@ValidateRole\s+userRole",
        "references": [
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
            "TypeScript Handbook: Decorators — https://www.typescriptlang.org/docs/handbook/decorators.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/decorators.html",
    },
    {
        "num": "07",
        "title": "Floating Promise in Security Handlers",
        "platform": "Promise semantics of the JavaScript runtime apply wherever the compiled JavaScript runs (Node.js server handlers, browsers)",
        "mechanism": (
            "verifyPermissions(req) without await starts the check and returns "
            "a Promise the handler discards; the next() call runs immediately, "
            "so the request is dispatched while the authorization is still "
            "pending -- and when the check later resolves or rejects, nothing "
            "consumes the result. A rejected permission check becomes an "
            "unhandled rejection (crash or log line) while the request already "
            "completed. The type signature reveals the bug (Promise<void> "
            "discarded) but tsc does not error without lint enforcement, so "
            "the hole ships silently."
        ),
        "source": (
            "Async authentication/authorization/rate-limit functions invoked "
            "in middleware and handlers whose Promise is not awaited."
        ),
        "sink": (
            "Discarded Promise results before security decisions and "
            "sensitive operations in middleware chains"
        ),
        "guards": (
            "Check every security-decision call in middleware is awaited "
            "before next(); check the codebase enforces no-floating-promises "
            "(eslint rule) in CI; check rejections in these handlers fail "
            "closed by short-circuiting the response."
        ),
        "not_candidate_when": (
            "The operation is deliberately parallel with a later await/"
            "Promise.all before the guarded branch, the function is "
            "synchronous, or the middleware awaits inside a wrapper that "
            "propagates rejection into the response path."
        ),
        "vuln": "app.use((req, res, next) => { verifyPermissions(req); next(); });",
        "safe": "app.use(async (req, res, next) => { await verifyPermissions(req); next(); });",
        "signal": r"verifyPermissions\(req\);\s*next\(\);",
        "references": [
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
            "TypeScript Handbook: tsc CLI options (strict family) — https://www.typescriptlang.org/docs/handbook/compiler-options.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/compiler-options.html",
    },
    {
        "num": "08",
        "title": "Compiler Flag Relaxation Causing Verification Holes",
        "platform": "tsconfig.json compile-time settings; strictNullChecks relaxation changes only the checker, emitted JavaScript runs wherever deployed",
        "mechanism": (
            "With strictNullChecks off, the checker removes undefined from "
            "every type, so users[id] typed 'User' is believed non-undefined "
            "while the runtime lookup returns undefined for attacker-chosen "
            "IDs; the annotated return type then 'guarantees' a value the "
            "code never checked, and guards that look redundant are actually "
            "absent. skipLibCheck hides mismatched declaration files whose "
            "types disagree with runtime behavior, and path aliases can "
            "resolve a shimmed module -- the compiled output then imports "
            "something other than the audited implementation."
        ),
        "source": (
            "Lookup keys and IDs from requests, and configuration drift "
            "between tsconfig/lib types and the runtime the bundle uses."
        ),
        "sink": (
            "Index lookups and dereferences typed non-nullable under relaxed "
            "flags, feeding authorization or null-dereference-prone logic"
        ),
        "guards": (
            "Check tsconfig enables strict (at minimum strictNullChecks), "
            "lookups on attacker-influenced keys are handled as possibly "
            "undefined at runtime, and declaration files for security-relevant "
            "modules match the runtime implementation."
        ),
        "not_candidate_when": (
            "Strict mode is on and the lookup result is narrowed before use, "
            "the key comes from a fixed internal set, or the failure path is "
            "non-security and contained."
        ),
        "vuln": "function get(id: string): User { return users[id]; }",
        "safe": "function get(id: string): User | undefined { return users[id]; }",
        "signal": r"function\s+get\(id:\s*string\):\s*User",
        "references": [
            "CWE-754: Improper Check for Unusual or Exceptional Conditions — https://cwe.mitre.org/data/definitions/754.html",
            "TypeScript Handbook: compiler-options — https://www.typescriptlang.org/docs/handbook/compiler-options.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/compiler-options.html",
    },
    {
        "num": "09",
        "title": "Compile-Time Access Control Bypass via Runtime Inspection",
        "platform": "'private'/'readonly' exist only in tsc and are erased at emit; ES '#private' fields are enforced by the runtime (V8 and all ES2022 engines)",
        "mechanism": (
            "The 'private' modifier is a checker-only annotation: tsc emits the "
            "field as an ordinary property, so (obj as any).key, JSON "
            "round-trips, and Object.entries all read or overwrite it. "
            "Class instances rebuilt from payloads lose the invariant the "
            "type declared, because deserialization assigns plain fields "
            "without running the constructor that established them. '#private' "
            "fields are hard slots at the engine level: external code cannot "
            "reach them even with any-casts, and deserialization cannot "
            "forge them."
        ),
        "source": (
            "Deserialized objects, any-casts, and reflective access to "
            "instances whose internal fields gate security behavior."
        ),
        "sink": (
            "private/readonly fields holding credentials, roles, or invariants "
            "that can be read or rewritten from outside the class"
        ),
        "guards": (
            "Check secrets and security invariants use '#private' (or closures/"
            "WeakMap) rather than the modifier keyword; check deserialization "
            "paths reconstruct instances through validated constructors or "
            "static fromJSON factories instead of plain assignment."
        ),
        "not_candidate_when": (
            "The private field is non-security and its corruption is contained, "
            "the class is never reconstructed from external data, or '#private'"
            "is already used for the security-relevant state."
        ),
        "vuln": "class Secret { private key: string = 'token'; }",
        "safe": "class Secret { #key: string = 'token'; }",
        "signal": r"class\s+Secret\s*\{\s*private\s+key",
        "references": [
            "CWE-668: Exposure of Resource to Wrong Sphere — https://cwe.mitre.org/data/definitions/668.html",
            "TypeScript Handbook: Classes — https://www.typescriptlang.org/docs/handbook/2/classes.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/2/classes.html",
    },
    {
        "num": "10",
        "title": "Serialization Boundary Precision Loss on Large Integers",
        "platform": "IEEE-754 double semantics of the JavaScript runtime (Number); applies wherever JSON payloads cross into the compiled JS",
        "mechanism": (
            "JSON.parse returns any and converts every number to a 64-bit "
            "double, so 64-bit identifiers (snowflake IDs, Discord/GitHub "
            "object IDs, 64-bit epochs) lose precision above 2^53: two "
            "different IDs parse to the same Number, and an authorization "
            "check or ownership comparison then matches the wrong record -- "
            "an attacker picks an ID that rounds onto the victim's. Date "
            "round-trips shift by timezone/millis rules and bigint fields "
            "silently become Number (lossy) or string (type confusion) "
            "depending on the serializer, so the value compared at the guard "
            "is not the value the client sent."
        ),
        "source": (
            "JSON request/response bodies, third-party API payloads, and "
            "event streams carrying 64-bit numeric identifiers or timestamps."
        ),
        "sink": (
            "JSON.parse of numeric fields used as IDs in authorization, "
            "ownership, or deduplication comparisons; Number coercion of "
            "bigint/date fields at service boundaries"
        ),
        "guards": (
            "Check 64-bit IDs are transported and compared as strings or "
            "BigInt end to end (JSON big-integer serialization), check "
            "parsed payloads pass a schema that pins ID fields to string "
            "type, and check Date fields round-trip through explicit ISO "
            "string parsing rather than numeric coercion."
        ),
        "not_candidate_when": (
            "IDs are already strings on the wire, the numeric range is "
            "provably below 2^53 by schema, or the compared value is "
            "regenerated server-side rather than taken from the payload."
        ),
        "vuln": "const id = JSON.parse(jsonPayload).id;",
        "safe": "const id = BigInt(JSONBig.parse(jsonPayload).id);",
        "signal": r"JSON\.parse\(jsonPayload\)\.id",
        "references": [
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "TypeScript Handbook: Narrowing / Everyday Types (Number limits) — https://www.typescriptlang.org/docs/handbook/2/everyday-types.html",
        ],
        "doc_url": "https://www.typescriptlang.org/docs/handbook/2/everyday-types.html",
    },
]
