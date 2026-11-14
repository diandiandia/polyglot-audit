"""Substantive per-card content for the Rust knowledge cards (rust-01..rust-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, Rust standard library docs, The Rustonomicon).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (Rust section).
"""

LANGUAGE = {
    "name": "Rust",
    "prefix": "rust",
}

CARDS = [
    {
        "num": "01",
        "title": "Unsoundness in Unsafe Memory Operations",
        "platform": (
            "Any Rust toolchain (stable/nightly); unsafe blocks bypass the borrow "
            "checker on every target and optimization level"
        ),
        "mechanism": (
            "Rust's safety guarantees are a contract the programmer must uphold "
            "inside every unsafe block: slice::from_raw_parts(ptr, len) builds a "
            "&[T] valid only if ptr points to len live, initialized, aligned "
            "elements for the slice's whole lifetime. A length taken from a "
            "protocol header or peer makes the contract attacker-controlled, so "
            "the resulting slice lets safe code — which the compiler assumes "
            "cannot access invalid memory — read or write far past the real "
            "allocation. The same holds for transmute (reinterpreting bytes as a "
            "different type, breaking size or layout invariants), MaybeUninit::"
            "assume_init (asserting initialization that never happened), "
            "get_unchecked (asserting a bound that was never checked), and "
            "Vec::set_len (asserting elements exist that were never constructed). "
            "Because the type system now believes the lie, the optimizer may "
            "elide the real bounds checks that would have caught the access."
        ),
        "source": (
            "Lengths, pointers, and layout assumptions derived from peer data: "
            "wire-format length prefixes, FFI-returned pointers and counts, "
            "descriptor tables."
        ),
        "sink": (
            "unsafe { slice::from_raw_parts / from_raw_parts_mut } with an external "
            "length; transmute; MaybeUninit::assume_init; get_unchecked(_mut); "
            "Vec::set_len"
        ),
        "guards": (
            "Check that the length/pointer is validated against a real bound "
            "(allocation size, protocol maximum) BEFORE entering the unsafe block, "
            "that the provenance of the pointer is documented and within-lifetime, "
            "and that initialization claims (assume_init, set_len) are backed by "
            "writes that already happened; flag any unsafe block whose inputs "
            "include unvalidated external values."
        ),
        "not_candidate_when": (
            "The unsafe block's length is clamped to the real allocation before "
            "entry and the bound is enforced in safe code, the pointer/length come "
            "from a checked internal invariant established at construction, or the "
            "block is covered by a reviewed abstraction whose safe API validates "
            "every input (and the external input never reaches the unsafe inputs)."
        ),
        "vuln": "unsafe { std::slice::from_raw_parts(ptr, external_len); }",
        "safe": "if external_len <= max_len { unsafe { std::slice::from_raw_parts(ptr, external_len) }; }",
        "signal": r"slice::from_raw_parts\(ptr,\s*external_len\)",
        "references": [
            "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer — https://cwe.mitre.org/data/definitions/119.html",
            "CWE-787: Out-of-bounds Write — https://cwe.mitre.org/data/definitions/787.html",
            "Rust std: slice::from_raw_parts — https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html",
            "The Rustonomicon — https://doc.rust-lang.org/nomicon/",
            "Rust Reference: Behavior considered undefined — https://doc.rust-lang.org/reference/behavior-considered-undefined.html",
        ],
        "doc_url": "https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html",
    },
    {
        "num": "02",
        "title": "FFI Boundary Lifetime and CString Hazards",
        "platform": (
            "Any Rust toolchain linking C via extern \"C\" (libc on Unix, MSVC CRT "
            "on Windows); #[repr(C)] layout rules apply per target ABI"
        ),
        "mechanism": (
            "CString::new(s).unwrap().as_ptr() evaluates as a temporary: the "
            "CString owning the NUL-terminated buffer is dropped at the end of the "
            "statement, so the pointer handed to the C function already points to "
            "memory that Rust has freed — the callee reads freed heap whose "
            "contents the allocator may have reused. Box::from_raw on a pointer "
            "that is not exactly the one from Box::into_raw (or called twice for "
            "one allocation) makes the allocator free a block from a mismatched "
            "base or twice. A #[repr(Rust)] struct passed across FFI as #[repr(C)] "
            "implies a field order and padding the C side does not match, so both "
            "sides read each other's fields at wrong offsets; and a Rust panic "
            "unwinding through an extern \"C\" frame is undefined behavior on "
            "targets where C cannot handle unwinding (panic=abort changes this)."
        ),
        "source": (
            "Strings, buffers, and handles crossing into C: peer-supplied strings "
            "converted for C APIs, handles returned by C and re-wrapped with "
            "from_raw, struct layouts matched to C headers."
        ),
        "sink": (
            "CString/CStr::as_ptr results used after the owner dropped; "
            "Box::from_raw / Vec::from_raw_parts on pointers whose allocation "
            "method or count mismatches; extern \"C\" function signatures with "
            "non-repr(C) struct parameters"
        ),
        "guards": (
            "Check that the CString binding outlives the call (named binding kept "
            "alive across the extern call), that every from_raw pairs exactly with "
            "the matching into_raw from the same type and runs once, that struct "
            "types crossing FFI carry #[repr(C)] matching the C header, and that "
            "panic strategy (abort vs unwind) is set deliberately for FFI-facing "
            "code with catch_unwind where needed."
        ),
        "not_candidate_when": (
            "The owner binding is kept alive for the whole extern call, the "
            "from_raw/into_raw pair is uniquely matched and single-shot, both "
            "sides compile the same #[repr(C)] layout from one source of truth, "
            "or the FFI surface is compile-time constant with no peer-controlled "
            "strings or counts."
        ),
        "vuln": "let p = CString::new(s).unwrap().as_ptr(); unsafe { c_function(p); }",
        "safe": "let cs = CString::new(s).unwrap(); unsafe { c_function(cs.as_ptr()); }",
        "signal": r"CString::new\(s\)\.unwrap\(\)\.as_ptr\(\)",
        "references": [
            "CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html",
            "CWE-415: Double Free — https://cwe.mitre.org/data/definitions/415.html",
            "Rust std: CString — https://doc.rust-lang.org/std/ffi/struct.CString.html",
            "The Rustonomicon: FFI — https://doc.rust-lang.org/nomicon/ffi.html",
        ],
        "doc_url": "https://doc.rust-lang.org/std/ffi/struct.CString.html",
    },
    {
        "num": "03",
        "title": "Denial of Service via Panic on Untrusted Input",
        "platform": (
            "Any Rust toolchain; panic behavior depends on release profile "
            "(panic=unwind unwinds to the nearest catch/recover, panic=abort "
            "kills the process immediately)"
        ),
        "mechanism": (
            "Rust turns several ordinary mistakes into process-level aborts rather "
            "than error values: slice indexing out of range, unwrap/expect on None "
            "or Err, integer division by zero, RefCell::borrow_mut while already "
            "borrowed, and `array[index]` on fixed arrays all panic. On a shared "
            "service a panic triggered by one request aborts (panic=abort) or "
            "unwinds past the handler (unwind with no catch_unwind in the worker "
            "loop), taking the worker or whole process down. Deep recursion on "
            "attacker-shaped input (nested parsers) exhausts the fixed thread "
            "stack and raises a stack-overflow abort that no catch_unwind can "
            "catch, because it is not a Rust panic at all."
        ),
        "source": (
            "Request fields that select indexes, drive recursion depth, or arrive "
            "in shapes the code assumed impossible: list indexes, numeric fields "
            "used as divisors, deeply nested JSON/XML, empty optional payloads."
        ),
        "sink": (
            "unwrap()/expect() on input-derived Result/Option; slice/array indexing "
            "and str range slicing with external indexes; RefCell double borrow; "
            "unbounded recursion on external data"
        ),
        "guards": (
            "Check that indexing uses .get()/.get_mut() with explicit error "
            "handling and division checks for zero, that unwrap/expect is "
            "confined to values proven by an earlier check or by construction, "
            "that recursion is bounded by an explicit depth limit, and that the "
            "worker loop installs catch_unwind (and/or the profile sets "
            "panic=unwind deliberately) so one request's panic is contained."
        ),
        "not_candidate_when": (
            "The index/length was validated against .len() before the access, the "
            "unwrap is backed by a preceding check that makes panic unreachable "
            "for any input, recursion depth is capped below the stack budget, or "
            "the process handles panics per-worker and the input cannot exhaust "
            "the stack."
        ),
        "vuln": "let val = packet[user_index];",
        "safe": "let val = packet.get(user_index).ok_or(Error::InvalidIndex)?;",
        "signal": r"packet\[user_index\]",
        "references": [
            "CWE-755: Improper Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/755.html",
            "CWE-248: Uncaught Exception — https://cwe.mitre.org/data/definitions/248.html",
            "CWE-674: Uncontrolled Recursion — https://cwe.mitre.org/data/definitions/674.html",
            "Rust std: panic macro and catch_unwind — https://doc.rust-lang.org/std/panic/fn.catch_unwind.html",
        ],
        "doc_url": "https://doc.rust-lang.org/std/panic/fn.catch_unwind.html",
    },
    {
        "num": "04",
        "title": "Integer Wrapping and Lossy Casting via 'as'",
        "platform": (
            "Any Rust toolchain; wrapping only occurs when the release profile "
            "disables overflow checks (--release defaults overflow-checks=false; "
            "debug builds panic instead)"
        ),
        "mechanism": (
            "In release builds with overflow-checks off, arithmetic wraps modulo "
            "2^N silently and the `as` cast truncates: `user_size as u16` keeps "
            "the low 16 bits, so 65536 becomes 0 and 131073 becomes 1 — a value "
            "that passed a >0 or <MAX check comes out tiny or negative-typed after "
            "the cast. The truncated value then drives allocation sizes, slice "
            "lengths, or loop bounds, producing buffers far smaller than the peer "
            "believes while the code writes the original count of bytes. "
            "Signedness changes compound this: casting i64 -1 to usize yields "
            "usize::MAX, turning a negative-length check into a near-maximum "
            "unsigned allocation."
        ),
        "source": (
            "Sizes, counts, and offsets from protocol fields: declared payload "
            "lengths, item counts, offsets in binary formats."
        ),
        "sink": (
            "`as` casts between integer types on input-derived values; unchecked "
            "arithmetic (a + b, a * b) whose result feeds allocation, indexing, "
            "or copy length"
        ),
        "guards": (
            "Check that input-derived values are converted with "
            "try_from().map_err(...) (fails on truncation) rather than `as`, that "
            "arithmetic on external values uses checked_/saturating_ variants or "
            "runs with overflow-checks enabled in release, and that any wrapping "
            "is explicit (wrapping_ / overflowing_) and justified by a bound "
            "already applied."
        ),
        "not_candidate_when": (
            "The value was range-checked before the cast such that truncation is "
            "impossible (e.g. u16::try_from already used, or the value is bounded "
            "by a protocol maximum below 65536), the arithmetic is done in "
            "checked/saturating form, or the release profile explicitly enables "
            "overflow-checks and the code handles the resulting panic."
        ),
        "vuln": "let len = user_size as u16;",
        "safe": "let len = u16::try_from(user_size).map_err(|_| Error::Overflow)?;",
        "signal": r"user_size\s+as\s+u16",
        "references": [
            "CWE-197: Numeric Truncation Error — https://cwe.mitre.org/data/definitions/197.html",
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-128: Wrap-around Error — https://cwe.mitre.org/data/definitions/128.html",
            "Rust std: FromPrimitive conversions (try_from) — https://doc.rust-lang.org/std/convert/trait.TryFrom.html",
        ],
        "doc_url": "https://doc.rust-lang.org/std/convert/trait.TryFrom.html",
    },
    {
        "num": "05",
        "title": "Unsound Send and Sync Implementations",
        "platform": (
            "Any Rust toolchain; the C11/C++-style memory model of std::sync::"
            "atomic Orderings applies per CPU architecture"
        ),
        "mechanism": (
            "The compiler grants cross-thread access based on the marker traits "
            "Send and Sync, and `unsafe impl Sync for T` asserts to the whole "
            "type system that &T is thread-sharable without any proof: a type "
            "holding a raw pointer or a non-atomic counter then compiles into "
            "data races that are undefined behavior, not mere wrong answers. "
            "static mut shares the same hazard — every access is a raw multi-"
            "threaded pointer dereference with no synchronization. Relaxed or "
            "mis-chosen atomic Orderings compile but do not synchronize: a flag "
            "set with Relaxed and read with Relaxed may be observed late or "
            "reordered relative to the data it protects, so a check-then-act on "
            "credentials races with the writer. Across .await points the same "
            "state interleaves between polls, producing a check-then-act race "
            "the borrow checker cannot see."
        ),
        "source": (
            "Concurrent requests mutating shared authorization state, session "
            "tables, or caches; asynchronous tasks sharing one non-synchronized "
            "state object across .await points."
        ),
        "sink": (
            "unsafe impl Send/Sync for types containing raw pointers or non-atomic "
            "state; static mut access; atomics with incorrect Ordering guarding "
            "other data; Mutex-adjacent check-then-act sequences across .await"
        ),
        "guards": (
            "Check that every unsafe impl Send/Sync is backed by an argument why "
            "&self is thread-safe (interior synchronization, immutable after "
            "construction), that static mut is replaced by OnceLock/lazy "
            "initialization or atomics, that an atomic Release/Acquire (not "
            "Relaxed) publishes the data it guards, and that shared state touched "
            "across .await is behind a Mutex or an actor owning the state."
        ),
        "not_candidate_when": (
            "The type is genuinely thread-safe (all fields atomic or behind "
            "locks) and the unsafe impl documents that proof, the state is only "
            "reachable from one thread/task by construction, or the atomic is "
            "used with an ordering that actually establishes the required "
            "happens-before relation."
        ),
        "vuln": "unsafe impl Sync for RawContainer {}",
        "safe": "/* use Mutex or Arc to ensure thread safety */",
        "signal": r"unsafe\s+impl\s+Sync\s+for",
        "references": [
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "CWE-667: Improper Locking — https://cwe.mitre.org/data/definitions/667.html",
            "The Rustonomicon: Send and Sync — https://doc.rust-lang.org/nomicon/send-and-sync.html",
            "Rust std: module std::sync::atomic — https://doc.rust-lang.org/std/sync/atomic/index.html",
        ],
        "doc_url": "https://doc.rust-lang.org/nomicon/send-and-sync.html",
    },
    {
        "num": "06",
        "title": "Unbounded Resource Allocation in Collections",
        "platform": (
            "Any Rust toolchain; Vec::with_capacity panics on allocation failure "
            "and the allocator behavior (overcommit vs guaranteed) is target-"
            "dependent"
        ),
        "mechanism": (
            "Vec::with_capacity(n) reserves n * size_of::<T>() bytes up front, so "
            "a length field read from a peer header reserves gigabytes before any "
            "byte of payload arrives — one request exhausts memory for the whole "
            "process. read_to_end on a socket grows the buffer to whatever the "
            "peer sends, and unbounded mpsc channels or spawned task counts turn "
            "request floods into unbounded queues. Decompression repeats the "
            "pattern: decoding a small compressed stream into memory with no "
            "output cap amplifies a few kilobytes into gigabytes. Each is the "
            "same root mechanism: an attacker-chosen magnitude drives allocation "
            "or work before any bound is applied."
        ),
        "source": (
            "Declared sizes and counts from protocol headers, request body "
            "lengths, compressed stream content, and message rates from peers."
        ),
        "sink": (
            "Vec::with_capacity / String::with_capacity sized from input; "
            "read_to_end on untrusted streams; unbounded channel/task creation; "
            "decompression into memory without an output budget"
        ),
        "guards": (
            "Check that any with_capacity argument is clamped to a fixed maximum "
            "(or sized from bytes already received) before the call, that body "
            "reads use take(Limit) or incremental reads with a cap, that queues "
            "are bounded (bounded channel, task semaphore), and that decompressors "
            "write through a limited writer with a byte budget."
        ),
        "not_candidate_when": (
            "The length field is validated against a protocol maximum below the "
            "memory budget before the allocation, capacity is sized from already-"
            "received data (chunked growth), or the stream is consumed "
            "incrementally with an enforced output cap."
        ),
        "vuln": "let mut v = Vec::with_capacity(remote_size);",
        "safe": "if remote_size > MAX_ALLOWED { return Err(Error::TooLarge); }; let mut v = Vec::with_capacity(remote_size);",
        "signal": r"Vec::with_capacity\(remote_size\)",
        "references": [
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "CWE-770: Allocation of Resources Without Limits or Throttling — https://cwe.mitre.org/data/definitions/770.html",
            "CWE-409: Improper Handling of Highly Compressed Data (Data Amplification) — https://cwe.mitre.org/data/definitions/409.html",
            "Rust std: Vec::with_capacity — https://doc.rust-lang.org/std/vec/struct.Vec.html#method.with_capacity",
        ],
        "doc_url": "https://doc.rust-lang.org/std/vec/struct.Vec.html#method.with_capacity",
    },
    {
        "num": "07",
        "title": "Deserialization and Untrusted Parser Assumptions",
        "platform": (
            "Any Rust toolchain; applies to serde-based formats (serde_json, "
            "postcard-style length-prefixed codecs) on all targets"
        ),
        "mechanism": (
            "Deserializers trust the document's own structure claims: a "
            "length prefix in the input is honored as the allocation size, a "
            "self-referential nesting depth recurses until the stack is "
            "exhausted (serde_json's recursion limit exists precisely because "
            "the input can nest arbitrarily), and unknown fields are dropped "
            "silently, so a peer can smuggle fields the schema authors never "
            "audited. Untagged (internally-tagged) enums deserialize by trying "
            "variants against the same payload, meaning one attacker-supplied "
            "object can be interpreted as a different variant than the sender "
            "intended — a type-confusion decision made on attacker data."
        ),
        "source": (
            "Any externally produced serialized bytes: API request bodies, "
            "peer-to-peer protocol messages, config files from untrusted origin."
        ),
        "sink": (
            "serde_json::from_reader/from_slice/from_str (and equivalent codec "
            "deserializers) on peer data with deep nesting, length-prefixed "
            "allocations, or untagged enum targets"
        ),
        "guards": (
            "Check that the deserializer enforces a nesting/recursion limit and "
            "a total input size cap, that length-prefix-driven allocation is "
            "validated against the real remaining bytes, that target structs "
            "deny unknown fields (deny_unknown_fields) where the extra keys "
            "could change semantics, and that untagged enums are avoided or "
            "tagged explicitly for security-relevant messages."
        ),
        "not_candidate_when": (
            "The input size is capped before parsing and nesting is bounded by "
            "the deserializer's limit, unknown fields are rejected or provably "
            "inert, enums are externally tagged (or validated after parse), and "
            "the payload producer is inside the same trust domain."
        ),
        "vuln": "let obj: ComplexEnum = serde_json::from_reader(reader)?;",
        # NOTE: the previous catalog shipped an inverted "safe" example here
        # (disable_recursion_limit, i.e. the fix removed the only guard).
        # Corrected to a size-capped reader; the vulnerable example and signal
        # pattern are unchanged.
        "safe": "let obj: ComplexEnum = serde_json::from_reader(reader.take(64 * 1024))?; // size-capped reader",
        "signal": r"serde_json::from_reader\(reader\)",
        "references": [
            "CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html",
            "CWE-674: Uncontrolled Recursion — https://cwe.mitre.org/data/definitions/674.html",
            "CWE-400: Uncontrolled Resource Consumption — https://cwe.mitre.org/data/definitions/400.html",
            "serde docs: untagged enums and unknown fields — https://serde.rs/attr-deny-unknown-fields.html",
        ],
        "doc_url": "https://serde.rs/attr-deny-unknown-fields.html",
    },
    {
        "num": "08",
        "title": "Command and Path Traversal Hazards",
        "platform": (
            "Any Rust toolchain; std::process::Command spawns directly (no "
            "shell) but on Windows uses CreateProcess arg-quoting semantics"
        ),
        "mechanism": (
            "Command::new(name) treats its argument as the executable; when the "
            "name comes from input the attacker selects which binary runs, and "
            "on Windows the CRT's argument quoting allows embedded metacharacter "
            "attacks against programs that re-parse their command line. Path "
            "construction has the same trap with different semantics: "
            "Path::join / PathBuf::push REPLACE the whole base when the argument "
            "is absolute (`/etc/passwd` joined to /srv/data yields /etc/passwd), "
            "and `..` components remain in the result unless normalized, so one "
            "join does not confine the outcome to the base directory. Archive "
            "entry names reproduce the traversal when extracted with the entry's "
            "own path."
        ),
        "source": (
            "Executable names, file names, and archive entry paths from "
            "requests, uploads, and peer-supplied manifests."
        ),
        "sink": (
            "std::process::Command::new with an attacker-influenced program or "
            "argument; Path::join / PathBuf::push with input followed by file "
            "operations; archive entry paths extracted as-is"
        ),
        "guards": (
            "Check that the spawned program is a fixed absolute path (or "
            "allowlisted) and dynamic values arrive via .arg() as single "
            "arguments, that the joined path is canonicalized and verified to "
            "start_with the base after canonicalization, and that archive "
            "extraction rejects absolute paths and `..` components per entry."
        ),
        "not_candidate_when": (
            "The executable is a constant with input passed only as one argument "
            "to a program that takes no options, the joined path is validated "
            "with canonicalize()+starts_with on the result, or entry names are "
            "stripped to their file component before extraction."
        ),
        "vuln": "Command::new(user_cmd).arg(arg).spawn()?;",
        "safe": "Command::new(\"/usr/bin/trusted_app\").arg(arg).spawn()?;",
        "signal": r"Command::new\(user_cmd\)",
        "references": [
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command — https://cwe.mitre.org/data/definitions/78.html",
            "CWE-22: Improper Limitation of a Pathname to a Restricted Directory — https://cwe.mitre.org/data/definitions/22.html",
            "CWE-88: Argument Injection or Modification — https://cwe.mitre.org/data/definitions/88.html",
            "Rust std: process::Command — https://doc.rust-lang.org/std/process/struct.Command.html",
            "Rust std: Path::join — https://doc.rust-lang.org/std/path/struct.Path.html#method.join",
        ],
        "doc_url": "https://doc.rust-lang.org/std/process/struct.Command.html",
    },
    {
        "num": "09",
        "title": "Cryptographic Constant-Time Comparison Failures",
        "platform": (
            "Any Rust toolchain; timing exploitation depends on target CPU and "
            "network jitter but `==` on Vec<u8>/&[u8] is never constant-time"
        ),
        "mechanism": (
            "The derived PartialEq for &[u8] compares bytes with early return on "
            "the first mismatch, so the wall-clock time of a MAC/tag comparison "
            "correlates with the number of leading correct bytes. An attacker "
            "who can submit many candidate tags and measure response time "
            "recovers the expected tag byte by byte, forging authentication "
            "without knowing the key. The same class covers nonce misuse (a "
            "counter nonce reused across messages with the same key destroys "
            "AES-GCM confidentiality and authentication), secrets left in "
            "zeroable memory (Vec buffers freed without wiping keep key material "
            "in freed heap reachable by later leaks), and closing certificate "
            "validation to make a TLS layer accept any peer."
        ),
        "source": (
            "Attacker-supplied MAC tags, signatures, and tokens compared against "
            "computed secrets, plus key material handled in ordinary Vec buffers."
        ),
        "sink": (
            "== / != / assert_eq! on digests, MACs, and signature byte slices "
            "used to grant access; nonce reuse across encryptions; secrets stored "
            "in non-wiped buffers; disabled certificate verification"
        ),
        "guards": (
            "Check that tag comparison uses the `subtle` crate's ConstantTimeEq "
            "ct_eq (or an equivalent constant-time primitive) before the "
            "decision, that AEAD nonces are unique per key (counter or random "
            "with collision-avoidance), that key buffers are zeroized after use, "
            "and that certificate verification remains at library defaults."
        ),
        "not_candidate_when": (
            "The comparison is over non-secret data (public IDs, content "
            "hashes), the constant-time primitive is already in place, the AEAD "
            "nonce is provably unique per key, or the compared values never "
            "gate authentication and no timing oracle is reachable."
        ),
        "vuln": "if sig == expected_sig { grant(); }",
        "safe": "if subtle::ConstantTimeEq::ct_eq(&sig, &expected_sig).into() { grant(); }",
        "signal": r"if\s+sig\s*==\s*expected_sig",
        "references": [
            "CWE-208: Observable Timing Discrepancy — https://cwe.mitre.org/data/definitions/208.html",
            "CWE-347: Improper Verification of Cryptographic Signature — https://cwe.mitre.org/data/definitions/347.html",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm — https://cwe.mitre.org/data/definitions/327.html",
            "docs.rs: subtle crate ConstantTimeEq — https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html",
        ],
        "doc_url": "https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html",
    },
    {
        "num": "10",
        "title": "Unsafe Abstraction Drop and Panic Safety",
        "platform": (
            "Any Rust toolchain; drop/panic interaction semantics are "
            "toolchain-independent, Pin projection rules apply to async/future "
            "types"
        ),
        "mechanism": (
            "Rust's safety story assumes every value is dropped exactly once and "
            "destructors always run, but unsafe abstractions can break both. "
            "ptr::read copies the value out bitwise while leaving the source "
            "intact: if the source is later dropped normally, the same value is "
            "dropped twice, and if a panic fires between read and forget the "
            "double drop happens mid-unwind. Abstractions that rely on the "
            "destructor to restore an invariant (releasing a lock, decrementing "
            "a count, restoring a file mode) leave the invariant broken if a "
            "panic skips the drop path they assumed — unwinding still runs "
            "destructors, but only for values already constructed, so "
            "ManuallyDrop/DontDrop fields and manually-managed slots escape "
            "cleanup. Pin misuse (moving a pinned value, or projecting a "
            "non-structural field as structural) breaks self-referential "
            "futures whose internal pointers then dangle across the next poll."
        ),
        "source": (
            "Attacker-triggerable panics and early returns that interrupt an "
            "unsafe abstraction between its setup and teardown steps (parse "
            "errors mid-construction, request cancellation between polls)."
        ),
        "sink": (
            "unsafe { ptr::read / ptr::copy_nonoverlapping } followed by manual "
            "mem::forget; Drop implementations assuming they always run; Pin "
            "projections that move pinned data; invariants restored only in "
            "explicit (not drop-guard) code paths"
        ),
        "guards": (
            "Check that every ptr::read is paired with mem::forget or "
            "ManuallyDrop on ALL paths including panic unwinding, that "
            "resource-releasing and invariant-restoring logic lives in Drop "
            "rather than a call the caller may skip, and that Pin projections "
            "follow the pinned-field rules (structural pinning only for fields "
            "that are genuinely pinned)."
        ),
        "not_candidate_when": (
            "The read/forget pair is total on every path and the type is "
            "UnwindSafe-verified, invariants are enforced by Drop guards so "
            "unwinding restores them, the pinned type has no structural "
            "self-references (Pin is only a marker there), or the abstraction "
            "is unreachable from input-triggered panics."
        ),
        "vuln": "let val = unsafe { std::ptr::read(src) };",
        "safe": "/* ensure std::mem::forget or ManuallyDrop handles panic */",
        "signal": r"std::ptr::read\(src\)",
        "references": [
            "CWE-415: Double Free — https://cwe.mitre.org/data/definitions/415.html",
            "CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html",
            "Rust std: ptr::read — https://doc.rust-lang.org/std/ptr/fn.read.html",
            "Rust std: module std::pin — https://doc.rust-lang.org/std/pin/index.html",
            "The Rustonomicon: Drop Check — https://doc.rust-lang.org/nomicon/dropck.html",
        ],
        "doc_url": "https://doc.rust-lang.org/std/ptr/fn.read.html",
    },
]
