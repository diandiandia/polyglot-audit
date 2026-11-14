"""Substantive per-card content for the C++ knowledge cards (cpp-01..cpp-10).

This file is the source of truth consumed by tools/generate_catalog.py.
One entry per card; every card must carry real mechanism, source/sink, guard,
and disqualification text. Entries cite only public references that are
believed to exist (CWE pages, cppreference symbol pages, C++ Core Guidelines).

Follows docs/design/LANGUAGE_CATALOG_DRAFT.md (C++ section).
"""

LANGUAGE = {
    "name": "C++",
    "prefix": "cpp",
}

CARDS = [
    {
        "num": "01",
        "title": "Dangling Reference and Iterator Invalidation",
        "platform": (
            "C++11 and later (string_view is C++17, spans are C++20) on any "
            "conforming toolchain; the defect is silent — no runtime check fires"
        ),
        "mechanism": (
            "C++ value semantics create temporaries whose lifetime ends at the full "
            "expression: binding std::string_view to `std::string(user_input)` "
            "constructs a temporary string, the view points into its heap buffer, "
            "and the temporary is destroyed at the semicolon, leaving the view "
            "dangling while it still type-checks as a valid string-like object. "
            "The same gap appears between container mutation and held views: "
            "vector::push_back may reallocate, invalidating every iterator, "
            "pointer, and reference taken before the call, and a lambda that "
            "captures a local by reference outlives the local when it is invoked "
            "later (queue, callback, thread). Moved-from objects add a variant: "
            "the language leaves a moved-from std::string/vector in a valid but "
            "unspecified state, and reading it is a logic bug, not a compile error."
        ),
        "source": (
            "Request-derived strings and buffers passed through conversion "
            "boundaries (string_view/span parameters), iterators retained across "
            "container updates, and lambdas/callbacks stored for later invocation."
        ),
        "sink": (
            "Read or copy through a std::string_view/std::span bound to a temporary "
            "or destroyed string; iterator/pointer/reference used after push_back/"
            "insert/erase on the container; lambda reference capture invoked after "
            "the captured scope returned"
        ),
        "guards": (
            "Check that views/spans are bound only to objects whose lifetime "
            "outlives the view (a named string, not a temporary), that no iterator "
            "or reference is used after any call that may reallocate (or is "
            "re-fetched after the mutation), and that lambdas escaping the current "
            "scope capture by value or via shared ownership."
        ),
        "not_candidate_when": (
            "The view is consumed within the same full expression that binds it, "
            "the container's capacity is reserved and no mutation occurs between "
            "iterator capture and use, the lambda is invoked before its captured "
            "scope exits, or the dangling reference never feeds a security decision "
            "or attacker-reachable output."
        ),
        "vuln": "std::string_view sv = std::string(user_input); return sv;",
        "safe": "std::string s = user_input; return s;",
        "signal": r"std::string_view.*std::string\(",
        "references": [
            "CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html",
            "cppreference: std::basic_string_view — https://en.cppreference.com/w/cpp/string/basic_string_view",
            "cppreference: std::vector::push_back (iterator invalidation) — https://en.cppreference.com/w/cpp/container/vector/push_back",
            "C++ Core Guidelines: Views and spans lifetime rules — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/string/basic_string_view",
    },
    {
        "num": "02",
        "title": "Asynchronous Lifetime and Coroutine Data Race",
        "platform": (
            "C++11 threads and C++20 coroutines on any conforming toolchain; "
            "manifestation depends on scheduler timing and memory model"
        ),
        "mechanism": (
            "A detached std::thread constructed with `[this]() {...}` captures the "
            "raw pointer; when the owning object is destroyed (request ends, parent "
            "returns) the still-running thread dereferences freed memory, and there "
            "is no join or signal to stop it. The intended fix — enable_shared_from_"
            "this — only works when the object is already owned by a shared_ptr and "
            "shared_from_this() is called after construction; calling it in a "
            "constructor or on a stack object throws or produces an empty weak "
            "reference, so a superficially 'fixed' version can still dangle. "
            "C++20 coroutines repeat the pattern at co_await boundaries: frame "
            "suspension may outlive the caller's scope, so parameters passed by "
            "reference and locals referenced across co_await dangle when the "
            "coroutine resumes after its parent returned. Non-atomic shared state "
            "mutated from the callback is simultaneously a data race (undefined "
            "behavior under the C++ memory model)."
        ),
        "source": (
            "Request lifetime boundaries: completion callbacks, detached workers, "
            "timers, and coroutine resumptions that execute after the request "
            "context or session object was destroyed."
        ),
        "sink": (
            "std::thread(...).detach() or stored callback capturing `this`; "
            "shared_from_this()/weak_ptr misuse; coroutine lambdas taking reference "
            "parameters and referencing locals across co_await"
        ),
        "guards": (
            "Check that asynchronous work owns the object through shared_ptr taken "
            "via enable_shared_from_this BEFORE launching (and that the object is "
            "managed by shared_ptr at all), that detached threads are replaced by "
            "scoped joinable threads (std::jthread) or an explicit stop mechanism, "
            "and that coroutine parameters are taken by value and no local is "
            "referenced across a co_await."
        ),
        "not_candidate_when": (
            "The thread/callback is joined or awaited before the owner can be "
            "destroyed, ownership is carried by a shared_ptr captured by value and "
            "the object's lifetime is provably covered, or the coroutine is consumed "
            "to completion within the parent scope (no suspension escapes)."
        ),
        "vuln": "std::thread([this]() { this->process(); }).detach();",
        "safe": "auto self = shared_from_this(); std::thread([self]() { self->process(); }).detach();",
        "signal": r"std::thread\(\[this\]",
        "references": [
            "CWE-416: Use After Free — https://cwe.mitre.org/data/definitions/416.html",
            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization — https://cwe.mitre.org/data/definitions/362.html",
            "C++ Core Guidelines: CP concurrency rules — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
            "cppreference: std::enable_shared_from_this — https://en.cppreference.com/w/cpp/memory/enable_shared_from_this",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/memory/enable_shared_from_this",
    },
    {
        "num": "03",
        "title": "Container and Raw Buffer Out-of-Bounds",
        "platform": (
            "C++11 and later on any conforming toolchain; operator[] is unchecked "
            "by default in release, and only libstdc++/MSVC debug builds assert"
        ),
        "mechanism": (
            "vector::operator[] and string::operator[] perform no bounds check in "
            "conforming release builds: the standard makes an out-of-range index "
            "undefined behavior rather than an exception, so an attacker-supplied "
            "index reads or writes whatever object lies at data() + i * element_"
            "size. The same unchecked boundary appears where C++ hands its buffer "
            "to C: passing vector::data() plus a separately-tracked length to a C "
            "API lets a stale or mismatched length parameter overflow the vector's "
            "allocation, since data() itself is a raw pointer carrying no size."
        ),
        "source": (
            "Indexes and lengths from protocol fields, request parameters, parsed "
            "message offsets, or computed from attacker-influenced values."
        ),
        "sink": (
            "operator[] on vector/deque/string/map with an unchecked index; "
            "data()/c_str() plus an external length handed to memcpy or a C API"
        ),
        "guards": (
            "Check that .at() is used (throws std::out_of_range) or the index is "
            "explicitly compared against .size() before operator[], and that every "
            "data()-plus-length hand-off to C derives both from the same container "
            "object in the same expression (size() called on the live vector, not a "
            "cached value)."
        ),
        "not_candidate_when": (
            "The index was validated against size() on the same path before the "
            "access, the container is a compile-time array with a constant index, "
            "or the buffer is only passed to C interfaces with lengths derived from "
            "the same live container object."
        ),
        "vuln": "int val = data[user_index];",
        "safe": "int val = data.at(user_index);",
        "signal": r"data\[user_index\]",
        "references": [
            "CWE-129: Improper Validation of Array Index — https://cwe.mitre.org/data/definitions/129.html",
            "CWE-125: Out-of-bounds Read — https://cwe.mitre.org/data/definitions/125.html",
            "cppreference: std::vector::operator[] — https://en.cppreference.com/w/cpp/container/vector/operator_at",
            "C++ Core Guidelines: ES (expressions and statements) — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/container/vector/operator_at",
    },
    {
        "num": "04",
        "title": "Size Computation Overflow in Container Allocation",
        "platform": (
            "C++11 and later on any conforming toolchain; signed overflow in the "
            "size computation is undefined behavior, unsigned wraps silently"
        ),
        "mechanism": (
            "Container capacity math runs in the same machine integers as C: "
            "`user_n * sizeof(int)` in size_t wraps modulo 2^64 (or 2^32), so two "
            "large attacker values produce a small product and reserve()/resize()/"
            "new[] succeed with a fraction of the requested storage. Subsequent "
            "indexed writes counted with the original n then run past the small "
            "allocation. Mixed-width arithmetic makes it worse: an int count "
            "converted to size_t sign-extends a negative value into a near-2^64 "
            "number, and a reserve() that throws bad_alloc on one platform silently "
            "wraps on another where size_t is narrower."
        ),
        "source": (
            "Counts, element counts, or message lengths taken from protocol fields "
            "and request bodies (e.g. an item-count header followed by the items)."
        ),
        "sink": (
            "vector::reserve/resize, new T[n], make_unique<T[]>(n), or any "
            "allocator call whose argument is a product or sum of attacker values"
        ),
        "guards": (
            "Check that the count is bounded by an explicit protocol maximum before "
            "any arithmetic, that the multiplication uses a checked builtin "
            "(__builtin_mul_overflow) or a pre-division test "
            "(n > SIZE_MAX / sizeof(T)), and that the result stays in size_t "
            "throughout with no intermediate int conversions."
        ),
        "not_candidate_when": (
            "The count is validated to a small fixed maximum before allocation, the "
            "element size and count are compile-time constants with a provably "
            "in-range product, or the allocation feeds an offline tool whose inputs "
            "no external party controls."
        ),
        "vuln": "size_t total = user_n * sizeof(int); vec.reserve(total);",
        "safe": "if (__builtin_mul_overflow(user_n, sizeof(int), &total)) throw std::overflow_error(\"overflow\"); vec.reserve(total);",
        "signal": r"vec\.reserve\(total\)",
        "references": [
            "CWE-190: Integer Overflow or Wraparound — https://cwe.mitre.org/data/definitions/190.html",
            "CWE-787: Out-of-bounds Write — https://cwe.mitre.org/data/definitions/787.html",
            "cppreference: std::vector::reserve — https://en.cppreference.com/w/cpp/container/vector/reserve",
            "C++ Core Guidelines: ES.103 (no overflow) — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/container/vector/reserve",
    },
    {
        "num": "05",
        "title": "Unsafe Type Casting and Type Confusion",
        "platform": (
            "C++11 and later on any conforming toolchain; RTTI-based dynamic_cast "
            "requires the base class to be polymorphic (at least one virtual function)"
        ),
        "mechanism": (
            "static_cast<Derived*>(base_ptr) converts the pointer with zero runtime "
            "information: if the object is actually a different derived type (or a "
            "base), every subsequent member access through the resulting pointer "
            "computes offsets for the wrong layout, so a field write lands inside "
            "another field — classic type confusion that turns an object of one "
            "attacker-influenced type into another. reinterpret_cast and C-style "
            "casts are stronger still, permitting pointer-type punning and "
            "integer/pointer round-trips that violate strict aliasing. Unions used "
            "for type punning read a member of type T from bytes written as type U, "
            "which is undefined behavior the compiler may optimize across."
        ),
        "source": (
            "Type tags, discriminator fields, or polymorphic handles that arrive "
            "from deserialized data, plugin registries, or protocol payloads and "
            "then drive a downcast."
        ),
        "sink": (
            "static_cast / reinterpret_cast / C-style cast to a derived or unrelated "
            "pointer type on data whose dynamic type is attacker-influenced; union "
            "member reads of a different active member"
        ),
        "guards": (
            "Check that polymorphic downcasts use dynamic_cast with a null-result "
            "check (requires RTTI enabled), that any tag-driven cast validates the "
            "tag against the concrete object (e.g. via a virtual type id comparison "
            "that also fails closed), and that data reinterpretation goes through "
            "bit_cast (C++20) or explicit serialization rather than union punning."
        ),
        "not_candidate_when": (
            "The object's dynamic type is guaranteed by construction (factory that "
            "only produces Derived) and documented with an assertion, dynamic_cast "
            "with failure handling replaces the static_cast, or the cast is between "
            "layout-compatible numeric types with no object reuse."
        ),
        "vuln": "Derived *d = static_cast<Derived*>(base_ptr);",
        "safe": "Derived *d = dynamic_cast<Derived*>(base_ptr); if (!d) return;",
        "signal": r"static_cast<Derived\*>",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "CWE-843: Access of Resource Using Incompatible Type ('Type Confusion') — https://cwe.mitre.org/data/definitions/843.html",
            "cppreference: static_cast — https://en.cppreference.com/w/cpp/language/static_cast",
            "cppreference: dynamic_cast — https://en.cppreference.com/w/cpp/language/dynamic_cast",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/language/static_cast",
    },
    {
        "num": "06",
        "title": "Ownership and Deletion Mismatch",
        "platform": (
            "C++11 and later on any conforming toolchain; smart-pointer adoption "
            "depends on the codebase's C++ standard baseline"
        ),
        "mechanism": (
            "`new T[]` must be released with delete[] because the array form stores "
            "a count and runs the destructor loop; plain delete on an array pointer "
            "runs one destructor and hands a differently-shaped block to the "
            "allocator, corrupting the heap. Naked new/delete make ownership "
            "implicit, so two code paths that both 'own' the same pointer produce a "
            "double free, and a path that forgets its delete leaks until the "
            "resource (a lock file, a credential handle) is exhausted. shared_ptr "
            "adds its own trap: two shared_ptr instances constructed from the same "
            "raw pointer hold two independent control blocks, destroying the object "
            "twice when each hits zero."
        ),
        "source": (
            "Object lifetimes steered by request flow: early returns, error paths, "
            "and re-handoff of buffers between modules, any of which can free or "
            "re-take ownership while another path still holds the pointer."
        ),
        "sink": (
            "delete applied to a new[] pointer; two owners freeing one raw pointer; "
            "shared_ptr constructed from a raw pointer already owned elsewhere"
        ),
        "guards": (
            "Check that allocation goes through make_unique/make_shared (never "
            "naked new held in raw pointers), that array allocations use "
            "unique_ptr<T[]> or std::vector, and that no raw pointer that already "
            "has an owner is passed to a smart-pointer constructor or deleted a "
            "second time."
        ),
        "not_candidate_when": (
            "The allocation is owned exclusively by a smart pointer and no raw "
            "alias is ever deleted, the raw pointer is non-owning (observer) by "
            "documented convention and its owner provably outlives all users, or "
            "the array is a compile-time constant replaced by std::array/vector."
        ),
        "vuln": "int *arr = new int[user_len]; delete arr;",
        "safe": "auto arr = std::make_unique<int[]>(user_len);",
        "signal": r"delete\s+arr;",
        "references": [
            "CWE-404: Improper Resource Shutdown or Release — https://cwe.mitre.org/data/definitions/404.html",
            "CWE-415: Double Free — https://cwe.mitre.org/data/definitions/415.html",
            "cppreference: std::unique_ptr — https://en.cppreference.com/w/cpp/memory/unique_ptr",
            "C++ Core Guidelines: R resource-management rules — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/memory/unique_ptr",
    },
    {
        "num": "07",
        "title": "Exception Safety and Invariant Incompletion",
        "platform": (
            "C++11 and later on any conforming toolchain; noexcept violation calls "
            "std::terminate per the standard"
        ),
        "mechanism": (
            "An exception unwinds a constructor or mutator midway, leaving the "
            "object half-updated: members assigned before the throw keep new values "
            "while later invariants (an initialized lock, a registered resource) "
            "are missing, and any code that catches and continues now operates on "
            "an object whose advertised class invariant is false. Declaring a "
            "function noexcept and throwing anyway calls std::terminate, aborting "
            "the process from inside what should be a recoverable path — a "
            "request-reachable crash. Destructors must not let exceptions escape "
            "because unwinding already in progress makes a second throw terminate "
            "the program."
        ),
        "source": (
            "Any operation that can fail at runtime under attacker influence: bad "
            "allocations under request load, parse failures on malformed input, "
            "IO errors — each raising while an object is mid-mutation."
        ),
        "sink": (
            "Throwing destructors or noexcept functions that throw; multi-step "
            "mutation sequences without rollback (no RAII guard) whose early steps "
            "persist when a later step throws"
        ),
        "guards": (
            "Check that destructors are noexcept and swallow or log rather than "
            "rethrow, that throwing functions are not marked noexcept, and that "
            "multi-step mutations use RAII transaction guards or copy-and-swap so "
            "the object is either fully updated or untouched (strong exception "
            "guarantee)."
        ),
        "not_candidate_when": (
            "The mutating operations are marked noexcept (no unwind can interrupt "
            "them), the state is rebuilt from scratch on the error path so no "
            "half-state survives, or the exception path exits the process before "
            "the object is used again."
        ),
        "vuln": "~MyResource() noexcept(false) { if (err) throw std::runtime_error(\"fail\"); }",
        "safe": "~MyResource() noexcept { log_error(); }",
        "signal": r"throw\s+std::runtime_error",
        "references": [
            "CWE-703: Improper Check or Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/703.html",
            "CWE-755: Improper Handling of Exceptional Conditions — https://cwe.mitre.org/data/definitions/755.html",
            "cppreference: noexcept specifier — https://en.cppreference.com/w/cpp/language/noexcept_spec",
            "C++ Core Guidelines: E error-handling rules — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/language/noexcept_spec",
    },
    {
        "num": "08",
        "title": "Uninitialized Members and Padding Information Leak",
        "platform": (
            "C++11 and later on any conforming toolchain; padding layout follows "
            "the platform ABI (Itanium/SysV, MSVC)"
        ),
        "mechanism": (
            "A class with no default member initializers leaves its members "
            "indeterminate when default-constructed on the stack or via a raw "
            "allocation: reading a field yields whatever bytes occupied the "
            "storage, which may be a previous request's data. Two consequences "
            "follow: logic reading such a field (an authorization flag, a length) "
            "behaves attacker-shiftable, and a whole-object serialize — copying "
            "sizeof(S) including the ABI padding the compiler inserts between "
            "members — transmits uninitialized padding bytes to the peer, leaking "
            "fragments of earlier heap or stack contents. C++11 member initializers "
            "and value-initialization `S s{}` close the gap; placement-new into "
            "raw storage does not."
        ),
        "source": (
            "Objects constructed on request paths without explicit initialization "
            "and then serialized, hashed, or copied into responses; padding bytes "
            "covered by whole-object copies."
        ),
        "sink": (
            "memcpy/send/serialize over sizeof(obj) of a default-constructed "
            "object; any read of a member that no constructor initialized"
        ),
        "guards": (
            "Check that every member has a default member initializer "
            "(`int x{0};`) or the constructor initializes all members, that "
            "instances are value-initialized (`S s{};`) rather than default "
            "constructed, and that serialization copies field-by-field (or via a "
            "member-wise serializer) instead of whole-object memcpy of sizeof(S)."
        ),
        "not_candidate_when": (
            "Every constructor initializes every member and value-initialization is "
            "used at each instantiation, the object is never serialized beyond its "
            "explicitly-written fields, or the type is only used as an internal "
            "scratch object whose bytes never leave the process."
        ),
        "vuln": "struct S { int x; int y; }; S s; serialize(s);",
        "safe": "struct S { int x{0}; int y{0}; }; S s{}; serialize(s);",
        "signal": r"struct\s+S\s*\{.*int\s+x;\s*int\s+y;",
        "references": [
            "CWE-457: Use of Uninitialized Variable — https://cwe.mitre.org/data/definitions/457.html",
            "CWE-908: Use of Uninitialized Resource — https://cwe.mitre.org/data/definitions/908.html",
            "cppreference: default initialization — https://en.cppreference.com/w/cpp/language/default_initialization",
            "C++ Core Guidelines: C.41 (initialize in constructors) — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/language/default_initialization",
    },
    {
        "num": "09",
        "title": "C Memory Operations on Non-Trivial C++ Types",
        "platform": (
            "C++11 and later on any conforming toolchain; consequences depend on "
            "whether the type has virtual functions or owns resources"
        ),
        "mechanism": (
            "memcpy/memset/realloc operate on raw bytes, but a C++ object's meaning "
            "lives in its constructor-maintained invariants: overwriting an object "
            "whose members are std::string or std::vector with memset zeroes "
            "replaces their internal pointers with null without freeing, so the "
            "next destruction or assignment frees or reads through wild values. "
            "On a polymorphic type, memset also overwrites the vptr the compiler "
            "stores in the object, so the next virtual call jumps through a null "
            "or stale table. realloc moves the block without running any copy "
            "constructor, leaving internal self-pointers pointing at the old "
            "address. Only trivially copyable types may legally be copied this way."
        ),
        "source": (
            "Objects that carry attacker-influenced state (request data in "
            "std::string members) and cross C/C++ integration seams where raw "
            "byte-level copying is habitual."
        ),
        "sink": (
            "memcpy/memmove/memset/realloc applied to objects of non-trivially-"
            "copyable types (virtual functions, std::string/vector members, "
            "user-defined destructors)"
        ),
        "guards": (
            "Check that byte-level operations are applied only to trivially "
            "copyable types (static_assert(std::is_trivially_copyable_v<T>)), that "
            "resetting an object uses assignment (`obj = T{};`) or clear() methods, "
            "and that buffers owned by C++ containers are resized by the container "
            "API rather than realloc'd."
        ),
        "not_candidate_when": (
            "The target type is trivially copyable (POD aggregates without virtual "
            "functions or owning members) and the copy is legal, the zeroing is "
            "immediately followed by full reconstruction before any use, or the "
            "object is replaced wholesale via assignment as in the safe example."
        ),
        "vuln": "memset(&my_obj, 0, sizeof(my_obj));",
        "safe": "my_obj = MyClass{}; // Safe copy/move assignment",
        "signal": r"memset\(&my_obj",
        "references": [
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "CWE-672: Operation on a Resource after Expiration or Release — https://cwe.mitre.org/data/definitions/672.html",
            "cppreference: TriviallyCopyable — https://en.cppreference.com/w/cpp/named_req/TriviallyCopyable",
            "C++ Core Guidelines: CP/object-lifecycle rules — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/named_req/TriviallyCopyable",
    },
    {
        "num": "10",
        "title": "Polymorphism and Destructor Traps",
        "platform": (
            "C++11 and later on any conforming toolchain; UB shows up as wrong "
            "destructor or leaked/vtable-corrupted object rather than an exception"
        ),
        "mechanism": (
            "`delete b` where b is Base* but the object is Derived invokes undefined "
            "behavior when Base's destructor is not virtual: the compiler emits a "
            "call to ~Base with no dispatch, so Derived's members (owned strings, "
            "file handles) are never destroyed and the deallocation size passed to "
            "the allocator can mismatch the Derived block. Virtual calls during "
            "construction and destruction dispatch only to the currently-"
            "constructing level, so an overridden hook silently does nothing or "
            "runs base logic while the derived state is not yet alive. Copy "
            "assignment to a Base-typed value slices the Derived part off, and a "
            "non-explicit converting constructor lets a value of one type reach a "
            "security check as another (e.g. Token(string) converting a raw "
            "attacker string into a validated token implicitly)."
        ),
        "source": (
            "Polymorphic objects built from attacker-selected types (plugin and "
            "handler registries, deserialized type tags) and values converted "
            "implicitly across API boundaries."
        ),
        "sink": (
            "delete through a base pointer with a non-virtual destructor; virtual "
            "calls in constructors/destructors; Base = Derived assignments that "
            "slice; implicit conversions into security-relevant parameter types"
        ),
        "guards": (
            "Check that every polymorphic base class declares a virtual destructor, "
            "that ownership transfer uses unique_ptr<Base> (which still requires "
            "the virtual dtor), that no virtual function is invoked from a "
            "constructor or destructor body, and that converting constructors and "
            "conversion operators on security-relevant types are explicit."
        ),
        "not_candidate_when": (
            "The base class has a virtual destructor so deletion dispatches "
            "correctly, the hierarchy is final/non-polymorphic with no derived "
            "types, the type is deleted through its own concrete pointer, or the "
            "converting constructor is explicit and every call site passes the "
            "validated type deliberately."
        ),
        "vuln": "Base *b = new Derived(); delete b;",
        "safe": "class Base { public: virtual ~Base() = default; };",
        "signal": r"delete\s+b;",
        "references": [
            "CWE-404: Improper Resource Shutdown or Release — https://cwe.mitre.org/data/definitions/404.html",
            "CWE-704: Incorrect Type Conversion or Cast — https://cwe.mitre.org/data/definitions/704.html",
            "cppreference: virtual destructor — https://en.cppreference.com/w/cpp/language/destructor",
            "cppreference: explicit — https://en.cppreference.com/w/cpp/language/explicit",
            "C++ Core Guidelines: C.127 (virtual destructor for base classes) — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        ],
        "doc_url": "https://en.cppreference.com/w/cpp/language/destructor",
    },
]
