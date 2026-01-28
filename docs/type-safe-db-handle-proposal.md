# Proposal: Type-Safe Database Handle Initialization

## Problem Statement

The current `ZcashRustBackend` API allows creating instances without opened database handles. The `openDb()` method must be called separately before any database operations, but this is a runtime contract - not enforced by the type system. This leads to:

1. Tests forgetting to call `openDb()` and failing with "handle has not been opened" errors
2. Potential for similar bugs in production code during refactoring
3. 41+ methods that call `resolveHandle()` which throws if not opened

## Proposed Solution: Async Factory Pattern

Replace the public constructor with an async factory method that creates AND opens the backend atomically. Any instance of `ZcashRustBackendWelding` is guaranteed to be opened.

### Key Changes

1. **Make `ZcashRustBackend.init` private**
2. **Add static async factory:**
```swift
@DBActor
static func open(
    dbData: URL,
    fsBlockDbRoot: URL,
    spendParamsPath: URL,
    outputParamsPath: URL,
    networkType: NetworkType,
    logLevel: RustLogging = .off,
    sdkFlags: SDKFlags
) async throws -> ZcashRustBackend
```

3. **Remove `openDb()` from `ZcashRustBackendWelding` protocol** - the protocol now represents only "opened and operational" state

4. **Restructure `Dependencies.swift`** into phases since backend creation becomes async:
   - Phase 1 (sync): Register non-backend dependencies
   - Phase 2 (async): Create opened backend via factory
   - Phase 3 (sync): Register dependencies that require backend

### Benefits

- **Compile-time safety**: Impossible to obtain an unopened backend
- **Cleaner API**: No need to remember initialization order
- **Simpler tests**: No manual `openDb()` calls needed
- **Self-documenting**: The async factory makes it clear that database opening happens

### Trade-offs

- Factory must be async, which propagates to some callers
- `Dependencies.setup()` needs restructuring for async backend creation
- Breaking change for code that directly constructs `ZcashRustBackend`

### Files Requiring Changes

| File | Changes |
|------|---------|
| `Rust/ZcashRustBackend.swift` | Private init, add async factory |
| `Rust/ZcashRustBackendWelding.swift` | Remove `openDb()`, `resolveDbHandle()` |
| `Synchronizer/Dependencies.swift` | Split into phased setup |
| `Initializer.swift` | Update initialization flow |
| `Tests/TestUtils/Tests+Utils.swift` | Async factory for tests |
| Test files | Use async setUp |

### Alternative Approaches Considered

1. **Typestate Pattern** (separate `UninitializedBackend` and `InitializedBackend` types)
   - More explicit but requires significant protocol splitting
   - Complicates DI container registration

2. **Lazy Opening** (open on first `resolveHandle()` call)
   - Does NOT provide compile-time safety
   - Race conditions with `@DBActor` async requirements

3. **Sealed Protocol Pattern** (split protocol into creation vs operational interfaces)
   - Similar complexity to typestate
   - Protocol splitting creates churn across many files

## Implementation Timeline

This is a medium-sized refactoring effort. Recommended approach:
1. Add async factory alongside existing constructor (marked deprecated)
2. Migrate production code
3. Migrate test code
4. Remove deprecated constructor and `openDb()` from protocol
