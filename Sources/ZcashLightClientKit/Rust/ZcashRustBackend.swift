//
//  ZcashRustBackend.swift
//  ZcashLightClientKit
//
//  Created by Jack Grigg on 5/8/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//
//  ACTOR DISCIPLINE: methods here are split READ (no `@DBActor`, carries a `DB-READ` audit
//  marker) vs WRITE (`@DBActor`). The contract, the rule for new methods, and the re-pin
//  re-audit rule live on the `DBActor` declaration in Utils/DBActor.swift — read it before
//  adding or reclassifying a method.
//
// swiftlint:disable type_body_length
import Foundation
import libzcashlc

enum RustLogging: String {
    /// The logs are completely disabled.
    case off
    /// Logs very serious errors.
    case error
    /// Logs hazardous situations.
    case warn
    /// Logs useful information.
    case info
    /// Logs lower priority information.
    case debug
    /// Logs very low priority, often extremely verbose, information.
    case trace
}

/// A description of the policy that is used to determine what notes are available for spending,
/// based upon the number of confirmations (the number of blocks in the chain since and including
/// the block in which a note was produced.)
///
/// See [`ZIP 315`] for details including the definitions of "trusted" and "untrusted" notes.
///
/// # Note
///
/// `trusted` and `untrusted` are both meant to be non-zero values.
/// `0` will be treated as a request for a default value.
///
/// [`ZIP 315`]: https://zips.z.cash/zip-0315
public struct ConfirmationsPolicy {
    /// NonZero, zero for default
    let trusted: UInt32
    /// NonZero, zero for default; if this is set to zero, `trusted` must also be set to zero
    let untrusted: UInt32
    let allowZeroConfShielding: Bool

    init(trusted: UInt32 = 3, untrusted: UInt32 = 10, allowZeroConfShielding: Bool = true) {
        self.trusted = trusted
        self.untrusted = untrusted
        self.allowZeroConfShielding = allowZeroConfShielding
    }

    public static func defaultTransferPolicy() -> Self {
        ConfirmationsPolicy.init()
    }

    public static func defaultShieldingPolicy() -> Self {
        ConfirmationsPolicy.init(trusted: 1, untrusted: 1, allowZeroConfShielding: true)
    }

    public func toBackend() -> libzcashlc.ConfirmationsPolicy {
        var libzcashlcConfirmationsPolicy = libzcashlc.ConfirmationsPolicy()
        libzcashlcConfirmationsPolicy.trusted = self.trusted
        libzcashlcConfirmationsPolicy.untrusted = self.untrusted
        libzcashlcConfirmationsPolicy.allow_zero_conf_shielding = self.allowZeroConfShielding
        return libzcashlcConfirmationsPolicy
    }
}

struct ZcashRustBackend: ZcashRustBackendWelding {
    let confirmationsPolicy: ConfirmationsPolicy = ConfirmationsPolicy.defaultTransferPolicy()
    let shieldingConfirmationsPolicy: ConfirmationsPolicy = ConfirmationsPolicy.defaultShieldingPolicy()

    let dbData: (String, UInt)
    let fsBlockDbRoot: (String, UInt)
    let spendParamsPath: (String, UInt)
    let outputParamsPath: (String, UInt)
    let keyDeriving: ZcashKeyDerivationBackendWelding

    let networkType: NetworkType
    let sdkFlags: SDKFlags

    /// Guards the one-time Rust initialization (`initializeRust(logLevel:)` / `zcashlc_init_on_load`)
    /// against concurrent first construction. The underlying FFI call panics if invoked more than
    /// once (tracing's `.init()` plus rayon's `build_global().expect`), and an unwind across the FFI
    /// boundary aborts the process; a plain check-then-act on `rustInitialized` let two instances
    /// racing to be first (e.g. `OrchardMigration`'s own backend and the synchronizer's, constructed
    /// concurrently at launch -- see `Synchronizer/Dependencies.swift` and
    /// `Migration/OrchardMigration.swift`'s `init(config:)`, both of which construct a
    /// `ZcashRustBackend`) both observe "not yet initialized" and both call in.
    ///
    /// `OSAllocatedUnfairLock` (the user's stated global preference for new locking code) requires
    /// iOS 16 / macOS 13; this package's `Package.swift` declares `.iOS(.v13)` / `.macOS(.v12)`, and
    /// `OSAllocatedUnfairLock` does not typecheck against that deployment target (verified directly:
    /// `swiftc -target arm64-apple-macos12.0 -typecheck` on a minimal use fails with "'OSAllocatedUnfairLock'
    /// is only available in macOS 13.0 or newer"). Per that same preference's own stated fallback --
    /// "below iOS 16, use NSLock" -- this uses `NSLock`, matching the plain-`NSLock` convention already
    /// used elsewhere in this codebase (`Utils/DIContainer.swift`, `Utils/UsedAliasesChecker.swift`).
    private static let rustInitLock = NSLock()
    private static var rustInitialized = false

    /// Creates instance of `ZcashRustBackend`.
    /// - Parameters:
    ///   - dbData: `URL` pointing to file where data database will be.
    ///   - fsBlockDbRoot: `URL` pointing to the filesystem root directory where the fsBlock cache is.
    ///                    this directory  is expected to contain a `/blocks` sub-directory with the blocks stored in the convened filename
    ///                    format `{height}-{hash}-block`. This directory has must be granted both write and read permissions.
    ///   - spendParamsPath: `URL` pointing to spend parameters file.
    ///   - outputParamsPath: `URL` pointing to output parameters file.
    ///   - networkType: Network type to use.
    ///   - logLevel: this sets up whether the tracing system will dump logs onto the OSLogger system or not.
    ///     **Important note:** this will enable the tracing **for all instances** of ZcashRustBackend, not only for this one.
    ///     This is ignored after the first ZcashRustBackend instance is created -- first caller wins the log
    ///     level, even when two instances are constructed concurrently from different call sites.
    init(
        dbData: URL,
        fsBlockDbRoot: URL,
        spendParamsPath: URL,
        outputParamsPath: URL,
        networkType: NetworkType,
        logLevel: RustLogging = RustLogging.off,
        sdkFlags: SDKFlags
    ) {
        self.dbData = dbData.osStr()
        self.fsBlockDbRoot = fsBlockDbRoot.osPathStr()
        self.spendParamsPath = spendParamsPath.osPathStr()
        self.outputParamsPath = outputParamsPath.osPathStr()
        self.networkType = networkType
        self.keyDeriving = ZcashKeyDerivationBackend(networkType: networkType)
        self.sdkFlags = sdkFlags

        Self.rustInitLock.lock()
        defer { Self.rustInitLock.unlock() }
        if !Self.rustInitialized {
            Self.rustInitialized = true
            Self.initializeRust(logLevel: logLevel)
        }
    }

    /// Registers the custom network used for the regtest network id (`NetworkType.regtest`) with the
    /// Rust core: its `base` identity (address encoding / `chainName`) plus its per-NU activation
    /// heights, so subsequent FFI calls made with that network id resolve to it instead of failing.
    /// Process-global and idempotent; call once before using a custom network (see `MIGRATING.md`).
    /// A `nil` height means "not activated on this network".
    ///
    /// Returns `true` on a fresh registration or an identical re-registration. Returns `false` when
    /// the call replaced a **different** existing configuration (the replacement is still applied,
    /// last writer wins) — a host configuration bug, since the parameters are process-global and two
    /// live instances with different custom networks cannot both be honored.
    @discardableResult
    static func setCustomNetwork(base: NetworkType, _ heights: NetworkActivationHeights) -> Bool {
        func height(_ value: BlockHeight?) -> Int64 {
            guard let value else { return -1 }
            return Int64(value)
        }

        return zcashlc_set_custom_network(
            base.networkId,
            height(heights.overwinter),
            height(heights.sapling),
            height(heights.blossom),
            height(heights.heartwood),
            height(heights.canopy),
            height(heights.nu5),
            height(heights.nu6),
            height(heights.nu6_1),
            height(heights.nu6_2),
            height(heights.nu6_3)
        )
    }

    // DB-AUDIT (2026-08-03): SELECT-only, but stays serialized — listAccounts' per-id
    // getAccount loop relies on the actor's no-suspension property for enumeration
    // atomicity against deleteAccount. Un-actor only by resolving accounts in one FFI call.
    @DBActor
    func listAccounts() async throws -> [Account] {
        let accountsPtr = zcashlc_list_accounts(
            dbData.0,
            dbData.1,
            networkType.networkId
        )

        guard let accountsPtr else {
            throw ZcashError.rustListAccounts(lastErrorMessage(fallback: "`listAccounts` failed with unknown error"))
        }

        defer { zcashlc_free_accounts(accountsPtr) }

        var accounts: [Account] = []

        for i in (0 ..< Int(accountsPtr.pointee.len)) {
            let accountUUIDPtr = accountsPtr.pointee.ptr.advanced(by: i).pointee
            let accountUUID = AccountUUID(id: accountUUIDPtr.uuidArray)

            let account = try await getAccount(for: accountUUID)

            accounts.append(account)
        }

        return accounts
    }

    // DB-AUDIT (2026-08-03): SELECT-only, but stays serialized — listAccounts' per-id
    // getAccount loop relies on the actor's no-suspension property for enumeration
    // atomicity against deleteAccount. Un-actor only by resolving accounts in one FFI call.
    @DBActor
    func getAccount(
        for accountUUID: AccountUUID
    ) async throws -> Account {
        let accountPtr: UnsafeMutablePointer<FfiAccount>? = zcashlc_get_account(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id
        )

        guard let accountPtr else {
            throw ZcashError.rustImportAccountUfvk(lastErrorMessage(fallback: "`getAccount` failed with unknown error"))
        }

        defer { zcashlc_free_account(accountPtr) }

        guard let validAccount = accountPtr.pointee.unsafeToAccount() else {
            throw ZcashError.rustUUIDAccountNotFound(lastErrorMessage(fallback: "`getAccount` failed with unknown error"))
        }

        return validAccount
    }

    // swiftlint:disable:next function_parameter_count
    @DBActor func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        treeState: TreeState,
        recoverUntil: UInt32?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?
    ) async throws -> AccountUUID {
        var rUntil: Int64 = -1

        if let recoverUntil {
            rUntil = Int64(recoverUntil)
        }

        let treeStateBytes = try treeState.serializedData(partial: false).bytes

        var kSource: [CChar]?

        if let keySource {
            kSource = [CChar](keySource.utf8CString)
        }

        let index: UInt32 = zip32AccountIndex?.index ?? UINT32_MAX

        let uuidPtr = zcashlc_import_account_ufvk(
            dbData.0,
            dbData.1,
            [CChar](ufvk.utf8CString),
            treeStateBytes,
            UInt(treeStateBytes.count),
            rUntil,
            networkType.networkId,
            purpose.rawValue,
            [CChar](name.utf8CString),
            kSource,
            seedFingerprint,
            index
        )

        guard let uuidPtr else {
            throw ZcashError.rustImportAccountUfvk(lastErrorMessage(fallback: "`importAccount` failed with unknown error"))
        }

        defer { zcashlc_free_ffi_uuid(uuidPtr) }

        return uuidPtr.pointee.unsafeToAccountUUID()
    }

    @DBActor
    func createAccount(
        seed: [UInt8],
        treeState: TreeState,
        recoverUntil: UInt32?,
        name: String,
        keySource: String?
    ) async throws -> UnifiedSpendingKey {
        var rUntil: Int64 = -1

        if let recoverUntil {
            rUntil = Int64(recoverUntil)
        }

        let treeStateBytes = try treeState.serializedData(partial: false).bytes

        var kSource: [CChar]?

        if let keySource {
            kSource = [CChar](keySource.utf8CString)
        }

        let ffiBinaryKeyPtr = zcashlc_create_account(
            dbData.0,
            dbData.1,
            seed,
            UInt(seed.count),
            treeStateBytes,
            UInt(treeStateBytes.count),
            rUntil,
            networkType.networkId,
            [CChar](name.utf8CString),
            kSource
        )

        guard let ffiBinaryKeyPtr else {
            throw ZcashError.rustCreateAccount(lastErrorMessage(fallback: "`createAccount` failed with unknown error"))
        }

        defer { zcashlc_free_binary_key(ffiBinaryKeyPtr) }

        return ffiBinaryKeyPtr.pointee.unsafeToUnifiedSpendingKey(network: networkType)
    }

    // DB-READ (audited 2026-08-03): seed_relevance_to_derived_accounts — SELECT loops over
    // accounts plus in-memory key derivation.
    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        let result = zcashlc_is_seed_relevant_to_any_derived_account(
            dbData.0,
            dbData.1,
            seed,
            UInt(seed.count),
            networkType.networkId
        )

        // -1 is the error sentinel.
        guard result >= 0 else {
            throw ZcashError.rustIsSeedRelevantToAnyDerivedAccount(
                lastErrorMessage(fallback: "`isSeedRelevantToAnyDerivedAccount` failed with unknown error")
            )
        }

        // 0 is false, 1 is true.
        return result != 0
    }

    // DB-READ (audited 2026-08-03): propose_transfer with lock_inputs = None — the only write
    // branch statically skipped; input selection SELECT-only; the proposal is returned
    // serialized, never stored.
    func proposeTransfer(
        accountUUID: AccountUUID,
        to address: String,
        value: Int64,
        memo: MemoBytes?
    ) async throws -> FfiProposal {
        let proposal = zcashlc_propose_transfer(
            dbData.0,
            dbData.1,
            accountUUID.id,
            [CChar](address.utf8CString),
            value,
            memo?.bytes,
            networkType.networkId,
            confirmationsPolicy.toBackend()
        )

        guard let proposal else {
            throw ZcashError.rustCreateToAddress(lastErrorMessage(fallback: "`proposeTransfer` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(proposal) }

        return try FfiProposal(serializedBytes: Data(
            bytes: proposal.pointee.ptr,
            count: Int(proposal.pointee.len)
        ))
    }

    // DB-READ (audited 2026-08-03): propose_send_max_transfer with lock_inputs = None — write
    // branch statically gated off; selection over a shared read-only reference.
    func proposeSendMaxTransfer(
        accountUUID: AccountUUID,
        to address: String,
        memo: MemoBytes?,
        mode: MaxSpendMode
    ) async throws -> FfiProposal {
        let proposal = zcashlc_propose_send_max_transfer(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id,
            [CChar](address.utf8CString),
            memo?.bytes,
            mode.ffiMode,
            confirmationsPolicy.toBackend(),
            false // orchard_only — the public send-max path draws on every shielded pool
        )

        guard let proposal else {
            throw ZcashError.rustProposeSendMaxTransfer(lastErrorMessage(fallback: "`proposeSendMaxTransfer` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(proposal) }

        return try FfiProposal(serializedBytes: Data(
            bytes: proposal.pointee.ptr,
            count: Int(proposal.pointee.len)
        ))
    }

    // DB-READ (audited 2026-08-03): propose_send_max_transfer with lock_inputs = None — the
    // only write arm statically skipped; input selection SELECT-only; proposal returned,
    // never stored. Bypasses the migration open() preamble entirely.
    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> FfiProposal {
        let dbDataPtr = dbData.0
        let dbDataLen = dbData.1
        let account = accountUUID.id
        let networkId = networkType.networkId

        let proposal = zcashlc_propose_orchard_to_ironwood_migration(
            dbDataPtr,
            dbDataLen,
            account,
            networkId
        )

        guard let proposal else {
            throw ZcashError.rustCreateToAddress(
                lastErrorMessage(fallback: "`proposeOrchardToIronwoodMigration` failed with unknown error")
            )
        }

        defer { zcashlc_free_boxed_slice(proposal) }

        return try FfiProposal(serializedBytes: Data(
            bytes: proposal.pointee.ptr,
            count: Int(proposal.pointee.len)
        ))
    }

    // DB-READ (audited 2026-08-03): propose_transfer with lock_inputs = None — identical to
    // proposeTransfer; the URI is parsed in memory.
    func proposeTransferFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> FfiProposal {
        let proposal = zcashlc_propose_transfer_from_uri(
            dbData.0,
            dbData.1,
            accountUUID.id,
            [CChar](uri.utf8CString),
            networkType.networkId,
            confirmationsPolicy.toBackend()
        )

        guard let proposal else {
            throw ZcashError.rustCreateToAddress(lastErrorMessage(fallback: "`proposeTransfer` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(proposal) }

        return try FfiProposal(serializedBytes: Data(
            bytes: proposal.pointee.ptr,
            count: Int(proposal.pointee.len)
        ))
    }

    @DBActor
    func createPCZTFromProposal(
        accountUUID: AccountUUID,
        proposal: FfiProposal
    ) async throws -> Pczt {
        let proposalBytes = try proposal.serializedData(partial: false).bytes

        let pcztPtr = proposalBytes.withUnsafeBufferPointer { proposalPtr in
            zcashlc_create_pczt_from_proposal(
                dbData.0,
                dbData.1,
                networkType.networkId,
                proposalPtr.baseAddress,
                UInt(proposalBytes.count),
                accountUUID.id
            )
        }

        guard let pcztPtr else {
            throw ZcashError.rustCreatePCZTFromProposal(lastErrorMessage(fallback: "`createPCZTFromProposal` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(pcztPtr) }

        return Pczt(
            bytes: pcztPtr.pointee.ptr,
            count: Int(pcztPtr.pointee.len)
        )
    }

    func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt {
        let pcztPtr: UnsafeMutablePointer<FfiBoxedSlice>? = pczt.withUnsafeBytes { buffer in
            guard let bufferPtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }

            return zcashlc_redact_pczt_for_signer(
                bufferPtr,
                UInt(pczt.count)
            )
        }

        guard let pcztPtr else {
            throw ZcashError.rustRedactPCZTForSigner(lastErrorMessage(fallback: "`redactPCZTForSigner` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(pcztPtr) }

        return Pczt(
            bytes: pcztPtr.pointee.ptr,
            count: Int(pcztPtr.pointee.len)
        )
    }

    func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool {
        return pczt.withUnsafeBytes { buffer in
            guard let bufferPtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                // Return `false` here so the caller proceeds to `addProofsToPCZT` and
                // gets the same error.
                return false
            }

            return zcashlc_pczt_requires_sapling_proofs(
                bufferPtr,
                UInt(pczt.count)
            )
        }
    }

    func addProofsToPCZT(
        pczt: Pczt
    ) async throws -> Pczt {
        let pcztPtr: UnsafeMutablePointer<FfiBoxedSlice>? = pczt.withUnsafeBytes { buffer in
            guard let bufferPtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }

            return zcashlc_add_proofs_to_pczt(
                bufferPtr,
                UInt(pczt.count),
                spendParamsPath.0,
                spendParamsPath.1,
                outputParamsPath.0,
                outputParamsPath.1
            )
        }

        guard let pcztPtr else {
            throw ZcashError.rustAddProofsToPCZT(lastErrorMessage(fallback: "`addProofsToPCZT` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(pcztPtr) }

        return Pczt(
            bytes: pcztPtr.pointee.ptr,
            count: Int(pcztPtr.pointee.len)
        )
    }

    @DBActor
    func extractAndStoreTxFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> Data {
        let txidPtr: UnsafeMutablePointer<FfiBoxedSlice>? = pcztWithProofs.withUnsafeBytes { pcztWithProofsBuffer in
            guard let pcztWithProofsBufferPtr = pcztWithProofsBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }

            return pcztWithSigs.withUnsafeBytes { pcztWithSigsBuffer in
                guard let pcztWithSigsBufferPtr = pcztWithSigsBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return nil
                }

                return zcashlc_extract_and_store_from_pczt(
                    dbData.0,
                    dbData.1,
                    networkType.networkId,
                    pcztWithProofsBufferPtr,
                    UInt(pcztWithProofs.count),
                    pcztWithSigsBufferPtr,
                    UInt(pcztWithSigs.count),
                    spendParamsPath.0,
                    spendParamsPath.1,
                    outputParamsPath.0,
                    outputParamsPath.1
                )
            }
        }

        guard let txidPtr else {
            throw ZcashError.rustExtractAndStoreTxFromPCZT(lastErrorMessage(fallback: "`extractAndStoreTxFromPCZT` failed with unknown error"))
        }

        guard txidPtr.pointee.len == UInt(TxId.byteLength) else {
            throw ZcashError.rustTxidPtrIncorrectLength(lastErrorMessage(fallback: "`extractAndStoreTxFromPCZT` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(txidPtr) }

        return Data(
            bytes: txidPtr.pointee.ptr,
            count: Int(txidPtr.pointee.len)
        )
    }

    @DBActor
    func decryptAndStoreTransaction(txBytes: [UInt8], minedHeight: UInt32?) async throws -> Data {
        var contiguousTxidBytes = ContiguousArray<UInt8>(Data(count: TxId.byteLength))

        let result = contiguousTxidBytes.withUnsafeMutableBufferPointer { txidBytePtr in
            zcashlc_decrypt_and_store_transaction(
                dbData.0,
                dbData.1,
                txBytes,
                UInt(txBytes.count),
                Int64(minedHeight ?? 0),
                networkType.networkId,
                txidBytePtr.baseAddress
            )
        }

        // The FFI returns 1 on success and -1 on error; it never returns 0. Only a
        // returned 1 means the transaction was stored and the txid buffer was written.
        guard result == 1 else {
            throw ZcashError.rustDecryptAndStoreTransaction(lastErrorMessage(fallback: "`decryptAndStoreTransaction` failed with unknown error"))
        }

        return Data(contiguousTxidBytes)
    }

    // DB-READ (audited 2026-08-03): get_last_generated_address_matching — SELECT on
    // addresses; generates nothing.
    func getCurrentAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        let addressCStr = zcashlc_get_current_address(
            dbData.0,
            dbData.1,
            accountUUID.id,
            networkType.networkId
        )

        guard let addressCStr else {
            throw ZcashError.rustGetCurrentAddress(lastErrorMessage(fallback: "`getCurrentAddress` failed with unknown error"))
        }

        defer { zcashlc_string_free(addressCStr) }

        guard let address = String(validatingUTF8: addressCStr) else {
            throw ZcashError.rustGetCurrentAddressInvalidAddress
        }

        return UnifiedAddress(validatedEncoding: address, networkType: networkType)
    }

    @DBActor
    func getNextAvailableAddress(accountUUID: AccountUUID, receiverFlags: UInt32) async throws -> UnifiedAddress {
        let addressCStr = zcashlc_get_next_available_address(
            dbData.0,
            dbData.1,
            accountUUID.id,
            networkType.networkId,
            receiverFlags
        )

        guard let addressCStr else {
            throw ZcashError.rustGetNextAvailableAddress(lastErrorMessage(fallback: "`getNextAvailableAddress` failed with unknown error"))
        }

        defer { zcashlc_string_free(addressCStr) }

        guard let address = String(validatingUTF8: addressCStr) else {
            throw ZcashError.rustGetNextAvailableAddressInvalidAddress
        }

        return UnifiedAddress(validatedEncoding: address, networkType: networkType)
    }

    // DB-READ (audited 2026-08-03): get_sent_memo / get_received_memo — two query_row
    // SELECTs.
    func getMemo(txId: Data, outputPool: UInt32, outputIndex: UInt16) async throws -> Memo? {
        guard txId.count == TxId.byteLength else {
            throw ZcashError.rustGetMemoInvalidTxIdLength
        }

        var contiguousMemoBytes = ContiguousArray<UInt8>(MemoBytes.empty().bytes)
        var success = false

        contiguousMemoBytes.withUnsafeMutableBufferPointer { memoBytePtr in
            success = zcashlc_get_memo(dbData.0, dbData.1, txId.bytes, outputPool, outputIndex, memoBytePtr.baseAddress, networkType.networkId)
        }

        guard success else { return nil }

        return (try? MemoBytes(contiguousBytes: contiguousMemoBytes)).flatMap { try? $0.intoMemo() }
    }

    // DB-READ (audited 2026-08-03): get_transparent_balances — SELECT-only; the only inserts
    // in the body are into a Rust HashMap.
    func getTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        let balance = zcashlc_get_total_transparent_balance_for_account(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id
        )

        guard balance >= 0 else {
            throw ZcashError.rustGetTransparentBalance(
                accountUUID,
                lastErrorMessage(fallback: "Error getting Total Transparent balance from accountUUID \(accountUUID.id)")
            )
        }

        return balance
    }

    // DB-READ (audited 2026-08-03): get_spendable_transparent_outputs — SELECT-only; the
    // lock policy only filters rows, acquires nothing.
    func getVerifiedTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        let balance = zcashlc_get_verified_transparent_balance_for_account(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id,
            shieldingConfirmationsPolicy.toBackend()
        )

        guard balance >= 0 else {
            throw ZcashError.rustGetVerifiedTransparentBalance(
                accountUUID,
                lastErrorMessage(fallback: "Error getting verified transparent balance from accountUUID \(accountUUID.id)")
            )
        }

        return balance
    }

    @DBActor
    func initDataDb(seed: [UInt8]?) async throws -> DbInitResult {
        let initResult = zcashlc_init_data_database(dbData.0, dbData.1, seed, UInt(seed?.count ?? 0), networkType.networkId)

        switch initResult {
        case 0: // ok
            return DbInitResult.success
        case 1:
            return DbInitResult.seedRequired
        case 2:
            return DbInitResult.seedNotRelevant
        default:
            throw ZcashError.rustInitDataDb(lastErrorMessage(fallback: "`initDataDb` failed with unknown error"))
        }
    }

    @DBActor
    func initBlockMetadataDb() async throws {
        let result = zcashlc_init_block_metadata_db(fsBlockDbRoot.0, fsBlockDbRoot.1)

        guard result else {
            throw ZcashError.rustInitBlockMetadataDb(lastErrorMessage(fallback: "`initBlockMetadataDb` failed with unknown error"))
        }
    }

    @DBActor
    func writeBlocksMetadata(blocks: [ZcashCompactBlock]) async throws {
        var ffiBlockMetaVec: [FFIBlockMeta] = []

        for block in blocks {
            let meta = block.meta
            let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: meta.hash.count)

            let contiguousHashBytes = ContiguousArray(meta.hash.bytes)

            let result: Void? = contiguousHashBytes.withContiguousStorageIfAvailable { hashBytesPtr in
                // swiftlint:disable:next force_unwrapping
                hashPtr.initialize(from: hashBytesPtr.baseAddress!, count: hashBytesPtr.count)
            }

            guard result != nil else {
                defer {
                    hashPtr.deallocate()
                    ffiBlockMetaVec.deallocateElements()
                }
                throw ZcashError.rustWriteBlocksMetadataAllocationProblem
            }

            ffiBlockMetaVec.append(
                FFIBlockMeta(
                    height: UInt32(block.height),
                    block_hash_ptr: hashPtr,
                    block_hash_ptr_len: UInt(contiguousHashBytes.count),
                    block_time: meta.time,
                    sapling_outputs_count: meta.saplingOutputs,
                    orchard_actions_count: meta.orchardOutputs
                )
            )
        }

        var contiguousFFIBlocks = ContiguousArray(ffiBlockMetaVec)

        let len = UInt(contiguousFFIBlocks.count)

        let fsBlocks = UnsafeMutablePointer<FFIBlocksMeta>.allocate(capacity: 1)

        defer { ffiBlockMetaVec.deallocateElements() }

        try contiguousFFIBlocks.withContiguousMutableStorageIfAvailable { ptr in
            var meta = FFIBlocksMeta()
            meta.ptr = ptr.baseAddress
            meta.len = len

            fsBlocks.initialize(to: meta)

            let res = zcashlc_write_block_metadata(fsBlockDbRoot.0, fsBlockDbRoot.1, fsBlocks)

            guard res else {
                throw ZcashError.rustWriteBlocksMetadata(lastErrorMessage(fallback: "`writeBlocksMetadata` failed with unknown error"))
            }
        }
    }

    // DB-READ (audited 2026-08-03): FsBlockDb get_max_cached_height — SELECT MAX(height)
    // on the cache-metadata DB.
    func latestCachedBlockHeight() async throws -> BlockHeight {
        let height = zcashlc_latest_cached_block_height(fsBlockDbRoot.0, fsBlockDbRoot.1)

        if height >= 0 {
            return BlockHeight(height)
        } else if height == -1 {
            return BlockHeight.empty()
        } else {
            throw ZcashError.rustLatestCachedBlockHeight(lastErrorMessage(fallback: "`latestCachedBlockHeight` failed with unknown error"))
        }
    }

    // DB-READ (audited 2026-08-03): get_transparent_receivers — no SQL writes anywhere in
    // its body.
    func listTransparentReceivers(accountUUID: AccountUUID) async throws -> [TransparentAddress] {
        let encodedKeysPtr = zcashlc_list_transparent_receivers(
            dbData.0,
            dbData.1,
            accountUUID.id,
            networkType.networkId
        )

        guard let encodedKeysPtr else {
            throw ZcashError.rustListTransparentReceivers(lastErrorMessage(fallback: "`listTransparentReceivers` failed with unknown error"))
        }

        defer { zcashlc_free_keys(encodedKeysPtr) }

        var addresses: [TransparentAddress] = []

        for i in (0 ..< Int(encodedKeysPtr.pointee.len)) {
            let key = encodedKeysPtr.pointee.ptr.advanced(by: i).pointee

            guard let taddrStr = String(validatingUTF8: key.encoding) else {
                throw ZcashError.rustListTransparentReceiversInvalidAddress
            }

            addresses.append(
                TransparentAddress(validatedEncoding: taddrStr)
            )
        }

        return addresses
    }

    @DBActor
    func putUnspentTransparentOutput(
        txid: [UInt8],
        index: Int,
        script: [UInt8],
        value: Int64,
        height: BlockHeight
    ) async throws {
        let result = zcashlc_put_utxo(
            dbData.0,
            dbData.1,
            txid,
            UInt(txid.count),
            Int32(index),
            script,
            UInt(script.count),
            value,
            Int32(height),
            networkType.networkId
        )

        guard result else {
            throw ZcashError.rustPutUnspentTransparentOutput(lastErrorMessage(fallback: "`putUnspentTransparentOutput` failed with unknown error"))
        }
    }

    @DBActor
    func rewindToHeight(height: BlockHeight) async throws -> RewindResult {
        var safeRewindHeight: Int64 = -1
        let result = zcashlc_rewind_to_height(dbData.0, dbData.1, UInt32(height), networkType.networkId, &safeRewindHeight)

        if result >= 0 {
            return .success(BlockHeight(result))
        } else if result == -1 && safeRewindHeight > 0 {
            return .requestedHeightTooLow(BlockHeight(safeRewindHeight))
        } else {
            throw ZcashError.rustRewindToHeight(Int32(height), lastErrorMessage(fallback: "`rewindToHeight` failed with unknown error"))
        }
    }

    @DBActor
    func truncateToChainState(chainState: TreeState) async throws {
        let chainStateBytes = try chainState.serializedData(partial: false).bytes

        let result = zcashlc_truncate_to_chain_state(
            dbData.0,
            dbData.1,
            chainStateBytes,
            UInt(chainStateBytes.count),
            networkType.networkId
        )

        guard result else {
            throw ZcashError.rustTruncateToChainState(lastErrorMessage(fallback: "`truncateToChainState` failed with unknown error"))
        }
    }

    @DBActor
    func rewindCacheToHeight(height: Int32) async throws {
        let result = zcashlc_rewind_fs_block_cache_to_height(fsBlockDbRoot.0, fsBlockDbRoot.1, height)

        guard result else {
            throw ZcashError.rustRewindCacheToHeight(lastErrorMessage(fallback: "`rewindCacheToHeight` failed with unknown error"))
        }
    }

    @DBActor
    func putSaplingSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        var ffiSubtreeRootsVec: [FfiSubtreeRoot] = []

        for root in roots {
            let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: root.rootHash.count)

            let contiguousHashBytes = ContiguousArray(root.rootHash.bytes)

            let result: Void? = contiguousHashBytes.withContiguousStorageIfAvailable { hashBytesPtr in
                // swiftlint:disable:next force_unwrapping
                hashPtr.initialize(from: hashBytesPtr.baseAddress!, count: hashBytesPtr.count)
            }

            guard result != nil else {
                defer {
                    hashPtr.deallocate()
                    ffiSubtreeRootsVec.deallocateElements()
                }
                throw ZcashError.rustPutSaplingSubtreeRootsAllocationProblem
            }

            guard let completingBlockHeight = UInt32(exactly: root.completingBlockHeight) else {
                defer {
                    hashPtr.deallocate()
                    ffiSubtreeRootsVec.deallocateElements()
                }
                throw ZcashError.rustPutSaplingSubtreeRoots(
                    "server-supplied completing block height \(root.completingBlockHeight) does not fit in UInt32"
                )
            }

            ffiSubtreeRootsVec.append(
                FfiSubtreeRoot(
                    root_hash_ptr: hashPtr,
                    root_hash_ptr_len: UInt(contiguousHashBytes.count),
                    completing_block_height: completingBlockHeight
                )
            )
        }

        var contiguousFfiRoots = ContiguousArray(ffiSubtreeRootsVec)

        let len = UInt(contiguousFfiRoots.count)

        let rootsPtr = UnsafeMutablePointer<FfiSubtreeRoots>.allocate(capacity: 1)

        defer {
            ffiSubtreeRootsVec.deallocateElements()
            rootsPtr.deallocate()
        }

        try contiguousFfiRoots.withContiguousMutableStorageIfAvailable { ptr in
            var roots = FfiSubtreeRoots()
            roots.ptr = ptr.baseAddress
            roots.len = len

            rootsPtr.initialize(to: roots)

            let res = zcashlc_put_sapling_subtree_roots(dbData.0, dbData.1, startIndex, rootsPtr, networkType.networkId)

            guard res else {
                throw ZcashError.rustPutSaplingSubtreeRoots(lastErrorMessage(fallback: "`putSaplingSubtreeRoots` failed with unknown error"))
            }
        }
    }

    @DBActor
    func putOrchardSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        var ffiSubtreeRootsVec: [FfiSubtreeRoot] = []

        for root in roots {
            let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: root.rootHash.count)

            let contiguousHashBytes = ContiguousArray(root.rootHash.bytes)

            let result: Void? = contiguousHashBytes.withContiguousStorageIfAvailable { hashBytesPtr in
                // swiftlint:disable:next force_unwrapping
                hashPtr.initialize(from: hashBytesPtr.baseAddress!, count: hashBytesPtr.count)
            }

            guard result != nil else {
                defer {
                    hashPtr.deallocate()
                    ffiSubtreeRootsVec.deallocateElements()
                }
                throw ZcashError.rustPutOrchardSubtreeRootsAllocationProblem
            }

            guard let completingBlockHeight = UInt32(exactly: root.completingBlockHeight) else {
                defer {
                    hashPtr.deallocate()
                    ffiSubtreeRootsVec.deallocateElements()
                }
                throw ZcashError.rustPutOrchardSubtreeRoots(
                    "server-supplied completing block height \(root.completingBlockHeight) does not fit in UInt32"
                )
            }

            ffiSubtreeRootsVec.append(
                FfiSubtreeRoot(
                    root_hash_ptr: hashPtr,
                    root_hash_ptr_len: UInt(contiguousHashBytes.count),
                    completing_block_height: completingBlockHeight
                )
            )
        }

        var contiguousFfiRoots = ContiguousArray(ffiSubtreeRootsVec)

        let len = UInt(contiguousFfiRoots.count)

        let rootsPtr = UnsafeMutablePointer<FfiSubtreeRoots>.allocate(capacity: 1)

        defer {
            ffiSubtreeRootsVec.deallocateElements()
            rootsPtr.deallocate()
        }

        try contiguousFfiRoots.withContiguousMutableStorageIfAvailable { ptr in
            var roots = FfiSubtreeRoots()
            roots.ptr = ptr.baseAddress
            roots.len = len

            rootsPtr.initialize(to: roots)

            let res = zcashlc_put_orchard_subtree_roots(dbData.0, dbData.1, startIndex, rootsPtr, networkType.networkId)

            guard res else {
                throw ZcashError.rustPutOrchardSubtreeRoots(lastErrorMessage(fallback: "`putOrchardSubtreeRoots` failed with unknown error"))
            }
        }
    }

    @DBActor
    func putIronwoodSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        var ffiSubtreeRootsVec: [FfiSubtreeRoot] = []

        for root in roots {
            let hashPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: root.rootHash.count)

            let contiguousHashBytes = ContiguousArray(root.rootHash.bytes)

            let result: Void? = contiguousHashBytes.withContiguousStorageIfAvailable { hashBytesPtr in
                // swiftlint:disable:next force_unwrapping
                hashPtr.initialize(from: hashBytesPtr.baseAddress!, count: hashBytesPtr.count)
            }

            guard result != nil else {
                defer {
                    hashPtr.deallocate()
                    ffiSubtreeRootsVec.deallocateElements()
                }
                throw ZcashError.rustPutIronwoodSubtreeRootsAllocationProblem
            }

            guard let completingBlockHeight = UInt32(exactly: root.completingBlockHeight) else {
                defer {
                    hashPtr.deallocate()
                    ffiSubtreeRootsVec.deallocateElements()
                }
                throw ZcashError.rustPutIronwoodSubtreeRoots(
                    "server-supplied completing block height \(root.completingBlockHeight) does not fit in UInt32"
                )
            }

            ffiSubtreeRootsVec.append(
                FfiSubtreeRoot(
                    root_hash_ptr: hashPtr,
                    root_hash_ptr_len: UInt(contiguousHashBytes.count),
                    completing_block_height: completingBlockHeight
                )
            )
        }

        var contiguousFfiRoots = ContiguousArray(ffiSubtreeRootsVec)

        let len = UInt(contiguousFfiRoots.count)

        let rootsPtr = UnsafeMutablePointer<FfiSubtreeRoots>.allocate(capacity: 1)

        defer {
            ffiSubtreeRootsVec.deallocateElements()
            rootsPtr.deallocate()
        }

        try contiguousFfiRoots.withContiguousMutableStorageIfAvailable { ptr in
            var roots = FfiSubtreeRoots()
            roots.ptr = ptr.baseAddress
            roots.len = len

            rootsPtr.initialize(to: roots)

            let res = zcashlc_put_ironwood_subtree_roots(dbData.0, dbData.1, startIndex, rootsPtr, networkType.networkId)

            guard res else {
                throw ZcashError.rustPutIronwoodSubtreeRoots(lastErrorMessage(fallback: "`putIronwoodSubtreeRoots` failed with unknown error"))
            }
        }
    }

    @DBActor
    func updateChainTip(height: Int32) async throws {
        let result = zcashlc_update_chain_tip(dbData.0, dbData.1, height, networkType.networkId)

        guard result else {
            throw ZcashError.rustUpdateChainTip(lastErrorMessage(fallback: "`updateChainTip` failed with unknown error"))
        }
    }

    // DB-READ (audited 2026-08-03): block_fully_scanned — SELECTs via fully-scanned height
    // and block metadata.
    func fullyScannedHeight() async throws -> BlockHeight? {
        let height = zcashlc_fully_scanned_height(dbData.0, dbData.1, networkType.networkId)

        if height >= 0 {
            return BlockHeight(height)
        } else if height == -1 {
            return nil
        } else {
            throw ZcashError.rustFullyScannedHeight(lastErrorMessage(fallback: "`fullyScannedHeight` failed with unknown error"))
        }
    }

    // DB-READ (audited 2026-08-03): block_max_scanned — single query_row SELECT.
    func maxScannedHeight() async throws -> BlockHeight? {
        let height = zcashlc_max_scanned_height(dbData.0, dbData.1, networkType.networkId)

        if height >= 0 {
            return BlockHeight(height)
        } else if height == -1 {
            return nil
        } else {
            throw ZcashError.rustMaxScannedHeight(lastErrorMessage(fallback: "`maxScannedHeight` failed with unknown error"))
        }
    }

    // DB-READ (audited 2026-08-03): get_wallet_summary — verified no INSERT/UPDATE/DELETE/DDL
    // across its whole body; the sdkFlags await sits after the FFI window.
    func getWalletSummary() async throws -> WalletSummary? {
        let summaryPtr = zcashlc_get_wallet_summary(dbData.0, dbData.1, networkType.networkId, confirmationsPolicy.toBackend())

        guard let summaryPtr else {
            throw ZcashError.rustGetWalletSummary(lastErrorMessage(fallback: "`getWalletSummary` failed with unknown error"))
        }

        defer { zcashlc_free_wallet_summary(summaryPtr) }

        // C → Swift mapping shared with the unified wallet-summary path (WalletSummary+FFI.swift).
        guard let summary = WalletSummary.fromFFI(summaryPtr) else { return nil }

        // Mask spendable `accountBalances` while chainTip hasn't been updated yet ([#1591]).
        if await !sdkFlags.chainTipUpdated {
            return summary.withSpendableMasked()
        }

        return summary
    }

    // DB-READ (audited 2026-08-03): suggest_scan_ranges — single SELECT on scan_queue; no
    // request state is consumed.
    func suggestScanRanges() async throws -> [ScanRange] {
        let scanRangesPtr = zcashlc_suggest_scan_ranges(dbData.0, dbData.1, networkType.networkId)

        guard let scanRangesPtr else {
            throw ZcashError.rustSuggestScanRanges(lastErrorMessage(fallback: "`suggestScanRanges` failed with unknown error"))
        }

        defer { zcashlc_free_scan_ranges(scanRangesPtr) }

        var scanRanges: [ScanRange] = []

        for i in (0 ..< Int(scanRangesPtr.pointee.len)) {
            let scanRange = scanRangesPtr.pointee.ptr.advanced(by: i).pointee

            scanRanges.append(
                ScanRange(
                    range: Range(uncheckedBounds: (
                        BlockHeight(scanRange.start),
                        BlockHeight(scanRange.end)
                    )),
                    priority: ScanRange.Priority(scanRange.priority)
                )
            )
        }

        return scanRanges
    }

    @DBActor
    func scanBlocks(fromHeight: Int32, fromState: TreeState, limit: UInt32 = 0) async throws -> ScanSummary {
        let fromStateBytes = try fromState.serializedData(partial: false).bytes

        let summaryPtr = zcashlc_scan_blocks(
            fsBlockDbRoot.0,
            fsBlockDbRoot.1,
            dbData.0,
            dbData.1,
            fromHeight,
            fromStateBytes,
            UInt(fromStateBytes.count),
            limit,
            networkType.networkId
        )

        guard let summaryPtr else {
            throw ZcashError.rustScanBlocks(lastErrorMessage(fallback: "`scanBlocks` failed with unknown error"))
        }

        defer { zcashlc_free_scan_summary(summaryPtr) }

        return ScanSummary(
            scannedRange: Range(uncheckedBounds: (
                BlockHeight(summaryPtr.pointee.scanned_start),
                BlockHeight(summaryPtr.pointee.scanned_end)
            )),
            spentSaplingNoteCount: summaryPtr.pointee.spent_sapling_note_count,
            receivedSaplingNoteCount: summaryPtr.pointee.received_sapling_note_count
        )
    }

    // DB-READ (audited 2026-08-03): propose_shielding with lock_inputs = None — write branch
    // statically gated off; pre-reads SELECT-only; returns without writing when nothing is
    // shieldable.
    func proposeShielding(
        accountUUID: AccountUUID,
        memo: MemoBytes?,
        shieldingThreshold: Zatoshi,
        transparentReceiver: String?
    ) async throws -> FfiProposal? {
        let proposal = zcashlc_propose_shielding(
            dbData.0,
            dbData.1,
            accountUUID.id,
            memo?.bytes,
            UInt64(shieldingThreshold.amount),
            transparentReceiver.map { [CChar]($0.utf8CString) },
            networkType.networkId,
            shieldingConfirmationsPolicy.toBackend()
        )

        guard let proposal else {
            throw ZcashError.rustShieldFunds(lastErrorMessage(fallback: "Failed with nil proposal."))
        }

        defer { zcashlc_free_boxed_slice(proposal) }

        guard proposal.pointee.ptr != nil else {
            return nil
        }

        return try FfiProposal(serializedBytes: Data(
            bytes: proposal.pointee.ptr,
            count: Int(proposal.pointee.len)
        ))
    }

    @DBActor
    func createProposedTransactions(
        proposal: FfiProposal,
        usk: UnifiedSpendingKey
    ) async throws -> [Data] {
        let proposalBytes = try proposal.serializedData(partial: false).bytes

        let txIdsPtr = proposalBytes.withUnsafeBufferPointer { proposalPtr in
            usk.bytes.withUnsafeBufferPointer { uskPtr in
                zcashlc_create_proposed_transactions(
                    dbData.0,
                    dbData.1,
                    proposalPtr.baseAddress,
                    UInt(proposalBytes.count),
                    uskPtr.baseAddress,
                    UInt(usk.bytes.count),
                    spendParamsPath.0,
                    spendParamsPath.1,
                    outputParamsPath.0,
                    outputParamsPath.1,
                    networkType.networkId
                )
            }
        }

        guard let txIdsPtr else {
            throw ZcashError.rustCreateToAddress(lastErrorMessage(fallback: "`createToAddress` failed with unknown error"))
        }

        defer { zcashlc_free_txids(txIdsPtr) }

        var txIds: [Data] = []

        for i in (0 ..< Int(txIdsPtr.pointee.len)) {
            let txId = FfiTxId(tuple: txIdsPtr.pointee.ptr.advanced(by: i).pointee)
            txIds.append(Data(txId.array))
        }

        return txIds
    }

    // DB-READ (audited 2026-08-13): WalletRead::get_transaction — opens the wallet database
    // read-only and executes SELECT-only transaction lookup and parsing.
    func getTransaction(txId: Data) async throws -> TransactionData? {
        guard txId.count == TxId.byteLength else {
            throw ZcashError.rustGetTransaction("Transaction id must be \(TxId.byteLength) bytes")
        }

        let txIdBytes = [UInt8](txId)
        let transactionPtr = txIdBytes.withUnsafeBufferPointer { txIdPtr in
            zcashlc_get_transaction(
                dbData.0,
                dbData.1,
                txIdPtr.baseAddress,
                networkType.networkId
            )
        }

        guard let transactionPtr else {
            throw ZcashError.rustGetTransaction(lastErrorMessage(fallback: "Failed to read transaction from the wallet store"))
        }

        defer { zcashlc_free_transaction_data(transactionPtr) }

        guard let transaction = transactionPtr.pointee.unsafeToTransactionData() else { return nil }

        guard transaction.txId == txId else {
            throw ZcashError.rustGetTransaction("Stored transaction id does not match the requested id")
        }

        return transaction
    }

    nonisolated func consensusBranchIdFor(height: Int32) throws -> Int32 {
        let branchId = zcashlc_branch_id_for_height(height, networkType.networkId)

        guard branchId != -1 else {
            throw ZcashError.rustNoConsensusBranchId(height)
        }

        return branchId
    }

    // DB-READ (audited 2026-08-03): transaction_data_requests — SELECT-only in both the
    // wallet and transparent bodies; no request state is consumed or marked.
    func transactionDataRequests() async throws -> [TransactionDataRequest] {
        let tDataRequestsPtr = zcashlc_transaction_data_requests(
            dbData.0,
            dbData.1,
            networkType.networkId
        )

        guard let tDataRequestsPtr else {
            throw ZcashError.rustTransactionDataRequests(lastErrorMessage(fallback: "`transactionDataRequests` failed with unknown error"))
        }

        defer { zcashlc_free_transaction_data_requests(tDataRequestsPtr) }

        var transactionDataRequests: [TransactionDataRequest] = []

        for i in (0 ..< Int(tDataRequestsPtr.pointee.len)) {
            let tDataRequestPtr = tDataRequestsPtr.pointee.ptr.advanced(by: i).pointee

            var tDataRequest: TransactionDataRequest?

            if tDataRequestPtr.tag == 0 {
                tDataRequest = TransactionDataRequest.getStatus(FfiTxId(tuple: tDataRequestPtr.get_status).array)
            } else if tDataRequestPtr.tag == 1 {
                tDataRequest = TransactionDataRequest.enhancement(FfiTxId(tuple: tDataRequestPtr.enhancement).array)
            } else if tDataRequestPtr.tag == 2, let address = String(validatingUTF8: tDataRequestPtr.transactions_involving_address.address) {
                let end = tDataRequestPtr.transactions_involving_address.block_range_end
                let blockRangeEnd: UInt32? = end > UInt32.max || end == -1 ? nil : UInt32(end)

                let ffiRequestAt = tDataRequestPtr.transactions_involving_address.request_at
                let requestAt: Date? = if ffiRequestAt == -1 {
                    nil
                } else if ffiRequestAt >= 0 {
                    Date(timeIntervalSince1970: TimeInterval(ffiRequestAt))
                } else {
                    throw ZcashError.rustTransactionDataRequests("Invalid request_at")
                }

                let ffiTxStatusFilter = tDataRequestPtr.transactions_involving_address.tx_status_filter
                let txStatusFilter = if ffiTxStatusFilter == TransactionStatusFilter_Mined {
                    TransactionStatusFilter.mined
                } else if ffiTxStatusFilter == TransactionStatusFilter_Mempool {
                    TransactionStatusFilter.mempool
                } else if ffiTxStatusFilter == TransactionStatusFilter_All {
                    TransactionStatusFilter.all
                } else {
                    throw ZcashError.rustTransactionDataRequests("Invalid tx_status_filter")
                }

                let ffiOutputStatusFilter = tDataRequestPtr.transactions_involving_address.output_status_filter
                let outputStatusFilter = if ffiOutputStatusFilter == OutputStatusFilter_Unspent {
                    OutputStatusFilter.unspent
                } else if ffiOutputStatusFilter == OutputStatusFilter_All {
                    OutputStatusFilter.all
                } else {
                    throw ZcashError.rustTransactionDataRequests("Invalid output_status_filter")
                }

                tDataRequest = TransactionDataRequest.transactionsInvolvingAddress(
                    TransactionsInvolvingAddress(
                        address: address,
                        blockRangeStart: tDataRequestPtr.transactions_involving_address.block_range_start,
                        blockRangeEnd: blockRangeEnd,
                        requestAt: requestAt,
                        txStatusFilter: txStatusFilter,
                        outputStatusFilter: outputStatusFilter
                    )
                )
            }

            if let tDataRequest {
                transactionDataRequests.append(tDataRequest)
            }
        }

        return transactionDataRequests
    }

    @DBActor
    func setTransactionStatus(txId: Data, status: TransactionStatus) async throws {
        var transactionStatus = FfiTransactionStatus()

        switch status {
        case .txidNotRecognized:
            transactionStatus.tag = 0
        case .notInMainChain:
            transactionStatus.tag = 1
        case .mined(let height):
            transactionStatus.tag = 2
            transactionStatus.mined = UInt32(height)
        }

        let success = zcashlc_set_transaction_status(
            dbData.0,
            dbData.1,
            networkType.networkId,
            txId.bytes,
            UInt(txId.bytes.count),
            transactionStatus
        )

        guard success else {
            throw ZcashError.rustSetTransactionStatus(
                lastErrorMessage(fallback: "`setTransactionStatus` failed with unknown error")
            )
        }
    }

    @DBActor
    func fixWitnesses() async {
        zcashlc_fix_witnesses(dbData.0, dbData.1, networkType.networkId)
    }

    @DBActor
    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        let singleUseTaddrPtr = zcashlc_get_single_use_taddr(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id
        )

        guard let singleUseTaddrPtr else {
            throw ZcashError.rustGetSingleUseTransparentAddress(
                lastErrorMessage(fallback: "`getSingleUseTransparentAddress` failed with unknown error")
            )
        }

        defer { zcashlc_free_single_use_taddr(singleUseTaddrPtr) }

        return SingleUseTransparentAddress(
            address: String(cString: singleUseTaddrPtr.pointee.address),
            gapPosition: singleUseTaddrPtr.pointee.gap_position,
            gapLimit: singleUseTaddrPtr.pointee.gap_limit
        )
    }

    @DBActor
    func deleteAccount(_ accountUUID: AccountUUID) async throws {
        let success = zcashlc_delete_account(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id
        )

        guard success else {
            throw ZcashError.rustDeleteAccount(
                lastErrorMessage(fallback: "`deleteAccount` failed with unknown error")
            )
        }
    }

    // MARK: - Ironwood migration

    @DBActor
    func migrationAdvanceStep(for account: AccountUUID) async throws -> MigrationAdvance? {
        try await migrationAdvanceStep(for: account, estimatedTip: nil)
    }

    @DBActor
    func migrationAdvanceStep(
        for account: AccountUUID,
        estimatedTip: BlockHeight?
    ) async throws -> MigrationAdvance? {
        // Clear any stale, unconsumed last-error before this sentinel read (see
        // `migrationIsNoteSplitNeeded` below): a NULL return overloads "no stored run" and
        // "error", and only a recorded last-error distinguishes the two.
        zcashlc_clear_last_error()

        let stepPtr = zcashlc_migration_advance_step(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            estimatedTip.map(Int64.init) ?? -1
        )

        // NULL with no recorded error is the benign "no migration run is stored" answer (the
        // pointer analog of the bool/`-1` sentinel reads above).
        guard let stepPtr else {
            if zcashlc_last_error_length() > 0 {
                throw ZcashError.rustMigrationAdvanceStep(
                    lastErrorMessage(fallback: "`migrationAdvanceStep` failed with unknown error")
                )
            }

            return nil
        }

        defer { zcashlc_free_migration_advance_step(stepPtr) }

        guard let advance = stepPtr.pointee.unsafeToMigrationAdvance() else {
            throw ZcashError.rustMigrationAdvanceStep(
                lastErrorMessage(fallback: "`migrationAdvanceStep` returned a malformed step")
            )
        }

        return advance
    }

    // DB-READ (audited 2026-08-05): zcashlc_migration_sync_wakeups — opens through the
    // FFI's `open_read` (both connections SQLITE_OPEN_READ_ONLY; no reconcile, no preamble
    // writes), so read-only-ness is machine-enforced: a write anywhere down this path fails
    // SQLITE_READONLY rather than silently reclassifying the call. Mined promotion is persisted
    // by the write lanes (advance-step sweep, prove sweep, delivery serves).
    func migrationSyncWakeups(for account: AccountUUID) async throws -> [MigrationSyncWakeup] {
        let wakeupsPtr = zcashlc_migration_sync_wakeups(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        guard let wakeupsPtr else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationSyncWakeups` failed with unknown error"),
                fallback: ZcashError.rustMigrationSyncWakeups
            )
        }

        defer { zcashlc_free_migration_sync_wakeups(wakeupsPtr) }

        var wakeups: [MigrationSyncWakeup] = []
        wakeups.reserveCapacity(Int(wakeupsPtr.pointee.len))

        for index in 0 ..< Int(wakeupsPtr.pointee.len) {
            let row = wakeupsPtr.pointee.rows.advanced(by: index).pointee
            var covers: [UInt32] = []
            covers.reserveCapacity(Int(row.covers_len))
            if let coversPtr = row.covers {
                for coverIndex in 0 ..< Int(row.covers_len) {
                    covers.append(coversPtr.advanced(by: coverIndex).pointee)
                }
            }
            wakeups.append(MigrationSyncWakeup(height: BlockHeight(row.height), coversTransferIds: covers))
        }

        return wakeups
    }

    // DB-READ (audited 2026-08-03): wrapper-local SQL on its own SQLITE_OPEN_READ_ONLY
    // connection — single SELECT over `blocks`; writes impossible at connection level.
    func migrationBlockRateSamples(window: UInt32) async throws -> [MigrationBlockRateSample] {
        let samplesPtr = zcashlc_migration_block_rate_samples(
            dbData.0,
            dbData.1,
            networkType.networkId,
            window
        )

        guard let samplesPtr else {
            throw ZcashError.rustMigrationBlockRateSamples(
                lastErrorMessage(fallback: "`migrationBlockRateSamples` failed with unknown error")
            )
        }

        defer { zcashlc_free_block_rate_samples(samplesPtr) }

        var samples: [MigrationBlockRateSample] = []
        samples.reserveCapacity(Int(samplesPtr.pointee.len))

        for index in 0 ..< Int(samplesPtr.pointee.len) {
            let row = samplesPtr.pointee.rows.advanced(by: index).pointee
            samples.append(MigrationBlockRateSample(height: BlockHeight(row.height), unixTime: row.unix_time))
        }

        return samples
    }


    // DB-free: a pure split over the caller's action weights (mirrors the Keystone UR bridge
    // below), so unlike the wallet-db migration methods this is not `@DBActor`.
    func migrationBatchPcztsByActions(actions: [UInt32], maxActionsPerSession: Int) async throws -> [Int] {
        // A budget outside `UInt32`'s range (negative, or absurdly huge on 64-bit `Int`) is the
        // same caller bug the rust side reports for a sub-16 budget: throw it, never trap on the
        // conversion (A7) — this is reachable from the public
        // `batchMigrationPcztsForSigning(_:maxActionsPerSession:)`.
        guard let sessionBudget = UInt32(exactly: maxActionsPerSession) else {
            throw ZcashError.rustMigrationBatchPcztsByActions(
                "`migrationBatchPcztsByActions` was given a `maxActionsPerSession` (\(maxActionsPerSession)) outside the FFI's UInt32 range"
            )
        }

        let sizesPtr = actions.withUnsafeBufferPointer { actionsPtr in
            zcashlc_migration_batch_pczts_by_actions(
                actionsPtr.baseAddress,
                UInt(actionsPtr.count),
                sessionBudget
            )
        }

        guard let sizesPtr else {
            throw ZcashError.rustMigrationBatchPcztsByActions(
                lastErrorMessage(fallback: "`migrationBatchPcztsByActions` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_batch_sizes(sizesPtr) }

        var sizes: [Int] = []
        sizes.reserveCapacity(Int(sizesPtr.pointee.len))

        for index in 0 ..< Int(sizesPtr.pointee.len) {
            sizes.append(Int(sizesPtr.pointee.ptr.advanced(by: index).pointee))
        }

        return sizes
    }

    // DB-READ (audited 2026-08-05): zcashlc_migration_progress — opens through the
    // FFI's `open_read` (both connections SQLITE_OPEN_READ_ONLY; no reconcile, no preamble
    // writes), so read-only-ness is machine-enforced: a write anywhere down this path fails
    // SQLITE_READONLY rather than silently reclassifying the call. Mined promotion is persisted
    // by the write lanes (advance-step sweep, prove sweep, delivery serves).
    func migrationProgress(for account: AccountUUID) async throws -> MigrationProgress? {
        let progressPtr = zcashlc_migration_progress(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        guard let progressPtr else {
            throw ZcashError.rustMigrationProgress(lastErrorMessage(fallback: "`migrationProgress` failed with unknown error"))
        }

        defer { zcashlc_free_migration_progress(progressPtr) }

        return progressPtr.pointee.unsafeToMigrationProgress()
    }

    // DB-READ (audited 2026-08-05): zcashlc_migration_transaction_statuses — opens through the
    // FFI's `open_read` (both connections SQLITE_OPEN_READ_ONLY; no reconcile, no preamble
    // writes), so read-only-ness is machine-enforced: a write anywhere down this path fails
    // SQLITE_READONLY rather than silently reclassifying the call. Mined promotion is persisted
    // by the write lanes (advance-step sweep, prove sweep, delivery serves).
    func migrationTransactionStatuses(for account: AccountUUID) async throws -> [MigrationTransactionStatus] {
        let statusesPtr = zcashlc_migration_transaction_statuses(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        guard let statusesPtr else {
            throw ZcashError.rustMigrationTransactionStatuses(
                lastErrorMessage(fallback: "`migrationTransactionStatuses` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_transaction_statuses(statusesPtr) }

        guard let statuses = statusesPtr.pointee.unsafeToMigrationTransactionStatuses() else {
            throw ZcashError.rustMigrationTransactionStatuses(
                lastErrorMessage(fallback: "`migrationTransactionStatuses` returned malformed data")
            )
        }

        return statuses
    }

    // DB-AUDIT (2026-08-03): SELECT-only in steady state, but routes through the shared
    // open() preamble (CREATE TABLE IF NOT EXISTS + first-call legacy-marks migration can
    // write). Stays serialized.
    @DBActor
    func migrationIsNoteSplitNeeded(for account: AccountUUID) async throws -> Bool {
        // Clear any stale, unconsumed last-error left by an earlier producer before reading this
        // ambiguous-bool sentinel: thread-local `LAST_ERROR` is never cleared on success, only when
        // read via `lastErrorMessage`, so a leftover error here would misfire the check below on
        // this call's own legitimate `false`.
        zcashlc_clear_last_error()

        let needed = zcashlc_migration_is_note_split_needed(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        // `false` overloads "legitimately not needed" and "error" (see `zcashlc_last_error_message`);
        // only a recorded last-error distinguishes the two.
        if !needed, zcashlc_last_error_length() > 0 {
            throw ZcashError.rustMigrationIsNoteSplitNeeded(
                lastErrorMessage(fallback: "`migrationIsNoteSplitNeeded` failed with unknown error")
            )
        }

        return needed
    }

    // DB-READ (audited 2026-08-05): zcashlc_migration_has_overdue_transfers — opens through the
    // FFI's `open_read` (both connections SQLITE_OPEN_READ_ONLY; no reconcile, no preamble
    // writes), so read-only-ness is machine-enforced: a write anywhere down this path fails
    // SQLITE_READONLY rather than silently reclassifying the call. Mined promotion is persisted
    // by the write lanes (advance-step sweep, prove sweep, delivery serves).
    func migrationHasOverdueTransfers(for account: AccountUUID, estimatedTip: BlockHeight?) async throws -> Bool {
        // Clear any stale, unconsumed last-error before this sentinel read (see
        // `migrationIsNoteSplitNeeded` above).
        zcashlc_clear_last_error()

        let hasOverdue = zcashlc_migration_has_overdue_transfers(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            // `-1` disables the estimate on the rust side.
            estimatedTip.map(Int64.init) ?? -1
        )

        // `false` overloads "legitimately none overdue" and "error"; check last-error to disambiguate.
        if !hasOverdue, zcashlc_last_error_length() > 0 {
            throw ZcashError.rustMigrationHasOverdueTransfers(
                lastErrorMessage(fallback: "`migrationHasOverdueTransfers` failed with unknown error")
            )
        }

        return hasOverdue
    }

    // DB-READ (audited 2026-08-05): zcashlc_migration_has_invalid_transfers — opens through the
    // FFI's `open_read` (both connections SQLITE_OPEN_READ_ONLY; no reconcile, no preamble
    // writes), so read-only-ness is machine-enforced: a write anywhere down this path fails
    // SQLITE_READONLY rather than silently reclassifying the call. Mined promotion is persisted
    // by the write lanes (advance-step sweep, prove sweep, delivery serves).
    func migrationHasInvalidTransfers(for account: AccountUUID) async throws -> Bool {
        // Clear any stale, unconsumed last-error before this sentinel read (see
        // `migrationIsNoteSplitNeeded` above).
        zcashlc_clear_last_error()

        let hasInvalid = zcashlc_migration_has_invalid_transfers(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        // `false` overloads "legitimately none invalid" and "error"; check last-error to disambiguate.
        if !hasInvalid, zcashlc_last_error_length() > 0 {
            throw ZcashError.rustMigrationHasInvalidTransfers(
                lastErrorMessage(fallback: "`migrationHasInvalidTransfers` failed with unknown error")
            )
        }

        return hasInvalid
    }

    @DBActor
    func migrationPrepareNoteSplit(for account: AccountUUID) async throws -> NoteSplitProposal {
        let proposalPtr = zcashlc_migration_prepare_note_split(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        guard let proposalPtr else {
            throw ZcashError.rustMigrationPrepareNoteSplit(
                lastErrorMessage(fallback: "`migrationPrepareNoteSplit` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_note_split_proposal(proposalPtr) }

        return proposalPtr.pointee.toNoteSplitProposal()
    }

    /// Routes the rust layer's stable error prefixes to their dedicated `ZcashError` cases:
    /// `MIGRATION_PLAN_STALE` -> `.migrationPlanStale` (re-propose),
    /// `MIGRATION_PROVING_UNAVAILABLE` -> `.migrationProvingUnavailable` (proving failed hard),
    /// and `MIGRATION_WAKEUP_INFEASIBLE:<id>` -> `.migrationWakeupInfeasible(id)` (an
    /// inconsistent stored schedule; the id names the offending transfer). Anything else —
    /// including a `MIGRATION_WAKEUP_INFEASIBLE` whose id does not parse — falls back to the
    /// member's own case.
    ///
    /// Internal (not `private`) so the parse/degrade branches are pinned by unit tests directly —
    /// driving each prefix through a real FFI failure is not reachable from an offline test.
    nonisolated func migrationRoutedError(_ message: String, fallback: (String) -> ZcashError) -> ZcashError {
        if message.hasPrefix("MIGRATION_PLAN_STALE") {
            return .migrationPlanStale
        }
        if message.hasPrefix("MIGRATION_PROVING_UNAVAILABLE") {
            return .migrationProvingUnavailable(message)
        }
        if message.hasPrefix("MIGRATION_WAKEUP_INFEASIBLE:") {
            // The rust side emits exactly `MIGRATION_WAKEUP_INFEASIBLE:<id>`; an unparseable id
            // (a contract drift) degrades to the generic fallback rather than fabricating one.
            let rawId = message.dropFirst("MIGRATION_WAKEUP_INFEASIBLE:".count)
            if let transferId = UInt32(rawId) {
                return .migrationWakeupInfeasible(transferId)
            }
        }
        return fallback(message)
    }

    @DBActor
    func migrationSignNoteSplit(
        proposal: NoteSplitProposal,
        usk: UnifiedSpendingKey,
        for account: AccountUUID
    ) async throws -> PreparedMigrationTransfer {
        let preparedPtr = zcashlc_migration_sign_note_split(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            proposal.proposalHandle,
            usk.bytes,
            UInt(usk.bytes.count)
        )

        guard let preparedPtr else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationSignNoteSplit` failed with unknown error"),
                fallback: ZcashError.rustMigrationSignNoteSplit
            )
        }

        defer { zcashlc_free_migration_prepared_transfer(preparedPtr) }

        guard let prepared = preparedPtr.pointee.unsafeToPreparedMigrationTransfer() else {
            throw ZcashError.rustMigrationSignNoteSplit(
                lastErrorMessage(fallback: "`migrationSignNoteSplit` returned a malformed prepared transfer")
            )
        }

        return prepared
    }

    // DB-AUDIT (2026-08-03): SELECT-only in steady state, but routes through the shared
    // open() preamble (CREATE TABLE IF NOT EXISTS + first-call legacy-marks migration can
    // write). Stays serialized.
    @DBActor
    func migrationResidualAfterMigration(for account: AccountUUID) async throws -> Zatoshi? {
        // Clear any stale, unconsumed last-error before this sentinel read (see
        // `migrationIsNoteSplitNeeded` above).
        zcashlc_clear_last_error()

        let residual = zcashlc_migration_residual_after_migration(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        // `-1` overloads "legitimately no residual" and "error"; check last-error to disambiguate.
        if residual < 0 {
            if zcashlc_last_error_length() > 0 {
                throw ZcashError.rustMigrationResidualAfterMigration(
                    lastErrorMessage(fallback: "`migrationResidualAfterMigration` failed with unknown error")
                )
            }

            return nil
        }

        return Zatoshi(residual)
    }

    @DBActor
    func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi {
        let locked = zcashlc_migration_lock_residual(
            dbData.0,
            dbData.1,
            accountUUID.id,
            networkType.networkId
        )

        // Unlike the ambiguous sentinels above, `-1` here means only "error": `0` is the
        // legitimate "nothing was spendable" answer, so no last-error disambiguation is needed.
        guard locked >= 0 else {
            throw ZcashError.rustMigrationLockResidual(
                lastErrorMessage(fallback: "`lockMigrationResidual` failed with unknown error")
            )
        }

        return Zatoshi(locked)
    }

    @DBActor
    func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int {
        let unlocked = zcashlc_migration_unlock_residual(
            dbData.0,
            dbData.1,
            accountUUID.id,
            networkType.networkId
        )

        // `-1` means only "error" (`0` is the legitimate "nothing was locked" answer).
        guard unlocked >= 0 else {
            throw ZcashError.rustMigrationUnlockResidual(
                lastErrorMessage(fallback: "`unlockMigrationResidual` failed with unknown error")
            )
        }

        return Int(unlocked)
    }

    // DB-AUDIT (2026-08-03): SELECT-only in steady state, but routes through the shared
    // open() preamble (CREATE TABLE IF NOT EXISTS + first-call legacy-marks migration can
    // write). Stays serialized.
    @DBActor
    func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate {
        let estimatePtr = zcashlc_migration_estimate_runs(
            dbData.0,
            dbData.1,
            accountUUID.id,
            networkType.networkId
        )

        guard let estimatePtr else {
            throw ZcashError.rustMigrationEstimateRuns(
                lastErrorMessage(fallback: "`estimateMigrationRuns` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_run_estimate(estimatePtr) }

        return estimatePtr.pointee.toMigrationRunEstimate()
    }

    @DBActor
    func migrationProposeTransfers(for account: AccountUUID) async throws -> MigrationSchedule {
        let schedulePtr = zcashlc_migration_propose_transfers(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        guard let schedulePtr else {
            throw ZcashError.rustMigrationProposeTransfers(
                lastErrorMessage(fallback: "`migrationProposeTransfers` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_schedule(schedulePtr) }

        guard let schedule = schedulePtr.pointee.unsafeToMigrationSchedule() else {
            throw ZcashError.rustMigrationProposeTransfers(
                lastErrorMessage(fallback: "`migrationProposeTransfers` returned a malformed schedule")
            )
        }

        return schedule
    }

    // DB-READ (audited 2026-08-03): propose_send_max_transfer with lock_inputs = None — write
    // branch statically gated off; selection over a shared read-only reference.
    func proposeSendMaxTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        memo: MemoBytes?,
        orchardOnly: Bool
    ) async throws -> FfiProposal {
        let proposal = zcashlc_propose_send_max_transfer(
            dbData.0,
            dbData.1,
            networkType.networkId,
            accountUUID.id,
            [CChar](recipient.utf8CString),
            memo?.bytes,
            MaxSpendable,
            confirmationsPolicy.toBackend(),
            orchardOnly
        )

        guard let proposal else {
            throw ZcashError.rustProposeSendMaxTransfer(lastErrorMessage(fallback: "`proposeSendMaxTransfer` failed with unknown error"))
        }

        defer { zcashlc_free_boxed_slice(proposal) }

        return try FfiProposal(serializedBytes: Data(
            bytes: proposal.pointee.ptr,
            count: Int(proposal.pointee.len)
        ))
    }

    @DBActor
    func migrationSignAndStoreSchedule(
        _ schedule: MigrationSchedule,
        usk: UnifiedSpendingKey,
        for account: AccountUUID
    ) async throws {
        let success = zcashlc_migration_sign_and_store_schedule(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            schedule.proposalHandle,
            usk.bytes,
            UInt(usk.bytes.count)
        )

        guard success else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationSignAndStoreSchedule` failed with unknown error"),
                fallback: ZcashError.rustMigrationSignAndStoreSchedule
            )
        }
    }

    @DBActor
    func migrationProveTransactions(
        ids: [UInt32],
        maxProofs: Int,
        for account: AccountUUID
    ) async throws -> MigrationProveOutcome {
        guard !ids.isEmpty, maxProofs > 0 else {
            return MigrationProveOutcome(totalProved: 0, preparationTxids: [])
        }

        // The batch is CHUNKED: one proof per FFI call, with a suspension between calls. Each
        // proof is seconds of CPU. Since the read/write split, every read-only call runs OFF
        // `DBActor`, so readers never queue here at all — the actor now serializes only
        // Swift-initiated WRITES, and holding it through each chunk is the point: no other
        // Swift write can interleave with a proof's bookkeeping. The `Task.yield()` between
        // chunks releases the actor briefly so queued WRITERS (broadcast bookkeeping, a user
        // send) wait at most one proof, not the whole sweep. See `DBActor.swift` for the
        // contract this method now relies on.
        //
        // Every chunk re-passes the WHOLE instruction rather than a remaining slice, and does NOT
        // re-advance between chunks: the rust executor skips a row that is no longer awaiting its
        // proof, so the rows earlier chunks already proved cost nothing to re-name, and the cap of
        // 1 lands on the first row still outstanding. The loop ends when a chunk proves nothing —
        // either the batch is exhausted or the remainder is transiently unprovable — or when the
        // caller's `maxProofs` budget is spent. Because each chunk is capped at 1 and a skip never
        // counts against the rust cap, the budget is honoured EXACTLY: this returns at most
        // `maxProofs`, all of them real proofs.
        //
        // The chunks' PREPARATION TXIDS accumulate across the whole pass, in prove order, so the
        // caller sees one handoff list for the pass rather than one per chunk.
        var totalProved = 0
        var preparationTxids: [Data] = []
        while totalProved < maxProofs {
            // The last-error is cleared first so the message read on failure cannot be a
            // leftover from an earlier call on this thread.
            zcashlc_clear_last_error()

            let outcomePtr = ids.withUnsafeBufferPointer { buffer in
                zcashlc_migration_prove_transactions(
                    dbData.0,
                    dbData.1,
                    account.id,
                    networkType.networkId,
                    buffer.baseAddress,
                    UInt(buffer.count),
                    1
                )
            }

            guard let outcomePtr else {
                throw migrationRoutedError(
                    lastErrorMessage(fallback: "`migrationProveTransactions` failed with unknown error"),
                    fallback: ZcashError.rustMigrationProveTransactions
                )
            }

            let chunk = outcomePtr.pointee.unsafeToMigrationProveOutcome()
            zcashlc_free_migration_prove_outcome(outcomePtr)

            guard chunk.totalProved > 0 else {
                return MigrationProveOutcome(totalProved: totalProved, preparationTxids: preparationTxids)
            }
            totalProved += chunk.totalProved
            preparationTxids.append(contentsOf: chunk.preparationTxids)

            // Let queued `DBActor` writers run before the next proof.
            await Task.yield()
        }

        // The budget is spent, with the batch possibly still holding provable rows: the caller
        // advances again and re-passes whatever the next crank offers.
        return MigrationProveOutcome(totalProved: totalProved, preparationTxids: preparationTxids)
    }

    // DB-AUDIT (2026-08-07): WRITE — the accessor IS the store's atomic broadcast seam: it records
    // the transaction in the wallet's own tables in the same database transaction that hands the
    // bytes back. Stays serialized.
    @DBActor
    func migrationTakePreparation(txid: Data, for account: AccountUUID) async throws -> PreparedMigrationTransfer {
        guard txid.count == TxId.byteLength else {
            throw ZcashError.rustMigrationTakePreparation(
                "`migrationTakePreparation` was given a \(txid.count)-byte txid; it must be \(TxId.byteLength) bytes"
            )
        }

        let preparedPtr: UnsafeMutablePointer<FfiPreparedTransfer>? = txid.withUnsafeBytes { buffer in
            guard let bufferPtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }

            return zcashlc_migration_take_preparation_by_txid(
                dbData.0,
                dbData.1,
                account.id,
                networkType.networkId,
                bufferPtr
            )
        }

        guard let preparedPtr else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationTakePreparation` failed with unknown error"),
                fallback: ZcashError.rustMigrationTakePreparation
            )
        }

        defer { zcashlc_free_migration_prepared_transfer(preparedPtr) }

        guard let prepared = preparedPtr.pointee.unsafeToPreparedMigrationTransfer() else {
            throw ZcashError.rustMigrationTakePreparation(
                lastErrorMessage(fallback: "`migrationTakePreparation` returned a malformed transaction")
            )
        }

        return prepared
    }

    // DB-AUDIT (2026-08-03): WRITE — the broadcast seam records the transaction in the wallet's
    // own tables in the same database transaction that hands the bytes back. Stays serialized.
    @DBActor
    func migrationTakeBroadcastTransaction(id: UInt32, for account: AccountUUID) async throws -> PreparedMigrationTransfer {
        let preparedPtr = zcashlc_migration_take_broadcast_transaction(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            id
        )

        guard let preparedPtr else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationTakeBroadcastTransaction` failed with unknown error"),
                fallback: ZcashError.rustMigrationTakeBroadcastTransaction
            )
        }

        defer { zcashlc_free_migration_prepared_transfer(preparedPtr) }

        guard let prepared = preparedPtr.pointee.unsafeToPreparedMigrationTransfer() else {
            throw ZcashError.rustMigrationTakeBroadcastTransaction(
                lastErrorMessage(fallback: "`migrationTakeBroadcastTransaction` returned a malformed transaction")
            )
        }

        return prepared
    }

    @DBActor
    func migrationRecordTransferResult(
        transferId: UInt32,
        result: MigrationTransferResult,
        for account: AccountUUID
    ) async throws {
        let resultTag: Int32
        var txidBytes: [UInt8]?

        switch result {
        case .success(let txId):
            // `txId` is the display-form hex string (see `MigrationTransferResult.success`); the
            // FFI wants the raw 32-byte internal-order id, so round-trip it through `TxId`, which
            // both validates the length and undoes the display byte-reversal.
            guard let parsedTxId = try? TxId(txId), parsedTxId.id.count == TxId.byteLength else {
                throw ZcashError.migrationInvalidTxId(txId)
            }

            resultTag = 0
            txidBytes = parsedTxId.id
        case .networkError:
            // `retryable` is a Swift-level signal for the caller's own retry policy; the rust
            // layer's behavior for a network error never depended on it (tag 1 alone drives it).
            resultTag = 1
        case .invalidNote:
            resultTag = 2
        case .expired:
            resultTag = 3
        }

        let success = zcashlc_migration_record_transfer_result(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            transferId,
            resultTag,
            txidBytes
        )

        guard success else {
            throw ZcashError.rustMigrationRecordTransferResult(
                lastErrorMessage(fallback: "`migrationRecordTransferResult` failed with unknown error")
            )
        }
    }

    @DBActor
    func migrationRecordImmediateRun(txid: Data, for account: AccountUUID) async throws {
        guard txid.count == TxId.byteLength else {
            throw ZcashError.migrationRecordImmediateRunInvalidTxId(txid.count)
        }

        let success = txid.withUnsafeBytes { buffer -> Bool in
            guard let bufferPtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return false
            }

            return zcashlc_migration_record_immediate_run(
                dbData.0,
                dbData.1,
                account.id,
                networkType.networkId,
                bufferPtr
            )
        }

        guard success else {
            throw ZcashError.rustMigrationRecordImmediateRun(
                lastErrorMessage(fallback: "`migrationRecordImmediateRun` failed with unknown error")
            )
        }
    }

    @DBActor
    func migrationRestartStep(for account: AccountUUID) async throws -> MigrationSchedule {
        let schedulePtr = zcashlc_migration_restart_step(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId
        )

        guard let schedulePtr else {
            throw ZcashError.rustMigrationRestartStep(lastErrorMessage(fallback: "`migrationRestartStep` failed with unknown error"))
        }

        defer { zcashlc_free_migration_schedule(schedulePtr) }

        guard let schedule = schedulePtr.pointee.unsafeToMigrationSchedule() else {
            throw ZcashError.rustMigrationRestartStep(lastErrorMessage(fallback: "`migrationRestartStep` returned a malformed schedule"))
        }

        return schedule
    }

    @DBActor
    func migrationRefreshStaleTransfers(
        usk: UnifiedSpendingKey?,
        for account: AccountUUID
    ) async throws -> MigrationSchedule {
        // A `nil` spending key is the external-signer lane: NULL/0 selects the unsigned rebuild
        // (the rebuilt transfer awaits its signature for the PCZT ceremony to complete).
        let schedulePtr: UnsafeMutablePointer<FfiMigrationSchedule>?
        if let usk {
            schedulePtr = zcashlc_migration_refresh_stale_transfers(
                dbData.0,
                dbData.1,
                account.id,
                networkType.networkId,
                usk.bytes,
                UInt(usk.bytes.count)
            )
        } else {
            schedulePtr = zcashlc_migration_refresh_stale_transfers(
                dbData.0,
                dbData.1,
                account.id,
                networkType.networkId,
                nil,
                0
            )
        }

        // NULL is an unambiguous error sentinel here: every legitimate outcome — nothing stored,
        // a terminal run, nothing expired, or a completed rebuild — returns a schedule (possibly
        // empty), mirroring `migrationRestartStep`.
        guard let schedulePtr else {
            throw ZcashError.rustMigrationRefreshStaleTransfers(
                lastErrorMessage(fallback: "`migrationRefreshStaleTransfers` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_schedule(schedulePtr) }

        guard let schedule = schedulePtr.pointee.unsafeToMigrationSchedule() else {
            throw ZcashError.rustMigrationRefreshStaleTransfers(
                lastErrorMessage(fallback: "`migrationRefreshStaleTransfers` returned a malformed schedule")
            )
        }

        return schedule
    }

    @DBActor
    func migrationCreateUnsignedNoteSplitPczts(
        for schedule: MigrationSchedule,
        for account: AccountUUID
    ) async throws -> [MigrationUnsignedTransferPczt] {
        let pcztsPtr = zcashlc_migration_create_unsigned_note_split_pczts(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            schedule.proposalHandle
        )

        guard let pcztsPtr else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationCreateUnsignedNoteSplitPczts` failed with unknown error"),
                fallback: ZcashError.rustMigrationCreateUnsignedNoteSplitPczt
            )
        }

        defer { zcashlc_free_migration_unsigned_transfer_pczts(pcztsPtr) }

        var unsignedPczts: [MigrationUnsignedTransferPczt] = []
        unsignedPczts.reserveCapacity(Int(pcztsPtr.pointee.len))

        for index in 0 ..< Int(pcztsPtr.pointee.len) {
            guard let unsignedPczt = pcztsPtr.pointee.ptr.advanced(by: index).pointee.unsafeToMigrationUnsignedTransferPczt() else {
                throw ZcashError.rustMigrationCreateUnsignedNoteSplitPczt(
                    lastErrorMessage(fallback: "`migrationCreateUnsignedNoteSplitPczts` returned a malformed pczt")
                )
            }

            unsignedPczts.append(unsignedPczt)
        }

        return unsignedPczts
    }

    @DBActor
    func migrationStoreSignedNoteSplitPczts(
        _ signed: [MigrationSignedTransferPczt],
        for account: AccountUUID
    ) async throws -> PreparedMigrationTransfer {
        let ids: [UInt32] = signed.map { $0.id }

        // One owned buffer per pczt (see `migrationStoreSignedSchedulePczts` for the rationale).
        let pcztBuffers: [UnsafeMutablePointer<UInt8>] = signed.map { transfer in
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: transfer.pczt.count)
            transfer.pczt.copyBytes(to: buffer, count: transfer.pczt.count)
            return buffer
        }
        defer { pcztBuffers.forEach { $0.deallocate() } }

        let pcztPointers: [UnsafePointer<UInt8>?] = pcztBuffers.map { UnsafePointer($0) }
        let pcztLens: [UInt] = signed.map { UInt($0.pczt.count) }

        let preparedPtr = ids.withUnsafeBufferPointer { idsPtr in
            pcztPointers.withUnsafeBufferPointer { pcztsPtr in
                pcztLens.withUnsafeBufferPointer { lensPtr in
                    zcashlc_migration_store_signed_note_split_pczts(
                        dbData.0,
                        dbData.1,
                        account.id,
                        networkType.networkId,
                        idsPtr.baseAddress,
                        UInt(idsPtr.count),
                        pcztsPtr.baseAddress,
                        lensPtr.baseAddress
                    )
                }
            }
        }

        guard let preparedPtr else {
            throw ZcashError.rustMigrationStoreSignedNoteSplitPczt(
                lastErrorMessage(fallback: "`migrationStoreSignedNoteSplitPczts` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_prepared_transfer(preparedPtr) }

        guard let prepared = preparedPtr.pointee.unsafeToPreparedMigrationTransfer() else {
            throw ZcashError.rustMigrationStoreSignedNoteSplitPczt(
                lastErrorMessage(fallback: "`migrationStoreSignedNoteSplitPczts` returned a malformed prepared transfer")
            )
        }

        return prepared
    }

    @DBActor
    func migrationCreateUnsignedTransferPczts(
        for schedule: MigrationSchedule,
        for account: AccountUUID
    ) async throws -> [MigrationUnsignedTransferPczt] {
        let pcztsPtr = zcashlc_migration_create_unsigned_transfer_pczts(
            dbData.0,
            dbData.1,
            account.id,
            networkType.networkId,
            schedule.proposalHandle
        )

        guard let pcztsPtr else {
            throw migrationRoutedError(
                lastErrorMessage(fallback: "`migrationCreateUnsignedTransferPczts` failed with unknown error"),
                fallback: ZcashError.rustMigrationCreateUnsignedTransferPczts
            )
        }

        defer { zcashlc_free_migration_unsigned_transfer_pczts(pcztsPtr) }

        var unsignedPczts: [MigrationUnsignedTransferPczt] = []
        unsignedPczts.reserveCapacity(Int(pcztsPtr.pointee.len))

        for index in 0 ..< Int(pcztsPtr.pointee.len) {
            guard let unsignedPczt = pcztsPtr.pointee.ptr.advanced(by: index).pointee.unsafeToMigrationUnsignedTransferPczt() else {
                throw ZcashError.rustMigrationCreateUnsignedTransferPczts(
                    lastErrorMessage(fallback: "`migrationCreateUnsignedTransferPczts` returned a malformed pczt")
                )
            }

            unsignedPczts.append(unsignedPczt)
        }

        return unsignedPczts
    }

    @DBActor
    func migrationStoreSignedSchedulePczts(_ signed: [MigrationSignedTransferPczt], for account: AccountUUID) async throws {
        let ids: [UInt32] = signed.map { $0.id }

        // One owned buffer per pczt, each populated with a single `copyBytes` call. The FFI call
        // needs every pczt's bytes alive as an independent buffer simultaneously (parallel
        // `pczts`/`pczt_lens` arrays), so unlike the single-pczt calls above this cannot be scoped to
        // one `withUnsafeBytes`; `copyBytes(to:count:)` still keeps it to exactly one copy per pczt,
        // instead of the previous `.bytes` + `ContiguousArray` + manual `initialize(from:count:)` chain.
        let pcztBuffers: [UnsafeMutablePointer<UInt8>] = signed.map { transfer in
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: transfer.pczt.count)
            transfer.pczt.copyBytes(to: buffer, count: transfer.pczt.count)
            return buffer
        }
        defer { pcztBuffers.forEach { $0.deallocate() } }

        let pcztPointers: [UnsafePointer<UInt8>?] = pcztBuffers.map { UnsafePointer($0) }
        let pcztLens: [UInt] = signed.map { UInt($0.pczt.count) }

        let success = ids.withUnsafeBufferPointer { idsPtr in
            pcztPointers.withUnsafeBufferPointer { pcztsPtr in
                pcztLens.withUnsafeBufferPointer { lensPtr in
                    zcashlc_migration_store_signed_schedule_pczts(
                        dbData.0,
                        dbData.1,
                        account.id,
                        networkType.networkId,
                        idsPtr.baseAddress,
                        UInt(idsPtr.count),
                        pcztsPtr.baseAddress,
                        lensPtr.baseAddress
                    )
                }
            }
        }

        guard success else {
            throw ZcashError.rustMigrationStoreSignedSchedulePczts(
                lastErrorMessage(fallback: "`migrationStoreSignedSchedulePczts` failed with unknown error")
            )
        }
    }

    // DB-free: pure PCZT/UR operations over caller-held bytes, so unlike every migration method
    // above these are not `@DBActor` (mirrors `redactPCZTForSigner`/`PCZTRequiresSaplingProofs`).
    func migrationKeystoneBuildSignBatchQrParts(
        requestId: Data,
        pczts: [MigrationUnsignedTransferPczt],
        maxFragmentLen: Int
    ) async throws -> [String] {
        // One owned buffer per pczt (see `migrationStoreSignedSchedulePczts` for the rationale).
        let pcztBuffers: [UnsafeMutablePointer<UInt8>] = pczts.map { unsigned in
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: unsigned.pczt.count)
            unsigned.pczt.copyBytes(to: buffer, count: unsigned.pczt.count)
            return buffer
        }
        defer { pcztBuffers.forEach { $0.deallocate() } }

        let pcztPointers: [UnsafePointer<UInt8>?] = pcztBuffers.map { UnsafePointer($0) }
        let pcztLens: [UInt] = pczts.map { UInt($0.pczt.count) }
        let requestIdBytes = requestId.bytes

        let qrPartsPtr = pcztPointers.withUnsafeBufferPointer { pcztsPtr in
            pcztLens.withUnsafeBufferPointer { lensPtr in
                zcashlc_migration_keystone_build_sign_batch_qr_parts(
                    requestIdBytes,
                    UInt(requestIdBytes.count),
                    pcztsPtr.baseAddress,
                    lensPtr.baseAddress,
                    UInt(pcztsPtr.count),
                    UInt(maxFragmentLen)
                )
            }
        }

        guard let qrPartsPtr else {
            throw ZcashError.rustMigrationKeystoneBuildSignBatchQrParts(
                lastErrorMessage(fallback: "`migrationKeystoneBuildSignBatchQrParts` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_keystone_qr_parts(qrPartsPtr) }

        var parts: [String] = []
        parts.reserveCapacity(Int(qrPartsPtr.pointee.len))

        for index in 0 ..< Int(qrPartsPtr.pointee.len) {
            guard
                let partCString = qrPartsPtr.pointee.ptr.advanced(by: index).pointee,
                let part = String(validatingUTF8: partCString)
            else {
                throw ZcashError.rustMigrationKeystoneBuildSignBatchQrParts(
                    lastErrorMessage(fallback: "`migrationKeystoneBuildSignBatchQrParts` returned a malformed QR part")
                )
            }

            parts.append(part)
        }

        return parts
    }

    func migrationKeystoneResetSignBatchDecoder() async {
        zcashlc_migration_keystone_reset_sign_batch_decoder()
    }

    func migrationKeystoneDecodeSignBatchPart(
        _ part: String,
        expectedRequestId: Data
    ) async throws -> KeystoneBatchDecodeResult {
        let expectedRequestIdBytes = expectedRequestId.bytes

        let resultPtr = zcashlc_migration_keystone_decode_sign_batch_part(
            [CChar](part.utf8CString),
            expectedRequestIdBytes,
            UInt(expectedRequestIdBytes.count)
        )

        guard let resultPtr else {
            throw ZcashError.rustMigrationKeystoneDecodeSignBatchPart(
                lastErrorMessage(fallback: "`migrationKeystoneDecodeSignBatchPart` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_keystone_batch_decode_result(resultPtr) }

        return resultPtr.pointee.toKeystoneBatchDecodeResult()
    }

    func migrationKeystoneApplyBatchSignatures(
        pczts: [MigrationUnsignedTransferPczt],
        batchSignResponse: Data
    ) async throws -> [MigrationSignedTransferPczt] {
        let ids: [UInt32] = pczts.map { $0.id }

        // One owned buffer per pczt (see `migrationStoreSignedSchedulePczts` for the rationale).
        let pcztBuffers: [UnsafeMutablePointer<UInt8>] = pczts.map { unsigned in
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: unsigned.pczt.count)
            unsigned.pczt.copyBytes(to: buffer, count: unsigned.pczt.count)
            return buffer
        }
        defer { pcztBuffers.forEach { $0.deallocate() } }

        let pcztPointers: [UnsafePointer<UInt8>?] = pcztBuffers.map { UnsafePointer($0) }
        let pcztLens: [UInt] = pczts.map { UInt($0.pczt.count) }
        let responseBytes = batchSignResponse.bytes

        let signedPtr = ids.withUnsafeBufferPointer { idsPtr in
            pcztPointers.withUnsafeBufferPointer { pcztsPtr in
                pcztLens.withUnsafeBufferPointer { lensPtr in
                    zcashlc_migration_keystone_apply_batch_signatures(
                        idsPtr.baseAddress,
                        UInt(idsPtr.count),
                        pcztsPtr.baseAddress,
                        lensPtr.baseAddress,
                        responseBytes,
                        UInt(responseBytes.count)
                    )
                }
            }
        }

        guard let signedPtr else {
            throw ZcashError.rustMigrationKeystoneApplyBatchSignatures(
                lastErrorMessage(fallback: "`migrationKeystoneApplyBatchSignatures` failed with unknown error")
            )
        }

        defer { zcashlc_free_migration_unsigned_transfer_pczts(signedPtr) }

        var signedPczts: [MigrationSignedTransferPczt] = []
        signedPczts.reserveCapacity(Int(signedPtr.pointee.len))

        for index in 0 ..< Int(signedPtr.pointee.len) {
            guard let signedPczt = signedPtr.pointee.ptr.advanced(by: index).pointee.unsafeToMigrationSignedTransferPczt() else {
                throw ZcashError.rustMigrationKeystoneApplyBatchSignatures(
                    lastErrorMessage(fallback: "`migrationKeystoneApplyBatchSignatures` returned a malformed pczt")
                )
            }

            signedPczts.append(signedPczt)
        }

        return signedPczts
    }

    /// The NU6.3 (Ironwood) activation height for `networkType`, or `nil` when NU6.3 is unset for
    /// that network. Stateless (no db access).
    ///
    /// - Note: The underlying FFI also returns `-1` (indistinguishable from "unset") for a network
    ///   id outside `{testnet, mainnet}` (e.g. `.regtest`), and sets `zcashlc_last_error_message`
    ///   in that case. Unlike the instance methods above, this wrapper does not disambiguate the
    ///   two and always maps `-1` to `nil` — callers are expected to pass `.testnet`/`.mainnet`. It
    ///   does, however, consume/clear that last-error before returning: thread-local `LAST_ERROR` is
    ///   never cleared on its own, so leaving it set here would let it misfire an unrelated,
    ///   legitimately-`false`/`-1` sentinel read made later on the same thread.
    static func ironwoodActivationHeight(networkType: NetworkType) -> BlockHeight? {
        let height = zcashlc_ironwood_activation_height(networkType.networkId)

        guard height >= 0 else {
            // Consume/clear whatever last-error this call may have set (e.g. an unsupported network
            // id) so it cannot leak into a later, unrelated sentinel read on this thread.
            zcashlc_clear_last_error()
            return nil
        }

        return BlockHeight(height)
    }
}

private extension ZcashRustBackend {
    static func initializeRust(logLevel: RustLogging) {
        logLevel.rawValue.utf8CString.withUnsafeBufferPointer { levelPtr in
            zcashlc_init_on_load(levelPtr.baseAddress)
        }
    }
}

nonisolated func lastErrorMessage(fallback: String) -> String {
    let errorLen = zcashlc_last_error_length()
    defer { zcashlc_clear_last_error() }

    if errorLen > 0 {
        let error = UnsafeMutablePointer<Int8>.allocate(capacity: Int(errorLen))
        defer { error.deallocate() }

        zcashlc_error_message_utf8(error, errorLen)
        if let errorMessage = String(validatingUTF8: error) {
            return errorMessage
        } else {
            return fallback
        }
    } else {
        return fallback
    }
}

extension URL {
    func osStr() -> (String, UInt) {
        let path = self.absoluteString
        return (path, UInt(path.lengthOfBytes(using: .utf8)))
    }

    /// use when the rust ffi needs to make filesystem operations
    func osPathStr() -> (String, UInt) {
        let path = self.path
        return (path, UInt(path.lengthOfBytes(using: .utf8)))
    }
}

extension String {
    /**
    Checks whether this string contains null bytes before it's real ending
    */
    func containsCStringNullBytesBeforeStringEnding() -> Bool {
        self.utf8CString.firstIndex(of: 0) != (self.utf8CString.count - 1)
    }

    func isDbNotEmptyErrorMessage() -> Bool {
        return contains("is not empty")
    }
}

extension FfiAddress {
    /// converts an [`FfiAddress`] into a [`UnifiedAddress`]
    /// - Note: This does not check that the converted value actually holds a valid UnifiedAddress
    func unsafeToUnifiedAddress(_ networkType: NetworkType) -> UnifiedAddress {
        .init(validatedEncoding: String(cString: address), networkType: networkType)
    }
}

extension FfiAccount {
    var uuidArray: [UInt8] {
        withUnsafeBytes(of: uuid_bytes) { buf in
            [UInt8](buf)
        }
    }

    var seedFingerprintArray: [UInt8] {
        withUnsafeBytes(of: seed_fingerprint) { buf in
            [UInt8](buf)
        }
    }

    /// converts an [`FfiAccount`] into a [`Account`]
    /// - Note: This does not check that the converted value actually holds a valid Account
    func unsafeToAccount() -> Account? {
        // Invalid UUID check
        guard uuidArray != [UInt8](repeating: 0, count: 16) else {
            return nil
        }

        // Invalid ZIP 32 account index
        if hd_account_index == UInt32.max {
            return .init(
                id: AccountUUID(id: uuidArray),
                name: account_name != nil ? String(cString: account_name) : nil,
                keySource: key_source != nil ? String(cString: key_source) : nil,
                seedFingerprint: nil,
                hdAccountIndex: nil,
                ufvk: nil,
                uivk: nil
            )
        }

        let ufvkTyped = ufvk.map { UnifiedFullViewingKey(validatedEncoding: String(cString: $0)) }
        let uivkTyped = uivk.map { UnifiedIncomingViewingKey(validatedEncoding: String(cString: $0)) }

        // Valid ZIP32 account index
        return .init(
            id: AccountUUID(id: uuidArray),
            name: account_name != nil ? String(cString: account_name) : nil,
            keySource: key_source != nil ? String(cString: key_source) : nil,
            seedFingerprint: seedFingerprintArray,
            hdAccountIndex: Zip32AccountIndex(hd_account_index),
            ufvk: ufvkTyped,
            uivk: uivkTyped
        )
    }
}

extension FfiBoxedSlice {
    /// converts an [`FfiBoxedSlice`] into a [`UnifiedSpendingKey`]
    /// - Note: This does not check that the converted value actually holds a valid USK
    func unsafeToUnifiedSpendingKey(network: NetworkType) -> UnifiedSpendingKey {
        .init(
            network: network,
            bytes: self.ptr.toByteArray(length: Int(self.len))
        )
    }
}

extension FfiTransactionData {
    /// Copies rust-owned wallet transaction data into Swift, or returns `nil` when raw bytes are unavailable.
    func unsafeToTransactionData() -> TransactionData? {
        guard let raw, raw_len > 0, let rawCount = Int(exactly: raw_len) else { return nil }

        return TransactionData(
            txId: Data(FfiTxId(tuple: txid).array),
            raw: Data(bytes: raw, count: rawCount),
            expiryHeight: expiry_height == 0 ? nil : BlockHeight(expiry_height)
        )
    }
}

extension FfiUuid {
    var uuidArray: [UInt8] {
        withUnsafeBytes(of: self.uuid_bytes) { buf in
            [UInt8](buf)
        }
    }

    /// converts an [`FfiUuid`] into a [`AccountUUID`]
    func unsafeToAccountUUID() -> AccountUUID {
        .init(
            id: self.uuidArray
        )
    }
}

extension FFIBinaryKey {
    var uuidArray: [UInt8] {
        withUnsafeBytes(of: self.account_uuid) { buf in
            [UInt8](buf)
        }
    }

    /// converts an [`FFIBinaryKey`] into a [`UnifiedSpendingKey`]
    /// - Note: This does not check that the converted value actually holds a valid USK
    func unsafeToUnifiedSpendingKey(network: NetworkType) -> UnifiedSpendingKey {
        .init(
            network: network,
            bytes: self.encoding.toByteArray(
                length: Int(self.encoding_len)
            )
        )
    }
}

extension UnsafeMutablePointer where Pointee == UInt8 {
    /// copies the bytes pointed on
    func toByteArray(length: Int) -> [UInt8] {
        var bytes: [UInt8] = []

        for index in 0 ..< length {
            bytes.append(self.advanced(by: index).pointee)
        }

        return bytes
    }
}

extension Array where Element == FFIBlockMeta {
    func deallocateElements() {
        self.forEach { element in
            element.block_hash_ptr.deallocate()
        }
    }
}

extension Array where Element == FfiSubtreeRoot {
    func deallocateElements() {
        self.forEach { element in
            element.root_hash_ptr.deallocate()
        }
    }
}

extension FfiBalance {
    /// Converts an [`FfiBalance`] into a [`PoolBalance`].
    func toPoolBalance() -> PoolBalance {
        PoolBalance(
            spendableValue: Zatoshi(self.spendable_value),
            changePendingConfirmation: Zatoshi(self.change_pending_confirmation),
            valuePendingSpendability: Zatoshi(self.value_pending_spendability),
            lockedValue: Zatoshi(self.locked_value)
        )
    }
}

extension FfiAccountBalance {
    var uuidArray: [UInt8] {
        withUnsafeBytes(of: self.account_uuid) { buf in
            [UInt8](buf)
        }
    }

    /// Converts an [`FfiAccountBalance`] into a [`AccountBalance`].
    func toAccountBalance() -> AccountBalance {
        .init(
            saplingBalance: self.sapling_balance.toPoolBalance(),
            orchardBalance: self.orchard_balance.toPoolBalance(),
            ironwoodBalance: self.ironwood_balance.toPoolBalance(),
            unshielded: Zatoshi(self.unshielded)
        )
    }
}

extension FfiScanProgress {
    /// Converts an [`FfiScanProgress`] into a [`ScanProgress`].
    func toScanProgress() -> ScanProgress {
        .init(
            numerator: min(self.numerator, self.denominator),
            denominator: self.denominator
        )
    }
}

extension FfiMigrationProgress {
    /// Converts an [`FfiMigrationProgress`] into a [`MigrationProgress`], or `nil` when
    /// `is_present` is `false` (no migration currently in progress).
    func unsafeToMigrationProgress() -> MigrationProgress? {
        guard is_present else { return nil }

        return MigrationProgress(
            completedTransfers: Int(completed_transfers),
            totalTransfers: Int(total_transfers),
            remainingOrchard: Zatoshi(remaining_orchard_value),
            nextTransferReadyAtHeight: next_transfer_ready_at_height >= 0 ? BlockHeight(next_transfer_ready_at_height) : nil,
            isImmediate: is_immediate
        )
    }
}

extension FfiMigrationTransactionStatus {
    /// Converts an [`FfiMigrationTransactionStatus`] into a [`MigrationTransactionStatus`], or
    /// `nil` for an out-of-range discriminant or an invariant the engine's own contract rules out
    /// (should not happen; defensive only) -- see `zcashlc_migration_transaction_statuses`'s doc
    /// for the field-by-field contract this mirrors.
    func unsafeToMigrationTransactionStatus() -> MigrationTransactionStatus? {
        let kind: MigrationTransactionStatus.Kind
        if is_transfer {
            guard crossing >= 0 else { return nil }
            kind = .transfer(crossing: Int(crossing))
        } else {
            guard prep_layer >= 0, prep_index >= 0 else { return nil }
            kind = .preparation(layer: Int(prep_layer), index: Int(prep_index))
        }

        let decodedState: MigrationTransactionStatus.State
        switch state {
        case 0:
            decodedState = .awaitingSignature
        case 1:
            decodedState = .signed
        case 2:
            decodedState = .proved
        case 3:
            guard has_txid else { return nil }
            decodedState = .broadcast(txid: Data(FfiTxId(tuple: txid).array))
        case 4:
            guard mined_height >= 0 else { return nil }
            decodedState = .mined(height: BlockHeight(mined_height))
        case 5:
            // The Invalid state carries its reason the way Mined carries its height: a row
            // claiming invalidity without one is malformed.
            switch invalid_reason {
            case 0:
                decodedState = .invalid(reason: .fundingSpent)
            case 1:
                decodedState = .invalid(reason: .rejectedInvalid)
            case 2:
                decodedState = .invalid(reason: .rejectedExpired)
            default:
                return nil
            }
        default:
            return nil
        }

        let decodedNextAction: MigrationTransactionStatus.NextAction?
        switch action {
        case 0:
            decodedNextAction = nil
        case 1:
            decodedNextAction = .prove
        case 2:
            decodedNextAction = .broadcast
        default:
            return nil
        }

        let decodedBlockedOn: MigrationTransactionStatus.Blocker?
        switch blocked_on {
        case 0:
            decodedBlockedOn = nil
        case 1:
            decodedBlockedOn = .dependencies
        case 2:
            decodedBlockedOn = .schedule
        case 3:
            decodedBlockedOn = .anchorBoundary
        case 4:
            decodedBlockedOn = .signature
        case 5:
            decodedBlockedOn = .expired
        case 6:
            decodedBlockedOn = .invalid
        default:
            return nil
        }

        var decodedDependsOn: [UInt32] = []
        decodedDependsOn.reserveCapacity(Int(depends_on_len))
        if let dependsOnPtr = depends_on {
            for index in 0 ..< Int(depends_on_len) {
                decodedDependsOn.append(dependsOnPtr.advanced(by: index).pointee)
            }
        }

        return MigrationTransactionStatus(
            id: id,
            kind: kind,
            state: decodedState,
            scheduledHeight: BlockHeight(scheduled_height),
            expiryHeight: expiry_height == 0 ? nil : BlockHeight(expiry_height),
            isReady: ready,
            nextAction: decodedNextAction,
            blockedOn: decodedBlockedOn,
            dependsOn: decodedDependsOn,
            // `-1` is the "no drawn boundary" sentinel — always so for a preparation, which
            // anchors near-tip at proving time instead.
            anchorBoundaryHeight: anchor_boundary >= 0 ? BlockHeight(anchor_boundary) : nil
        )
    }
}

extension FfiMigrationTransactionStatuses {
    /// Converts an [`FfiMigrationTransactionStatuses`] container into
    /// `[MigrationTransactionStatus]`, or `nil` if any row fails to decode (should not happen;
    /// defensive only). An empty container (`len == 0`) decodes to an empty array -- the
    /// legitimate "no stored run" / "stored run with no transactions" answer.
    func unsafeToMigrationTransactionStatuses() -> [MigrationTransactionStatus]? {
        var decoded: [MigrationTransactionStatus] = []
        decoded.reserveCapacity(Int(len))

        for index in 0 ..< Int(len) {
            guard let status = ptr.advanced(by: index).pointee.unsafeToMigrationTransactionStatus() else {
                return nil
            }

            decoded.append(status)
        }

        return decoded
    }
}

extension FfiMigrationAdvanceStep {
    /// Converts an [`FfiMigrationAdvanceStep`] into a [`MigrationAdvance`], or `nil` for an
    /// unrecognized step discriminant (should not happen; defensive only), an EMPTY Prove batch
    /// (`prove_targets_len == 0` — upstream documents the batch never empty, so this is a
    /// malformed step, not the ordinary "nothing to prove" answer, which is `.waiting`), or an
    /// unrecognized `next_kind` while `next_height >= 0` (a malformed outlook — same defensive
    /// contract as the step discriminant). The per-kind payload fields
    /// (`kind_layer`/`kind_index`/`kind_crossing`) live on each `FfiProveTarget` row rather than on
    /// the step itself. The step discriminants are matched against the header's exported
    /// `ZCASHLC_ADVANCE_STEP_*` constants (U3), so this marshal and the rust side share one set of
    /// names instead of re-hardcoding the numbers; the outlook's kind is matched the same way
    /// against `ZCASHLC_STEP_KIND_*` (see [`MigrationStepKind.init(ffiValue:)`]).
    func unsafeToMigrationAdvance() -> MigrationAdvance? {
        let step: MigrationAdvanceStep
        switch Int32(bitPattern: self.step) {
        case ZCASHLC_ADVANCE_STEP_PROVE:
            var transactions: [MigrationProveTarget] = []
            transactions.reserveCapacity(Int(prove_targets_len))
            if let proveTargets = prove_targets {
                for index in 0 ..< Int(prove_targets_len) {
                    let target = proveTargets.advanced(by: index).pointee
                    // Likewise the sole producer of a `MigrationProveTarget` (internal init).
                    let kind: MigrationTransactionStatus.Kind = target.kind_is_preparation
                        ? .preparation(layer: Int(target.kind_layer), index: Int(target.kind_index))
                        : .transfer(crossing: Int(target.kind_crossing))
                    transactions.append(
                        MigrationProveTarget(id: target.id, kind: kind, isScheduleDue: target.schedule_due)
                    )
                }
            }
            guard !transactions.isEmpty else { return nil }
            step = .prove(transactions: transactions)
        case ZCASHLC_ADVANCE_STEP_BROADCAST:
            // THE SOLE PRODUCER of a `MigrationBroadcastInstruction`: its initializer is internal,
            // so an instruction exists only because this marshal minted one for a crank that
            // returned a BROADCAST step (see the type's doc).
            step = .broadcast(MigrationBroadcastInstruction(id: self.id))
        case ZCASHLC_ADVANCE_STEP_REBUILD:
            step = .rebuild(id: self.id)
        case ZCASHLC_ADVANCE_STEP_WAITING:
            step = .waiting
        case ZCASHLC_ADVANCE_STEP_COMPLETE:
            step = .complete
        case ZCASHLC_ADVANCE_STEP_REPLAN:
            // Bare on both sides of the FFI: upstream's Replan/Reevaluate name no transaction,
            // so there is no id to carry (the retired Attend collapse synthesised one).
            step = .replan
        case ZCASHLC_ADVANCE_STEP_REEVALUATE:
            step = .reevaluate
        default:
            return nil
        }

        var next: MigrationNextWork?
        if next_height >= 0 {
            guard let kind = MigrationStepKind(ffiValue: next_kind) else { return nil }
            next = MigrationNextWork(height: BlockHeight(next_height), kind: kind)
        }
        return MigrationAdvance(step: step, next: next)
    }
}

extension MigrationStepKind {
    /// Marshals the header's `ZCASHLC_STEP_KIND_*` constants into a `MigrationStepKind`, or `nil`
    /// for an unrecognized discriminant (should not happen; defensive only, same contract as the
    /// step discriminant itself).
    init?(ffiValue: UInt32) {
        switch Int32(bitPattern: ffiValue) {
        case ZCASHLC_STEP_KIND_PROVE:
            self = .prove
        case ZCASHLC_STEP_KIND_BROADCAST:
            self = .broadcast
        case ZCASHLC_STEP_KIND_REBUILD:
            self = .rebuild
        case ZCASHLC_STEP_KIND_REPLAN:
            self = .replan
        case ZCASHLC_STEP_KIND_REEVALUATE:
            self = .reevaluate
        case ZCASHLC_STEP_KIND_WAITING:
            self = .waiting
        case ZCASHLC_STEP_KIND_COMPLETE:
            self = .complete
        default:
            return nil
        }
    }
}

extension FfiNoteSplitProposal {
    /// Converts an [`FfiNoteSplitProposal`] into a [`NoteSplitProposal`].
    func toNoteSplitProposal() -> NoteSplitProposal {
        var outputNotes: [Zatoshi] = []
        outputNotes.reserveCapacity(Int(output_values_len))

        for index in 0 ..< Int(output_values_len) {
            outputNotes.append(Zatoshi(output_values.advanced(by: index).pointee))
        }

        return NoteSplitProposal(outputNotes: outputNotes, fee: Zatoshi(fee), proposalHandle: proposal_handle)
    }
}

extension FfiPreparedTransfer {
    /// Converts an [`FfiPreparedTransfer`] into a [`PreparedMigrationTransfer`], or `nil` when it
    /// carries no artifact at all (a null `pczt` — should not happen; defensive only, since every
    /// producer of this DTO either populates it or fails).
    func unsafeToPreparedMigrationTransfer() -> PreparedMigrationTransfer? {
        guard let pcztPtr = pczt else {
            return nil
        }

        return PreparedMigrationTransfer(
            id: id,
            txid: Data(FfiTxId(tuple: txid).array),
            pczt: Data(bytes: pcztPtr, count: Int(pczt_len))
        )
    }
}

extension FfiMigrationProveOutcome {
    /// Converts an [`FfiMigrationProveOutcome`] into a [`MigrationProveOutcome`], copying the
    /// preparation txids out of the rust-owned buffer (the caller still frees the DTO).
    ///
    /// Total-only is a valid shape: a pass that proved transfers alone reports its count with no
    /// txids, because only preparations are retrievable.
    func unsafeToMigrationProveOutcome() -> MigrationProveOutcome {
        var txids: [Data] = []
        txids.reserveCapacity(Int(preparation_txids_len))

        if let txidsPtr = preparation_txids {
            for index in 0 ..< Int(preparation_txids_len) {
                txids.append(Data(FfiTxId(tuple: txidsPtr.advanced(by: index).pointee).array))
            }
        }

        return MigrationProveOutcome(totalProved: Int(total_proved), preparationTxids: txids)
    }
}

extension FfiTransferProposal {
    /// Converts an [`FfiTransferProposal`] into a [`MigrationTransferProposal`], or `nil` for a
    /// missing `id` (should not happen; defensive only).
    func unsafeToMigrationTransferProposal() -> MigrationTransferProposal? {
        return MigrationTransferProposal(
            id: id,
            amount: Zatoshi(amount),
            anchorHeight: BlockHeight(anchor_height),
            nextExecutableAfterHeight: BlockHeight(next_executable_after_height),
            expiryHeight: BlockHeight(expiry_height)
        )
    }
}

extension FfiMigrationSchedule {
    /// Converts an [`FfiMigrationSchedule`] into a [`MigrationSchedule`], or `nil` if any transfer
    /// in the array fails to decode (should not happen; defensive only).
    func unsafeToMigrationSchedule() -> MigrationSchedule? {
        var proposals: [MigrationTransferProposal] = []
        proposals.reserveCapacity(Int(transfers_len))

        for index in 0 ..< Int(transfers_len) {
            guard let proposal = transfers.advanced(by: index).pointee.unsafeToMigrationTransferProposal() else {
                return nil
            }

            proposals.append(proposal)
        }

        var preparationSteps: [MigrationPreparationStep] = []
        preparationSteps.reserveCapacity(Int(preparations_len))

        for index in 0 ..< Int(preparations_len) {
            let row = preparations.advanced(by: index).pointee
            var dependsOn: [UInt32] = []
            dependsOn.reserveCapacity(Int(row.depends_on_len))
            if let dependsOnPtr = row.depends_on {
                for dependencyIndex in 0 ..< Int(row.depends_on_len) {
                    dependsOn.append(dependsOnPtr.advanced(by: dependencyIndex).pointee)
                }
            }
            preparationSteps.append(
                MigrationPreparationStep(
                    id: row.id,
                    layer: Int(row.layer),
                    index: Int(row.index),
                    broadcastHeight: BlockHeight(row.broadcast_height),
                    dependsOn: dependsOn
                )
            )
        }

        return MigrationSchedule(
            transfers: proposals,
            estimatedDurationHours: Int(estimated_duration_hours),
            proposalHandle: proposal_handle,
            preparations: preparationSteps
        )
    }
}

extension FfiMigrationRunEstimate {
    /// Converts an [`FfiMigrationRunEstimate`] into a [`MigrationRunEstimate`]. Total, not
    /// failable: every field is a plain value, and an empty runs array (`runs_len == 0`) is the
    /// legitimate zero-run estimate.
    func toMigrationRunEstimate() -> MigrationRunEstimate {
        var decodedRuns: [MigrationRunEstimate.Run] = []
        decodedRuns.reserveCapacity(Int(runs_len))

        for index in 0 ..< Int(runs_len) {
            let run = runs.advanced(by: index).pointee
            decodedRuns.append(
                MigrationRunEstimate.Run(
                    migratable: Zatoshi(run.migratable),
                    crossings: Int(run.crossings),
                    preparationLayers: Int(run.prep_layers),
                    preparationTransactions: Int(run.prep_transactions),
                    actions: Int(run.actions),
                    keystoneSigningSessions: Int(run.keystone_rounds)
                )
            )
        }

        return MigrationRunEstimate(runs: decodedRuns, finalResidual: Zatoshi(final_residual))
    }
}

extension FfiUnsignedTransferPczt {
    /// Converts an [`FfiUnsignedTransferPczt`] into a [`MigrationUnsignedTransferPczt`], or `nil`
    /// for a missing `pczt` (should not happen; defensive only).
    func unsafeToMigrationUnsignedTransferPczt() -> MigrationUnsignedTransferPczt? {
        guard let pcztPtr = pczt else {
            return nil
        }

        return MigrationUnsignedTransferPczt(
            id: id,
            pczt: Data(bytes: pcztPtr, count: Int(pczt_len)),
            actions: Int(actions)
        )
    }

    /// Converts an [`FfiUnsignedTransferPczt`] into a [`MigrationSignedTransferPczt`] -- the same
    /// FFI struct doubles as the batch-SIGNED pczt pair set returned by
    /// `zcashlc_migration_keystone_apply_batch_signatures` (see its doc), so this mirrors
    /// `unsafeToMigrationUnsignedTransferPczt()` field-for-field into the signed model instead.
    /// `nil` for a missing `pczt` (should not happen; defensive only).
    func unsafeToMigrationSignedTransferPczt() -> MigrationSignedTransferPczt? {
        guard let pcztPtr = pczt else {
            return nil
        }

        return MigrationSignedTransferPczt(
            id: id,
            pczt: Data(bytes: pcztPtr, count: Int(pczt_len))
        )
    }
}

extension FfiKeystoneBatchDecodeResult {
    /// Converts an [`FfiKeystoneBatchDecodeResult`] into a [`KeystoneBatchDecodeResult`]. Total,
    /// not failable: `data`/`firmwareVersion` are legitimately `nil` while `!complete` (or when
    /// the response envelope carried no firmware version), not an error state.
    func toKeystoneBatchDecodeResult() -> KeystoneBatchDecodeResult {
        KeystoneBatchDecodeResult(
            complete: complete,
            progress: Int(progress),
            data: data.map { Data(bytes: $0, count: Int(data_len)) },
            firmwareVersion: has_firmware_version
                ? KeystoneFirmwareVersion(major: firmware_major, minor: firmware_minor, build: firmware_build)
                : nil
        )
    }
}

/// Duplicates each string into an owned, null-terminated C string for a `const char *const *` FFI
/// argument. Pair with `freeCStrings` once the call using them returns.
private func makeCStrings(_ strings: [String]) -> [UnsafeMutablePointer<CChar>?] {
    strings.map { strdup($0) }
}

/// Frees the C strings allocated by `makeCStrings`.
private func freeCStrings(_ pointers: [UnsafeMutablePointer<CChar>?]) {
    pointers.forEach { free($0) }
}

/// Views `makeCStrings`-owned pointers as `UnsafePointer<CChar>?`, matching the `const char *`
/// element type a `const char *const *` FFI argument expects (the owning array stays
/// `UnsafeMutablePointer` so `freeCStrings` can free it).
private func constPointers(_ owned: [UnsafeMutablePointer<CChar>?]) -> [UnsafePointer<CChar>?] {
    owned.map { pointer in pointer.map { UnsafePointer($0) } }
}

// swiftlint:disable large_tuple line_length file_length
struct FfiTxId {
    var tuple: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
    var array: [UInt8] {
        withUnsafeBytes(of: self.tuple) { buf in
            [UInt8](buf)
        }
    }
}
