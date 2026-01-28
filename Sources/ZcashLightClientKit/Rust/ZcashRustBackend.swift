//
//  ZcashRustBackend.swift
//  ZcashLightClientKit
//
//  Created by Jack Grigg on 5/8/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
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

    let walletDbHandle: WalletDbHandle
    let fsBlockDbHandle: FsBlockDbHandle
    let spendParamsPath: (String, UInt)
    let outputParamsPath: (String, UInt)
    let keyDeriving: ZcashKeyDerivationBackendWelding

    let networkType: NetworkType
    let sdkFlags: SDKFlags

    static var rustInitialized = false

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
    ///     This is ignored after the first ZcashRustBackend instance is created.
    init(
        dbData: URL,
        fsBlockDbRoot: URL,
        spendParamsPath: URL,
        outputParamsPath: URL,
        networkType: NetworkType,
        logLevel: RustLogging = RustLogging.off,
        sdkFlags: SDKFlags
    ) {
        self.walletDbHandle = WalletDbHandle(dbData: dbData, networkType: networkType)
        self.fsBlockDbHandle = FsBlockDbHandle(fsBlockDbRoot: fsBlockDbRoot)
        self.spendParamsPath = spendParamsPath.osPathStr()
        self.outputParamsPath = outputParamsPath.osPathStr()
        self.networkType = networkType
        self.keyDeriving = ZcashKeyDerivationBackend(networkType: networkType)
        self.sdkFlags = sdkFlags

        if !Self.rustInitialized {
            Self.rustInitialized = true
            Self.initializeRust(logLevel: logLevel)
        }
    }

    /// Opens the database handles for use.
    /// This must be called before any database operations.
    @DBActor
    func openDb() async throws {
        try walletDbHandle.open()
        try fsBlockDbHandle.open()
    }

    /// Returns the resolved wallet database handle pointer for use in FFI calls.
    @DBActor
    func resolveDbHandle() async throws -> OpaquePointer {
        try walletDbHandle.resolveHandle()
    }

    /// Returns the resolved filesystem block database handle pointer for use in FFI calls.
    @DBActor
    func resolveFsBlockDbHandle() async throws -> OpaquePointer {
        try fsBlockDbHandle.resolveHandle()
    }

    @DBActor
    func listAccounts() async throws -> [Account] {
        let accountsPtr = zcashlc_list_accounts(
            try walletDbHandle.resolveHandle()
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

    @DBActor
    func getAccount(
        for accountUUID: AccountUUID
    ) async throws -> Account {
        let accountPtr: UnsafeMutablePointer<FfiAccount>? = zcashlc_get_account(
            try walletDbHandle.resolveHandle(),
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
            try walletDbHandle.resolveHandle(),
            [CChar](ufvk.utf8CString),
            treeStateBytes,
            UInt(treeStateBytes.count),
            rUntil,
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
            try walletDbHandle.resolveHandle(),
            seed,
            UInt(seed.count),
            treeStateBytes,
            UInt(treeStateBytes.count),
            rUntil,
            [CChar](name.utf8CString),
            kSource
        )

        guard let ffiBinaryKeyPtr else {
            throw ZcashError.rustCreateAccount(lastErrorMessage(fallback: "`createAccount` failed with unknown error"))
        }

        defer { zcashlc_free_binary_key(ffiBinaryKeyPtr) }

        return ffiBinaryKeyPtr.pointee.unsafeToUnifiedSpendingKey(network: networkType)
    }

    @DBActor
    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        let result = zcashlc_is_seed_relevant_to_any_derived_account(
            try walletDbHandle.resolveHandle(),
            seed,
            UInt(seed.count)
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

    @DBActor
    func proposeTransfer(
        accountUUID: AccountUUID,
        to address: String,
        value: Int64,
        memo: MemoBytes?
    ) async throws -> FfiProposal {
        let proposal = zcashlc_propose_transfer(
            try walletDbHandle.resolveHandle(),
            accountUUID.id,
            [CChar](address.utf8CString),
            value,
            memo?.bytes,
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
    func proposeTransferFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> FfiProposal {
        let proposal = zcashlc_propose_transfer_from_uri(
            try walletDbHandle.resolveHandle(),
            accountUUID.id,
            [CChar](uri.utf8CString),
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

        let handle = try walletDbHandle.resolveHandle()
        let pcztPtr = proposalBytes.withUnsafeBufferPointer { proposalPtr in
            zcashlc_create_pczt_from_proposal(
                handle,
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
        let handle = try walletDbHandle.resolveHandle()
        let txidPtr: UnsafeMutablePointer<FfiBoxedSlice>? = pcztWithProofs.withUnsafeBytes { pcztWithProofsBuffer in
            guard let pcztWithProofsBufferPtr = pcztWithProofsBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return nil
            }

            return pcztWithSigs.withUnsafeBytes { pcztWithSigsBuffer in
                guard let pcztWithSigsBufferPtr = pcztWithSigsBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return nil
                }

                return zcashlc_extract_and_store_from_pczt(
                    handle,
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

        guard txidPtr.pointee.len == 32 else {
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
        var contiguousTxidBytes = ContiguousArray<UInt8>(Data(count: 32))

        let handle = try walletDbHandle.resolveHandle()
        let result = contiguousTxidBytes.withUnsafeMutableBufferPointer { txidBytePtr in
            zcashlc_decrypt_and_store_transaction(
                handle,
                txBytes,
                UInt(txBytes.count),
                Int64(minedHeight ?? 0),
                txidBytePtr.baseAddress
            )
        }

        guard result != 0 else {
            throw ZcashError.rustDecryptAndStoreTransaction(lastErrorMessage(fallback: "`decryptAndStoreTransaction` failed with unknown error"))
        }

        return Data(contiguousTxidBytes)
    }

    @DBActor
    func getCurrentAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        let addressCStr = zcashlc_get_current_address(
            try walletDbHandle.resolveHandle(),
            accountUUID.id
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
            try walletDbHandle.resolveHandle(),
            accountUUID.id,
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

    @DBActor
    func getMemo(txId: Data, outputPool: UInt32, outputIndex: UInt16) async throws -> Memo? {
        guard txId.count == 32 else {
            throw ZcashError.rustGetMemoInvalidTxIdLength
        }

        var contiguousMemoBytes = ContiguousArray<UInt8>(MemoBytes.empty().bytes)
        var success = false

        let handle = try walletDbHandle.resolveHandle()
        contiguousMemoBytes.withUnsafeMutableBufferPointer { memoBytePtr in
            success = zcashlc_get_memo(handle, txId.bytes, outputPool, outputIndex, memoBytePtr.baseAddress)
        }

        guard success else { return nil }

        return (try? MemoBytes(contiguousBytes: contiguousMemoBytes)).flatMap { try? $0.intoMemo() }
    }

    @DBActor
    func getTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        let balance = zcashlc_get_total_transparent_balance_for_account(
            try walletDbHandle.resolveHandle(),
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

    @DBActor
    func getVerifiedTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        let balance = zcashlc_get_verified_transparent_balance_for_account(
            try walletDbHandle.resolveHandle(),
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
        let initResult = zcashlc_init_data_database(try walletDbHandle.resolveHandle(), seed, UInt(seed?.count ?? 0))

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
        let result = zcashlc_init_block_metadata_db(try fsBlockDbHandle.resolveHandle())

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

            let res = zcashlc_write_block_metadata(try fsBlockDbHandle.resolveHandle(), fsBlocks)

            guard res else {
                throw ZcashError.rustWriteBlocksMetadata(lastErrorMessage(fallback: "`writeBlocksMetadata` failed with unknown error"))
            }
        }
    }

    @DBActor
    func latestCachedBlockHeight() async throws -> BlockHeight {
        let height = zcashlc_latest_cached_block_height(try fsBlockDbHandle.resolveHandle())

        if height >= 0 {
            return BlockHeight(height)
        } else if height == -1 {
            return BlockHeight.empty()
        } else {
            throw ZcashError.rustLatestCachedBlockHeight(lastErrorMessage(fallback: "`latestCachedBlockHeight` failed with unknown error"))
        }
    }

    @DBActor
    func listTransparentReceivers(accountUUID: AccountUUID) async throws -> [TransparentAddress] {
        let encodedKeysPtr = zcashlc_list_transparent_receivers(
            try walletDbHandle.resolveHandle(),
            accountUUID.id
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
            try walletDbHandle.resolveHandle(),
            txid,
            UInt(txid.count),
            Int32(index),
            script,
            UInt(script.count),
            value,
            Int32(height)
        )

        guard result else {
            throw ZcashError.rustPutUnspentTransparentOutput(lastErrorMessage(fallback: "`putUnspentTransparentOutput` failed with unknown error"))
        }
    }

    @DBActor
    func rewindToHeight(height: BlockHeight) async throws -> RewindResult {
        var safeRewindHeight: Int64 = -1
        let result = zcashlc_rewind_to_height(try walletDbHandle.resolveHandle(), UInt32(height), &safeRewindHeight)

        if result >= 0 {
            return .success(BlockHeight(result))
        } else if result == -1 && safeRewindHeight > 0 {
            return .requestedHeightTooLow(BlockHeight(safeRewindHeight))
        } else {
            throw ZcashError.rustRewindToHeight(Int32(height), lastErrorMessage(fallback: "`rewindToHeight` failed with unknown error"))
        }
    }

    @DBActor
    func rewindCacheToHeight(height: Int32) async throws {
        let result = zcashlc_rewind_fs_block_cache_to_height(try fsBlockDbHandle.resolveHandle(), height)

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

            ffiSubtreeRootsVec.append(
                FfiSubtreeRoot(
                    root_hash_ptr: hashPtr,
                    root_hash_ptr_len: UInt(contiguousHashBytes.count),
                    completing_block_height: UInt32(root.completingBlockHeight)
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

            let res = zcashlc_put_sapling_subtree_roots(try walletDbHandle.resolveHandle(), startIndex, rootsPtr)

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

            ffiSubtreeRootsVec.append(
                FfiSubtreeRoot(
                    root_hash_ptr: hashPtr,
                    root_hash_ptr_len: UInt(contiguousHashBytes.count),
                    completing_block_height: UInt32(root.completingBlockHeight)
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

            let res = zcashlc_put_orchard_subtree_roots(try walletDbHandle.resolveHandle(), startIndex, rootsPtr)

            guard res else {
                throw ZcashError.rustPutOrchardSubtreeRoots(lastErrorMessage(fallback: "`putOrchardSubtreeRoots` failed with unknown error"))
            }
        }
    }

    @DBActor
    func updateChainTip(height: Int32) async throws {
        let result = zcashlc_update_chain_tip(try walletDbHandle.resolveHandle(), height)

        guard result else {
            throw ZcashError.rustUpdateChainTip(lastErrorMessage(fallback: "`updateChainTip` failed with unknown error"))
        }
    }

    @DBActor
    func fullyScannedHeight() async throws -> BlockHeight? {
        let height = zcashlc_fully_scanned_height(try walletDbHandle.resolveHandle())

        if height >= 0 {
            return BlockHeight(height)
        } else if height == -1 {
            return nil
        } else {
            throw ZcashError.rustFullyScannedHeight(lastErrorMessage(fallback: "`fullyScannedHeight` failed with unknown error"))
        }
    }

    @DBActor
    func maxScannedHeight() async throws -> BlockHeight? {
        let height = zcashlc_max_scanned_height(try walletDbHandle.resolveHandle())

        if height >= 0 {
            return BlockHeight(height)
        } else if height == -1 {
            return nil
        } else {
            throw ZcashError.rustMaxScannedHeight(lastErrorMessage(fallback: "`maxScannedHeight` failed with unknown error"))
        }
    }

    @DBActor
    func getWalletSummary() async throws -> WalletSummary? {
        let summaryPtr = zcashlc_get_wallet_summary(try walletDbHandle.resolveHandle(), confirmationsPolicy.toBackend())

        guard let summaryPtr else {
            throw ZcashError.rustGetWalletSummary(lastErrorMessage(fallback: "`getWalletSummary` failed with unknown error"))
        }

        defer { zcashlc_free_wallet_summary(summaryPtr) }

        if summaryPtr.pointee.fully_scanned_height < 0 {
            return nil
        }

        var accountBalances: [AccountUUID: AccountBalance] = [:]

        for i in (0 ..< Int(summaryPtr.pointee.account_balances_len)) {
            let accountBalance = summaryPtr.pointee.account_balances.advanced(by: i).pointee
            accountBalances[AccountUUID(id: accountBalance.uuidArray)] = accountBalance.toAccountBalance()
        }
        
        // Modify spendable `accountBalances` if chainTip hasn't been updated yet
        if await !sdkFlags.chainTipUpdated {
            accountBalances.forEach { key, _ in
                if let accountBalance = accountBalances[key] {
                    accountBalances[key] = AccountBalance(
                        saplingBalance: PoolBalance(
                            spendableValue: .zero,
                            changePendingConfirmation: accountBalance.saplingBalance.changePendingConfirmation,
                            valuePendingSpendability: accountBalance.saplingBalance.valuePendingSpendability
                            + accountBalance.saplingBalance.spendableValue
                        ),
                        orchardBalance: PoolBalance(
                            spendableValue: .zero,
                            changePendingConfirmation: accountBalance.orchardBalance.changePendingConfirmation,
                            valuePendingSpendability: accountBalance.orchardBalance.valuePendingSpendability
                            + accountBalance.orchardBalance.spendableValue
                        ),
                        unshielded: .zero,
                        awaitingResolution: accountBalance.unshielded
                    )
                }
            }
        }

        return WalletSummary(
            accountBalances: accountBalances,
            chainTipHeight: BlockHeight(summaryPtr.pointee.chain_tip_height),
            fullyScannedHeight: BlockHeight(summaryPtr.pointee.fully_scanned_height),
            recoveryProgress: summaryPtr.pointee.recovery_progress?.pointee.toScanProgress(),
            scanProgress: summaryPtr.pointee.scan_progress?.pointee.toScanProgress(),
            nextSaplingSubtreeIndex: UInt32(summaryPtr.pointee.next_sapling_subtree_index),
            nextOrchardSubtreeIndex: UInt32(summaryPtr.pointee.next_orchard_subtree_index)
        )
    }

    @DBActor
    func suggestScanRanges() async throws -> [ScanRange] {
        let scanRangesPtr = zcashlc_suggest_scan_ranges(try walletDbHandle.resolveHandle())

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
            try walletDbHandle.resolveHandle(),
            try fsBlockDbHandle.resolveHandle(),
            fromHeight,
            fromStateBytes,
            UInt(fromStateBytes.count),
            limit
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

    @DBActor
    func proposeShielding(
        accountUUID: AccountUUID,
        memo: MemoBytes?,
        shieldingThreshold: Zatoshi,
        transparentReceiver: String?
    ) async throws -> FfiProposal? {
        let proposal = zcashlc_propose_shielding(
            try walletDbHandle.resolveHandle(),
            accountUUID.id,
            memo?.bytes,
            UInt64(shieldingThreshold.amount),
            transparentReceiver.map { [CChar]($0.utf8CString) },
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
        let handle = try walletDbHandle.resolveHandle()

        let txIdsPtr = proposalBytes.withUnsafeBufferPointer { proposalPtr in
            usk.bytes.withUnsafeBufferPointer { uskPtr in
                zcashlc_create_proposed_transactions(
                    handle,
                    proposalPtr.baseAddress,
                    UInt(proposalBytes.count),
                    uskPtr.baseAddress,
                    UInt(usk.bytes.count),
                    spendParamsPath.0,
                    spendParamsPath.1,
                    outputParamsPath.0,
                    outputParamsPath.1
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

    nonisolated func consensusBranchIdFor(height: Int32) throws -> Int32 {
        let branchId = zcashlc_branch_id_for_height(height, networkType.networkId)

        guard branchId != -1 else {
            throw ZcashError.rustNoConsensusBranchId(height)
        }

        return branchId
    }
    
    // swiftlint:disable:next cyclomatic_complexity
    @DBActor func transactionDataRequests() async throws -> [TransactionDataRequest] {
        let tDataRequestsPtr = zcashlc_transaction_data_requests(
            try walletDbHandle.resolveHandle()
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

        zcashlc_set_transaction_status(
            try walletDbHandle.resolveHandle(),
            txId.bytes,
            UInt(txId.bytes.count),
            transactionStatus
        )
    }
    
    @DBActor
    func fixWitnesses() async throws {
        zcashlc_fix_witnesses(try walletDbHandle.resolveHandle())
    }
    
    @DBActor
    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        let singleUseTaddrPtr = zcashlc_get_single_use_taddr(
            try walletDbHandle.resolveHandle(),
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
            try walletDbHandle.resolveHandle(),
            accountUUID.id
        )
        
        guard success else {
            throw ZcashError.rustDeleteAccount(
                lastErrorMessage(fallback: "`deleteAccount` failed with unknown error")
            )
        }
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
                ufvk: nil
            )
        }
        
        let ufvkTyped = ufvk.map { UnifiedFullViewingKey(validatedEncoding: String(cString: $0)) }

        // Valid ZIP32 account index
        return .init(
            id: AccountUUID(id: uuidArray),
            name: account_name != nil ? String(cString: account_name) : nil,
            keySource: key_source != nil ? String(cString: key_source) : nil,
            seedFingerprint: seedFingerprintArray,
            hdAccountIndex: Zip32AccountIndex(hd_account_index),
            ufvk: ufvkTyped
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
        .init(
            spendableValue: Zatoshi(self.spendable_value),
            changePendingConfirmation: Zatoshi(self.change_pending_confirmation),
            valuePendingSpendability: Zatoshi(self.value_pending_spendability)
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

// swiftlint:disable large_tuple line_length file_length
struct FfiTxId {
    var tuple: (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
    var array: [UInt8] {
        withUnsafeBytes(of: self.tuple) { buf in
            [UInt8](buf)
        }
    }
}
