// Generated using Sourcery 2.3.0 — https://github.com/krzysztofzablocki/Sourcery
// DO NOT EDIT

/*
!!!!! To edit this file go to ZcashErrorCodeDefinition first and udate/add codes. Then run generateErrorCode.sh script to regenerate this file.

By design each error should be used only at one place in the app. Thanks to that it is possible to identify exact line in the code from which the
error originates. And it can help with debugging.
*/

import Foundation

public enum ZcashError: Equatable, Error {
    /// Some error happened that is not handled as `ZcashError`. All errors in the SDK are (should be) `ZcashError`.
    /// This case is ideally not contructed directly or thrown by any SDK function, rather it's a wrapper for case clients expect ZcashErrot and want to pass it to a function/enum.
    /// If this is the case, use `toZcashError()` extension of Error. This helper avoids to end up with Optional handling.
    /// ZUNKWN0001
    case unknown(_ error: Error)
    /// Updating of paths in `Initilizer` according to alias failed.
    /// ZINIT0001
    case initializerCantUpdateURLWithAlias(_ url: URL)
    /// Alias used to create this instance of the `SDKSynchronizer` is already used by other instance.
    /// ZINIT0002
    case initializerAliasAlreadyInUse(_ alias: ZcashSynchronizerAlias)
    /// Object on disk at `generalStorageURL` path exists. But it file not directory.
    /// ZINIT0003
    case initializerGeneralStorageExistsButIsFile(_ generalStorageURL: URL)
    /// Can't create directory at `generalStorageURL` path.
    /// ZINIT0004
    case initializerGeneralStorageCantCreate(_ generalStorageURL: URL, _ error: Error)
    /// Can't set `isExcludedFromBackup` flag to `generalStorageURL`.
    /// ZINIT0005
    case initializerCantSetNoBackupFlagToGeneralStorageURL(_ generalStorageURL: URL, _ error: Error)
    /// Unknown GRPC Service error
    /// ZSRVC0001
    case serviceUnknownError(_ error: Error)
    /// LightWalletService.getInfo failed.
    /// ZSRVC0002
    case serviceGetInfoFailed(_ error: LightWalletServiceError)
    /// LightWalletService.latestBlock failed.
    /// ZSRVC0003
    case serviceLatestBlockFailed(_ error: LightWalletServiceError)
    /// LightWalletService.latestBlockHeight failed.
    /// ZSRVC0004
    case serviceLatestBlockHeightFailed(_ error: LightWalletServiceError)
    /// LightWalletService.blockRange failed.
    /// ZSRVC0005
    case serviceBlockRangeFailed(_ error: LightWalletServiceError)
    /// LightWalletService.submit failed.
    /// ZSRVC0006
    case serviceSubmitFailed(_ error: LightWalletServiceError)
    /// LightWalletService.fetchTransaction failed.
    /// ZSRVC0007
    case serviceFetchTransactionFailed(_ error: LightWalletServiceError)
    /// LightWalletService.fetchUTXOs failed.
    /// ZSRVC0008
    case serviceFetchUTXOsFailed(_ error: LightWalletServiceError)
    /// LightWalletService.blockStream failed.
    /// ZSRVC0000
    case serviceBlockStreamFailed(_ error: LightWalletServiceError)
    /// LightWalletService.getSubtreeRoots failed.
    /// ZSRVC0009
    case serviceSubtreeRootsStreamFailed(_ error: LightWalletServiceError)
    /// LightWalletService.getTaddressTxids failed.
    /// ZSRVC0010
    case serviceGetTaddressTxidsFailed(_ error: LightWalletServiceError)
    /// LightWalletService.getMempoolStream failed.
    /// ZSRVC0011
    case serviceGetMempoolStreamFailed(_ error: LightWalletServiceError)
    /// Endpoint is not provided
    /// ZTSRV0001
    case torServiceMissingEndpoint
    /// Tor client fails to resolve ServiceMode
    /// ZTSRV0002
    case torServiceUnresolvedMode
    /// GRPC Service is called with a Tor mode instead of direct one
    /// ZTSRV0003
    case grpcServiceCalledWithTorMode
    /// TorClient is nil
    /// ZTSRV0004
    case torClientUnavailable
    /// TorClient is called but SDKFlags are set as Tor disabled
    /// ZTSRV0005
    case torNotEnabled
    /// SimpleConnectionProvider init of Connection failed.
    /// ZSCPC0001
    case simpleConnectionProvider(_ error: Error)
    /// Downloaded file with sapling spending parameters isn't valid.
    /// ZSAPP0001
    case saplingParamsInvalidSpendParams
    /// Downloaded file with sapling output parameters isn't valid.
    /// ZSAPP0002
    case saplingParamsInvalidOutputParams
    /// Failed to download sapling parameters file
    /// - `error` is download error.
    /// - `downloadURL` is URL from which was file downloaded.
    /// ZSAPP0003
    case saplingParamsDownload(_ error: Error, _ downloadURL: URL)
    /// Failed to move sapling parameters file to final destination after download.
    /// - `error` is move error.
    /// - `downloadURL` is URL from which was file downloaded.
    /// - `destination` is filesystem URL pointing to location where downloaded file should be moved.
    /// ZSAPP0004
    case saplingParamsCantMoveDownloadedFile(_ error: Error, _ downloadURL: URL, _ destination: URL)
    /// SQLite query failed when fetching block information from database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZBDAO0001
    case blockDAOBlock(_ sqliteError: Error)
    /// Fetched block information from DB but can't decode them.
    /// - `error` is decoding error.
    /// ZBDAO0002
    case blockDAOCantDecode(_ error: Error)
    /// SQLite query failed when fetching height of the latest block from the database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZBDAO0003
    case blockDAOLatestBlockHeight(_ sqliteError: Error)
    /// SQLite query failed when fetching the latest block from the database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZBDAO0004
    case blockDAOLatestBlock(_ sqliteError: Error)
    /// Fetched latest block information from DB but can't decode them.
    /// - `error` is decoding error.
    /// ZBDAO0005
    case blockDAOLatestBlockCantDecode(_ error: Error)
    /// SQLite query failed when fetching the first unenhanced block from the database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZBDAO0006
    case blockDAOFirstUnenhancedHeight(_ sqliteError: Error)
    /// Fetched unenhanced block information from DB but can't decode them.
    /// - `error` is decoding error.
    /// ZBDAO0007
    case blockDAOFirstUnenhancedCantDecode(_ error: Error)
    /// Error from rust layer when calling ZcashRustBackend.createAccount
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0001
    case rustCreateAccount(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.createToAddress
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0002
    case rustCreateToAddress(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.decryptAndStoreTransaction
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0003
    case rustDecryptAndStoreTransaction(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.getBalance
    /// - `account` is account passed to ZcashRustBackend.getBalance.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0004
    case rustGetBalance(_ account: Int, _ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.getCurrentAddress
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0005
    case rustGetCurrentAddress(_ rustError: String)
    /// Unified address generated by rust layer is invalid when calling ZcashRustBackend.getCurrentAddress
    /// ZRUST0006
    case rustGetCurrentAddressInvalidAddress
    /// Error from rust layer when calling ZcashRustBackend.getNearestRewindHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0007
    case rustGetNearestRewindHeight(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.getNextAvailableAddress
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0008
    case rustGetNextAvailableAddress(_ rustError: String)
    /// Unified address generated by rust layer is invalid when calling ZcashRustBackend.getNextAvailableAddress
    /// ZRUST0009
    case rustGetNextAvailableAddressInvalidAddress
    /// Error from rust layer when calling ZcashRustBackend.getTransparentBalance
    /// - `account` is account passed to ZcashRustBackend.getTransparentBalance.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0011
    case rustGetTransparentBalance(_ accountUUID: AccountUUID, _ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.getVerifiedBalance
    /// - `account` is account passed to ZcashRustBackend.getVerifiedBalance.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0012
    case rustGetVerifiedBalance(_ account: Int, _ rustError: String)
    /// account parameter is lower than 0 when calling ZcashRustBackend.getVerifiedTransparentBalance
    /// - `account` is account passed to ZcashRustBackend.getVerifiedTransparentBalance.
    /// ZRUST0013
    case rustGetVerifiedTransparentBalanceNegativeAccount(_ account: Int)
    /// Error from rust layer when calling ZcashRustBackend.getVerifiedTransparentBalance
    /// - `account` is account passed to ZcashRustBackend.getVerifiedTransparentBalance.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0014
    case rustGetVerifiedTransparentBalance(_ accountUUID: AccountUUID, _ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.initDataDb
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0015
    case rustInitDataDb(_ rustError: String)
    /// Any of the viewing keys passed to the ZcashRustBackend.initAccountsTable method contains null bytes before end
    /// ZRUST0016
    case rustInitAccountsTableViewingKeyCotainsNullBytes
    /// Any of the viewing keys passed to the ZcashRustBackend.initAccountsTable method isn't valid
    /// ZRUST0017
    case rustInitAccountsTableViewingKeyIsInvalid
    /// Error from rust layer when calling ZcashRustBackend.initAccountsTable
    /// ZRUST0018
    case rustInitAccountsTableDataDbNotEmpty
    /// Error from rust layer when calling ZcashRustBackend.initAccountsTable
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0019
    case rustInitAccountsTable(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.initBlockMetadataDb
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0020
    case rustInitBlockMetadataDb(_ rustError: String)
    /// Unable to allocate memory required to write blocks when calling ZcashRustBackend.writeBlocksMetadata
    /// ZRUST0021
    case rustWriteBlocksMetadataAllocationProblem
    /// Error from rust layer when calling ZcashRustBackend.writeBlocksMetadata
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0022
    case rustWriteBlocksMetadata(_ rustError: String)
    /// hash passed to the ZcashRustBackend.initBlocksTable method contains null bytes before end
    /// ZRUST0023
    case rustInitBlocksTableHashContainsNullBytes
    /// saplingTree passed to the ZcashRustBackend.initBlocksTable method contains null bytes before end
    /// ZRUST0024
    case rustInitBlocksTableSaplingTreeContainsNullBytes
    /// Error from rust layer when calling ZcashRustBackend.initBlocksTable
    /// ZRUST0025
    case rustInitBlocksTableDataDbNotEmpty
    /// Error from rust layer when calling ZcashRustBackend.initBlocksTable
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0026
    case rustInitBlocksTable(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.listTransparentReceivers
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0027
    case rustListTransparentReceivers(_ rustError: String)
    /// Transparent receiver generated by rust layer is invalid when calling ZcashRustBackend.listTransparentReceivers
    /// ZRUST0028
    case rustListTransparentReceiversInvalidAddress
    /// Error from rust layer when calling ZcashRustBackend.putUnspentTransparentOutput
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0029
    case rustPutUnspentTransparentOutput(_ rustError: String)
    /// Error unrelated to chain validity from rust layer when calling ZcashRustBackend.validateCombinedChain
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0030
    case rustValidateCombinedChainValidationFailed(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.rewindToHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0032
    case rustRewindToHeight(_ height: Int32, _ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.rewindCacheToHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0033
    case rustRewindCacheToHeight(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.scanBlocks
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0034
    case rustScanBlocks(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.shieldFunds
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0035
    case rustShieldFunds(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.consensusBranchIdFor
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0036
    case rustNoConsensusBranchId(_ height: Int32)
    /// address passed to the ZcashRustBackend.receiverTypecodesOnUnifiedAddress method contains null bytes before end
    /// - `address` is address passed to ZcashRustBackend.receiverTypecodesOnUnifiedAddress.
    /// ZRUST0037
    case rustReceiverTypecodesOnUnifiedAddressContainsNullBytes(_ address: String)
    /// Error from rust layer when calling ZcashRustBackend.receiverTypecodesOnUnifiedAddress
    /// ZRUST0038
    case rustRustReceiverTypecodesOnUnifiedAddressMalformed
    /// Error from rust layer when calling ZcashRustBackend.deriveUnifiedSpendingKey
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0039
    case rustDeriveUnifiedSpendingKey(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.deriveUnifiedFullViewingKey
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0040
    case rustDeriveUnifiedFullViewingKey(_ rustError: String)
    /// Viewing key derived by rust layer is invalid when calling ZcashRustBackend.deriveUnifiedFullViewingKey
    /// ZRUST0041
    case rustDeriveUnifiedFullViewingKeyInvalidDerivedKey
    /// Error from rust layer when calling ZcashRustBackend.getSaplingReceiver
    /// - `address` is address passed to ZcashRustBackend.getSaplingReceiver.
    /// ZRUST0042
    case rustGetSaplingReceiverInvalidAddress(_ address: UnifiedAddress)
    /// Sapling receiver generated by rust layer is invalid when calling ZcashRustBackend.getSaplingReceiver
    /// ZRUST0043
    case rustGetSaplingReceiverInvalidReceiver
    /// Error from rust layer when calling ZcashRustBackend.getTransparentReceiver
    /// - `address` is address passed to ZcashRustBackend.getTransparentReceiver.
    /// ZRUST0044
    case rustGetTransparentReceiverInvalidAddress(_ address: UnifiedAddress)
    /// Transparent receiver generated by rust layer is invalid when calling ZcashRustBackend.getTransparentReceiver
    /// ZRUST0045
    case rustGetTransparentReceiverInvalidReceiver
    /// Unable to allocate memory required to write blocks when calling ZcashRustBackend.putSaplingSubtreeRoots
    /// sourcery: code="ZRUST0046"
    /// ZRUST0046
    case rustPutSaplingSubtreeRootsAllocationProblem
    /// Error from rust layer when calling ZcashRustBackend.putSaplingSubtreeRoots
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0047"
    /// ZRUST0047
    case rustPutSaplingSubtreeRoots(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.updateChainTip
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0048"
    /// ZRUST0048
    case rustUpdateChainTip(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.suggestScanRanges
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0049"
    /// ZRUST0049
    case rustSuggestScanRanges(_ rustError: String)
    /// Invalid transaction ID length when calling ZcashRustBackend.getMemo. txId must be 32 bytes.
    /// ZRUST0050
    case rustGetMemoInvalidTxIdLength
    /// Error from rust layer when calling ZcashRustBackend.getScanProgress
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0051
    case rustGetScanProgress(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.fullyScannedHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0052
    case rustFullyScannedHeight(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.maxScannedHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0053
    case rustMaxScannedHeight(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.latestCachedBlockHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0054
    case rustLatestCachedBlockHeight(_ rustError: String)
    /// Rust layer's call ZcashRustBackend.getScanProgress returned values that after computation are outside of allowed range 0-100%.
    /// - `progress` value reported
    /// ZRUST0055
    case rustScanProgressOutOfRange(_ progress: String)
    /// Error from rust layer when calling ZcashRustBackend.getWalletSummary
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0056
    case rustGetWalletSummary(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0057
    case rustProposeTransferFromURI(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0058
    case rustListAccounts(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.rustIsSeedRelevantToAnyDerivedAccount
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0059
    case rustIsSeedRelevantToAnyDerivedAccount(_ rustError: String)
    /// Unable to allocate memory required to write blocks when calling ZcashRustBackend.putOrchardSubtreeRoots
    /// sourcery: code="ZRUST0060"
    /// ZRUST0060
    case rustPutOrchardSubtreeRootsAllocationProblem
    /// Error from rust layer when calling ZcashRustBackend.putOrchardSubtreeRoots
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0061"
    /// ZRUST0061
    case rustPutOrchardSubtreeRoots(_ rustError: String)
    /// Error from rust layer when calling TorClient.init
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0062"
    /// ZRUST0062
    case rustTorClientInit(_ rustError: String)
    /// Error from rust layer when calling TorClient.get
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0063"
    /// ZRUST0063
    case rustTorClientGet(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.transactionDataRequests
    /// - `rustError` contains error generated by the rust layer.
    /// sourcery: code="ZRUST0064"
    /// ZRUST0064
    case rustTransactionDataRequests(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.deriveArbitraryWalletKey
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0065
    case rustDeriveArbitraryWalletKey(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.deriveArbitraryAccountKey
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0066
    case rustDeriveArbitraryAccountKey(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.importAccountUfvk
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0067
    case rustImportAccountUfvk(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.deriveAddressFromUfvk
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0068
    case rustDeriveAddressFromUfvk(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.createPCZTFromProposal
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0069
    case rustCreatePCZTFromProposal(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.addProofsToPCZT
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0070
    case rustAddProofsToPCZT(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.extractAndStoreTxFromPCZT
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0071
    case rustExtractAndStoreTxFromPCZT(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.getAccount
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0072
    case rustUUIDAccountNotFound(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.extractAndStoreTxFromPCZT
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0073
    case rustTxidPtrIncorrectLength(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.redactPCZTForSigner
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0074
    case rustRedactPCZTForSigner(_ rustError: String)
    /// Error from rust layer when calling AccountMetadatKey.init with a seed.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0075
    case rustDeriveAccountMetadataKey(_ rustError: String)
    /// Error from rust layer when calling AccountMetadatKey.derivePrivateUseMetadataKey
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0076
    case rustDerivePrivateUseMetadataKey(_ rustError: String)
    /// Error from rust layer when calling TorClient.isolatedClient
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0077
    case rustTorIsolatedClient(_ rustError: String)
    /// Error from rust layer when calling TorClient.connectToLightwalletd
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0078
    case rustTorConnectToLightwalletd(_ rustError: String)
    /// Error from rust layer when calling TorLwdConn.fetchTransaction
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0079
    case rustTorLwdFetchTransaction(_ rustError: String)
    /// Error from rust layer when calling TorLwdConn.submit
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0080
    case rustTorLwdSubmit(_ rustError: String)
    /// Error from rust layer when calling TorLwdConn.getInfo
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0081
    case rustTorLwdGetInfo(_ rustError: String)
    /// Error from rust layer when calling TorLwdConn.latestBlockHeight
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0082
    case rustTorLwdLatestBlockHeight(_ rustError: String)
    /// Error from rust layer when calling TorLwdConn.getTreeState
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0083
    case rustTorLwdGetTreeState(_ rustError: String)
    /// Error from rust layer when calling TorClient.httpRequest
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0084
    case rustTorHttpRequest(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.getSingleUseTransparentAddress
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0085
    case rustGetSingleUseTransparentAddress(_ rustError: String)
    /// Single use transparent address generated by rust layer is invalid when calling ZcashRustBackend.getSingleUseTransparentAddress
    /// ZRUST0086
    case rustGetSingleUseTransparentAddressInvalidAddress
    /// Error from rust layer when calling ZcashRustBackend.checkSingleUseTransparentAddresses
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0087
    case rustCheckSingleUseTransparentAddresses(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.updateTransparentAddressTransactions
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0088
    case rustUpdateTransparentAddressTransactions(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.fetchUTXOsByAddress
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0089
    case rustFetchUTXOsByAddress(_ rustError: String)
    /// Error from rust layer when calling ZcashRustBackend.deleteAccount
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0090
    case rustDeleteAccount(_ rustError: String)
    /// Error from rust layer when opening the database handle.
    /// - `rustError` contains error generated by the rust layer.
    /// ZRUST0091
    case rustOpenDb(_ rustError: String)
    /// SQLite query failed when fetching all accounts from the database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZADAO0001
    case accountDAOGetAll(_ sqliteError: Error)
    /// Fetched accounts from SQLite but can't decode them.
    /// - `error` is decoding error.
    /// ZADAO0002
    case accountDAOGetAllCantDecode(_ error: Error)
    /// SQLite query failed when seaching for accounts in the database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZADAO0003
    case accountDAOFindBy(_ sqliteError: Error)
    /// Fetched accounts from SQLite but can't decode them.
    /// - `error` is decoding error.
    /// ZADAO0004
    case accountDAOFindByCantDecode(_ error: Error)
    /// Object passed to update() method conforms to `AccountEntity` protocol but isn't exactly `Account` type.
    /// ZADAO0005
    case accountDAOUpdateInvalidAccount
    /// SQLite query failed when updating account in the database.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZADAO0006
    case accountDAOUpdate(_ sqliteError: Error)
    /// Update of the account updated 0 rows in the database. One row should be updated.
    /// ZADAO0007
    case accountDAOUpdatedZeroRows
    /// Failed to write block to disk.
    /// ZBLRP00001
    case blockRepositoryWriteBlock(_ block: ZcashCompactBlock, _ error: Error)
    /// Failed to get filename for the block from file URL.
    /// ZBLRP0002
    case blockRepositoryGetFilename(_ url: URL)
    /// Failed to parse block height from filename.
    /// ZBLRP0003
    case blockRepositoryParseHeightFromFilename(_ filename: String)
    /// Failed to remove existing block from disk.
    /// ZBLRP0004
    case blockRepositoryRemoveExistingBlock(_ url: URL, _ error: Error)
    /// Failed to get filename and information if url points to directory from file URL.
    /// ZBLRP0005
    case blockRepositoryGetFilenameAndIsDirectory(_ url: URL)
    /// Failed to create blocks cache directory.
    /// ZBLRP0006
    case blockRepositoryCreateBlocksCacheDirectory(_ url: URL, _ error: Error)
    /// Failed to read content of directory.
    /// ZBLRP0007
    case blockRepositoryReadDirectoryContent(_ url: URL, _ error: Error)
    /// Failed to remove block from disk after rewind operation.
    /// ZBLRP0008
    case blockRepositoryRemoveBlockAfterRewind(_ url: URL, _ error: Error)
    /// Failed to remove blocks cache directory while clearing storage.
    /// ZBLRP0009
    case blockRepositoryRemoveBlocksCacheDirectory(_ url: URL, _ error: Error)
    /// Failed to remove block from cache when clearing cache up to some height.
    /// ZBLRP0010
    case blockRepositoryRemoveBlockClearingCache(_ url: URL, _ error: Error)
    /// Trying to download blocks before sync range is set in `BlockDownloaderImpl`. This means that download stream is not created and download cant' start.
    /// ZBDWN0001
    case blockDownloadSyncRangeNotSet
    /// Stream downloading the given block range failed.
    /// ZBDSEO0001
    case blockDownloaderServiceDownloadBlockRange(_ error: Error)
    /// Initialization of `ZcashTransaction.Overview` failed.
    /// ZTEZT0001
    case zcashTransactionOverviewInit(_ error: Error)
    /// Initialization of `ZcashTransaction.Received` failed.
    /// ZTEZT0002
    case zcashTransactionReceivedInit(_ error: Error)
    /// Initialization of `ZcashTransaction.Sent` failed.
    /// ZTEZT0003
    case zcashTransactionSentInit(_ error: Error)
    /// Initialization of `ZcashTransaction.Output` failed.
    /// ZTEZT0004
    case zcashTransactionOutputInit(_ error: Error)
    /// Initialization of `ZcashTransaction.Output` failed because there an inconsistency in the output recipient.
    /// ZTEZT0005
    case zcashTransactionOutputInconsistentRecipient
    /// Entity not found in the database, result of `createEntity` execution.
    /// ZTREE0001
    case transactionRepositoryEntityNotFound
    /// `Find` call is missing fields, required fields are transaction `index` and `blockTime`.
    /// ZTREE0002
    case transactionRepositoryTransactionMissingRequiredFields
    /// Counting all transactions failed.
    /// ZTREE0003
    case transactionRepositoryCountAll(_ error: Error)
    /// Counting all unmined transactions failed.
    /// ZTREE0004
    case transactionRepositoryCountUnmined(_ error: Error)
    /// Execution of a query failed.
    /// ZTREE0005
    case transactionRepositoryQueryExecute(_ error: Error)
    /// Finding memos in the database failed.
    /// ZTREE0006
    case transactionRepositoryFindMemos(_ error: Error)
    /// Can't encode `ZcashCompactBlock` object.
    /// ZCMPB0001
    case compactBlockEncode(_ error: Error)
    /// Invalid UTF-8 Bytes where detected when attempting to create a MemoText.
    /// ZMEMO0001
    case memoTextInvalidUTF8
    /// Trailing null-bytes were found when attempting to create a MemoText.
    /// ZMEMO0002
    case memoTextInputEndsWithNullBytes
    /// The resulting bytes provided are too long to be stored as a MemoText.
    /// ZMEMO0003
    case memoTextInputTooLong(_ length: Int)
    /// The resulting bytes provided are too long to be stored as a MemoBytes.
    /// ZMEMO0004
    case memoBytesInputTooLong(_ length: Int)
    /// Invalid UTF-8 Bytes where detected when attempting to convert MemoBytes to Memo.
    /// ZMEMO0005
    case memoBytesInvalidUTF8
    /// Failed to load JSON with checkpoint from disk.
    /// ZCHKP0001
    case checkpointCantLoadFromDisk(_ error: Error)
    /// Failed to decode `Checkpoint` object.
    /// ZCHKP0002
    case checkpointDecode(_ error: Error)
    /// Creation of the table for unspent transaction output failed.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZUTOD0001
    case unspentTransactionOutputDAOCreateTable(_ sqliteError: Error)
    /// SQLite query failed when storing unspent transaction output.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZUTOD0002
    case unspentTransactionOutputDAOStore(_ sqliteError: Error)
    /// SQLite query failed when removing all the unspent transation outputs.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZUTOD0003
    case unspentTransactionOutputDAOClearAll(_ sqliteError: Error)
    /// Fetched information about unspent transaction output from the DB but it can't be decoded to `UTXO` object.
    /// - `error` decoding error.
    /// ZUTOD0004
    case unspentTransactionOutputDAOGetAllCantDecode(_ error: Error)
    /// SQLite query failed when getting all the unspent transation outputs.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZUTOD0005
    case unspentTransactionOutputDAOGetAll(_ sqliteError: Error)
    /// SQLite query failed when getting balance.
    /// - `sqliteError` is error produced by SQLite library.
    /// ZUTOD0006
    case unspentTransactionOutputDAOBalance(_ sqliteError: Error)
    /// Can't create `SaplingExtendedSpendingKey` because input is invalid.
    /// ZWLTP0001
    case spendingKeyInvalidInput
    /// Can't create `UnifiedFullViewingKey` because input is invalid.
    /// ZWLTP0002
    case unifiedFullViewingKeyInvalidInput
    /// Can't create `SaplingExtendedFullViewingKey` because input is invalid.
    /// ZWLTP0003
    case extetendedFullViewingKeyInvalidInput
    /// Can't create `TransparentAddress` because input is invalid.
    /// ZWLTP0004
    case transparentAddressInvalidInput
    /// Can't create `SaplingAddress` because input is invalid.
    /// ZWLTP0005
    case saplingAddressInvalidInput
    /// Can't create `UnifiedAddress` because input is invalid.
    /// ZWLTP0006
    case unifiedAddressInvalidInput
    /// Can't create `Recipient` because input is invalid.
    /// ZWLTP0007
    case recipientInvalidInput
    /// Can't create `TexAddress` because input is invalid.
    /// ZWLTP0008
    case texAddressInvalidInput
    /// WalletTransactionEncoder wants to create transaction but files with sapling parameters are not present on disk.
    /// ZWLTE0001
    case walletTransEncoderCreateTransactionMissingSaplingParams
    /// WalletTransactionEncoder wants to shield funds but files with sapling parameters are not present on disk.
    /// ZWLTE0002
    case walletTransEncoderShieldFundsMissingSaplingParams
    /// Initiatilzation fo `Zatoshi` from a decoder failed.
    /// ZTSHO0001
    case zatoshiDecode(_ error: Error)
    /// Encode of `Zatoshi` failed.
    /// ZTSHO0002
    case zatoshiEncode(_ error: Error)
    /// Awaiting transactions from the stream failed.
    /// ZUTXO0001
    case unspentTransactionFetcherStream(_ error: Error)
    /// CompactBlockProcessor was started with an invalid configuration.
    /// ZCBPEO0001
    case compactBlockProcessorInvalidConfiguration
    /// CompactBlockProcessor was set up with path but that location couldn't be reached.
    /// ZCBPEO0002
    case compactBlockProcessorMissingDbPath(_ path: String)
    /// Data Db file couldn't be initialized at path.
    /// ZCBPEO0003
    case compactBlockProcessorDataDbInitFailed(_ path: String)
    /// There's a problem with the network connection.
    /// ZCBPEO0004
    case compactBlockProcessorConnection(_ underlyingError: Error)
    /// Error on gRPC happened.
    /// ZCBPEO0005
    case compactBlockProcessorGrpcError(_ statusCode: Int, _ message: String)
    /// Network connection timeout.
    /// ZCBPEO0006
    case compactBlockProcessorConnectionTimeout
    /// Compact Block failed and reached the maximum amount of retries it was set up to do.
    /// ZCBPEO0007
    case compactBlockProcessorMaxAttemptsReached(_ attempts: Int)
    /// Unspecified error occured.
    /// ZCBPEO0008
    case compactBlockProcessorUnspecified(_ underlyingError: Error)
    /// Critical error occured.
    /// ZCBPEO0009
    case compactBlockProcessorCritical
    /// Invalid Account.
    /// ZCBPEO0010
    case compactBlockProcessorInvalidAccount
    /// The remote server you are connecting to is publishing a different branch ID than the one your App is expecting This could be caused by your App being out of date or the server you are connecting you being either on a different network or out of date after a network upgrade.
    /// ZCBPEO0011
    case compactBlockProcessorWrongConsensusBranchId(_ expectedLocally: ConsensusBranchID, _ found: ConsensusBranchID)
    /// A server was reached, but it's targeting the wrong network Type. Make sure you are pointing to the right server.
    /// ZCBPEO0012
    case compactBlockProcessorNetworkMismatch(_ expected: NetworkType, _ found: NetworkType)
    /// A server was reached, it's showing a different sapling activation. Are you sure you are pointing to the right server?
    /// ZCBPEO0013
    case compactBlockProcessorSaplingActivationMismatch(_ expected: BlockHeight, _ found: BlockHeight)
    /// when the given URL is the same URL than the one provided as `self.fsBlockDbRoot` assuming that's a programming error being the `legacyCacheDbURL` a sqlite database file and not a directory
    /// ZCBPEO0014
    case compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL
    /// Deletion of readable file at the provided URL failed.
    /// ZCBPEO0015
    case compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb(_ error: Error)
    /// Chain name does not match. Expected either 'test' or 'main'. This is probably an API or programming error.
    /// ZCBPEO0016
    case compactBlockProcessorChainName(_ name: String)
    /// Consensus BranchIDs don't match this is probably an API or programming error.
    /// ZCBPEO0017
    case compactBlockProcessorConsensusBranchID
    /// Rewind of DownloadBlockAction failed as no action is possible to unwrapp.
    /// ZCBPEO0018
    case compactBlockProcessorDownloadBlockActionRewind
    /// Put sapling subtree roots to the DB failed.
    /// ZCBPEO0019
    case compactBlockProcessorPutSaplingSubtreeRoots(_ error: Error)
    /// Getting the `lastScannedHeight` failed but it's supposed to always provide some value.
    /// ZCBPEO0020
    case compactBlockProcessorLastScannedHeight
    /// Getting the `supportedSyncAlgorithm` failed but it's supposed to always provide some value.
    /// ZCBPEO0021
    case compactBlockProcessorSupportedSyncAlgorithm
    /// Put Orchard subtree roots to the DB failed.
    /// ZCBPEO0022
    case compactBlockProcessorPutOrchardSubtreeRoots(_ error: Error)
    /// The synchronizer is unprepared.
    /// ZSYNCO0001
    case synchronizerNotPrepared
    /// Memos can't be sent to transparent addresses.
    /// ZSYNCO0002
    case synchronizerSendMemoToTransparentAddress
    /// There is not enough transparent funds to cover fee for the shielding.
    /// ZSYNCO0003
    case synchronizerShieldFundsInsuficientTransparentFunds
    /// LatestUTXOs for the address failed, invalid t-address.
    /// ZSYNCO0004
    case synchronizerLatestUTXOsInvalidTAddress
    /// Rewind failed, unknown archor height
    /// ZSYNCO0005
    case synchronizerRewindUnknownArchorHeight
    /// Indicates that this Synchronizer is disconnected from its lightwalletd server.
    /// ZSYNCO0006
    case synchronizerDisconnected
    /// The attempt to switch endpoints failed. Check that the hostname and port are correct, and are formatted as <hostname>:<port>.
    /// ZSYNCO0007
    case synchronizerServerSwitch
    /// The spending key does not belong to the wallet.
    /// ZSYNCO0008
    case synchronizerSpendingKeyDoesNotBelongToTheWallet
    /// Attempt to init TxId with input that is not 32 bytes.
    /// ZMODEL0001
    case txIdNot32Bytes
    /// Attempt to init TxId with invalid hex encoding.
    /// ZMODEL0002
    case txIdInvalidHexEncoding

    public var message: String {
        switch self {
        case .unknown: return "Some error happened that is not handled as `ZcashError`. All errors in the SDK are (should be) `ZcashError`."
        case .initializerCantUpdateURLWithAlias: return "Updating of paths in `Initilizer` according to alias failed."
        case .initializerAliasAlreadyInUse: return "Alias used to create this instance of the `SDKSynchronizer` is already used by other instance."
        case .initializerGeneralStorageExistsButIsFile: return "Object on disk at `generalStorageURL` path exists. But it file not directory."
        case .initializerGeneralStorageCantCreate: return "Can't create directory at `generalStorageURL` path."
        case .initializerCantSetNoBackupFlagToGeneralStorageURL: return "Can't set `isExcludedFromBackup` flag to `generalStorageURL`."
        case .serviceUnknownError: return "Unknown GRPC Service error"
        case .serviceGetInfoFailed: return "LightWalletService.getInfo failed."
        case .serviceLatestBlockFailed: return "LightWalletService.latestBlock failed."
        case .serviceLatestBlockHeightFailed: return "LightWalletService.latestBlockHeight failed."
        case .serviceBlockRangeFailed: return "LightWalletService.blockRange failed."
        case .serviceSubmitFailed: return "LightWalletService.submit failed."
        case .serviceFetchTransactionFailed: return "LightWalletService.fetchTransaction failed."
        case .serviceFetchUTXOsFailed: return "LightWalletService.fetchUTXOs failed."
        case .serviceBlockStreamFailed: return "LightWalletService.blockStream failed."
        case .serviceSubtreeRootsStreamFailed: return "LightWalletService.getSubtreeRoots failed."
        case .serviceGetTaddressTxidsFailed: return "LightWalletService.getTaddressTxids failed."
        case .serviceGetMempoolStreamFailed: return "LightWalletService.getMempoolStream failed."
        case .torServiceMissingEndpoint: return "Endpoint is not provided"
        case .torServiceUnresolvedMode: return "Tor client fails to resolve ServiceMode"
        case .grpcServiceCalledWithTorMode: return "GRPC Service is called with a Tor mode instead of direct one"
        case .torClientUnavailable: return "TorClient is nil"
        case .torNotEnabled: return "TorClient is called but SDKFlags are set as Tor disabled"
        case .simpleConnectionProvider: return "SimpleConnectionProvider init of Connection failed."
        case .saplingParamsInvalidSpendParams: return "Downloaded file with sapling spending parameters isn't valid."
        case .saplingParamsInvalidOutputParams: return "Downloaded file with sapling output parameters isn't valid."
        case .saplingParamsDownload: return "Failed to download sapling parameters file"
        case .saplingParamsCantMoveDownloadedFile: return "Failed to move sapling parameters file to final destination after download."
        case .blockDAOBlock: return "SQLite query failed when fetching block information from database."
        case .blockDAOCantDecode: return "Fetched block information from DB but can't decode them."
        case .blockDAOLatestBlockHeight: return "SQLite query failed when fetching height of the latest block from the database."
        case .blockDAOLatestBlock: return "SQLite query failed when fetching the latest block from the database."
        case .blockDAOLatestBlockCantDecode: return "Fetched latest block information from DB but can't decode them."
        case .blockDAOFirstUnenhancedHeight: return "SQLite query failed when fetching the first unenhanced block from the database."
        case .blockDAOFirstUnenhancedCantDecode: return "Fetched unenhanced block information from DB but can't decode them."
        case .rustCreateAccount: return "Error from rust layer when calling ZcashRustBackend.createAccount"
        case .rustCreateToAddress: return "Error from rust layer when calling ZcashRustBackend.createToAddress"
        case .rustDecryptAndStoreTransaction: return "Error from rust layer when calling ZcashRustBackend.decryptAndStoreTransaction"
        case .rustGetBalance: return "Error from rust layer when calling ZcashRustBackend.getBalance"
        case .rustGetCurrentAddress: return "Error from rust layer when calling ZcashRustBackend.getCurrentAddress"
        case .rustGetCurrentAddressInvalidAddress: return "Unified address generated by rust layer is invalid when calling ZcashRustBackend.getCurrentAddress"
        case .rustGetNearestRewindHeight: return "Error from rust layer when calling ZcashRustBackend.getNearestRewindHeight"
        case .rustGetNextAvailableAddress: return "Error from rust layer when calling ZcashRustBackend.getNextAvailableAddress"
        case .rustGetNextAvailableAddressInvalidAddress: return "Unified address generated by rust layer is invalid when calling ZcashRustBackend.getNextAvailableAddress"
        case .rustGetTransparentBalance: return "Error from rust layer when calling ZcashRustBackend.getTransparentBalance"
        case .rustGetVerifiedBalance: return "Error from rust layer when calling ZcashRustBackend.getVerifiedBalance"
        case .rustGetVerifiedTransparentBalanceNegativeAccount: return "account parameter is lower than 0 when calling ZcashRustBackend.getVerifiedTransparentBalance"
        case .rustGetVerifiedTransparentBalance: return "Error from rust layer when calling ZcashRustBackend.getVerifiedTransparentBalance"
        case .rustInitDataDb: return "Error from rust layer when calling ZcashRustBackend.initDataDb"
        case .rustInitAccountsTableViewingKeyCotainsNullBytes: return "Any of the viewing keys passed to the ZcashRustBackend.initAccountsTable method contains null bytes before end"
        case .rustInitAccountsTableViewingKeyIsInvalid: return "Any of the viewing keys passed to the ZcashRustBackend.initAccountsTable method isn't valid"
        case .rustInitAccountsTableDataDbNotEmpty: return "Error from rust layer when calling ZcashRustBackend.initAccountsTable"
        case .rustInitAccountsTable: return "Error from rust layer when calling ZcashRustBackend.initAccountsTable"
        case .rustInitBlockMetadataDb: return "Error from rust layer when calling ZcashRustBackend.initBlockMetadataDb"
        case .rustWriteBlocksMetadataAllocationProblem: return "Unable to allocate memory required to write blocks when calling ZcashRustBackend.writeBlocksMetadata"
        case .rustWriteBlocksMetadata: return "Error from rust layer when calling ZcashRustBackend.writeBlocksMetadata"
        case .rustInitBlocksTableHashContainsNullBytes: return "hash passed to the ZcashRustBackend.initBlocksTable method contains null bytes before end"
        case .rustInitBlocksTableSaplingTreeContainsNullBytes: return "saplingTree passed to the ZcashRustBackend.initBlocksTable method contains null bytes before end"
        case .rustInitBlocksTableDataDbNotEmpty: return "Error from rust layer when calling ZcashRustBackend.initBlocksTable"
        case .rustInitBlocksTable: return "Error from rust layer when calling ZcashRustBackend.initBlocksTable"
        case .rustListTransparentReceivers: return "Error from rust layer when calling ZcashRustBackend.listTransparentReceivers"
        case .rustListTransparentReceiversInvalidAddress: return "Transparent receiver generated by rust layer is invalid when calling ZcashRustBackend.listTransparentReceivers"
        case .rustPutUnspentTransparentOutput: return "Error from rust layer when calling ZcashRustBackend.putUnspentTransparentOutput"
        case .rustValidateCombinedChainValidationFailed: return "Error unrelated to chain validity from rust layer when calling ZcashRustBackend.validateCombinedChain"
        case .rustRewindToHeight: return "Error from rust layer when calling ZcashRustBackend.rewindToHeight"
        case .rustRewindCacheToHeight: return "Error from rust layer when calling ZcashRustBackend.rewindCacheToHeight"
        case .rustScanBlocks: return "Error from rust layer when calling ZcashRustBackend.scanBlocks"
        case .rustShieldFunds: return "Error from rust layer when calling ZcashRustBackend.shieldFunds"
        case .rustNoConsensusBranchId: return "Error from rust layer when calling ZcashRustBackend.consensusBranchIdFor"
        case .rustReceiverTypecodesOnUnifiedAddressContainsNullBytes: return "address passed to the ZcashRustBackend.receiverTypecodesOnUnifiedAddress method contains null bytes before end"
        case .rustRustReceiverTypecodesOnUnifiedAddressMalformed: return "Error from rust layer when calling ZcashRustBackend.receiverTypecodesOnUnifiedAddress"
        case .rustDeriveUnifiedSpendingKey: return "Error from rust layer when calling ZcashRustBackend.deriveUnifiedSpendingKey"
        case .rustDeriveUnifiedFullViewingKey: return "Error from rust layer when calling ZcashRustBackend.deriveUnifiedFullViewingKey"
        case .rustDeriveUnifiedFullViewingKeyInvalidDerivedKey: return "Viewing key derived by rust layer is invalid when calling ZcashRustBackend.deriveUnifiedFullViewingKey"
        case .rustGetSaplingReceiverInvalidAddress: return "Error from rust layer when calling ZcashRustBackend.getSaplingReceiver"
        case .rustGetSaplingReceiverInvalidReceiver: return "Sapling receiver generated by rust layer is invalid when calling ZcashRustBackend.getSaplingReceiver"
        case .rustGetTransparentReceiverInvalidAddress: return "Error from rust layer when calling ZcashRustBackend.getTransparentReceiver"
        case .rustGetTransparentReceiverInvalidReceiver: return "Transparent receiver generated by rust layer is invalid when calling ZcashRustBackend.getTransparentReceiver"
        case .rustPutSaplingSubtreeRootsAllocationProblem: return "Unable to allocate memory required to write blocks when calling ZcashRustBackend.putSaplingSubtreeRoots"
        case .rustPutSaplingSubtreeRoots: return "Error from rust layer when calling ZcashRustBackend.putSaplingSubtreeRoots"
        case .rustUpdateChainTip: return "Error from rust layer when calling ZcashRustBackend.updateChainTip"
        case .rustSuggestScanRanges: return "Error from rust layer when calling ZcashRustBackend.suggestScanRanges"
        case .rustGetMemoInvalidTxIdLength: return "Invalid transaction ID length when calling ZcashRustBackend.getMemo. txId must be 32 bytes."
        case .rustGetScanProgress: return "Error from rust layer when calling ZcashRustBackend.getScanProgress"
        case .rustFullyScannedHeight: return "Error from rust layer when calling ZcashRustBackend.fullyScannedHeight"
        case .rustMaxScannedHeight: return "Error from rust layer when calling ZcashRustBackend.maxScannedHeight"
        case .rustLatestCachedBlockHeight: return "Error from rust layer when calling ZcashRustBackend.latestCachedBlockHeight"
        case .rustScanProgressOutOfRange: return "Rust layer's call ZcashRustBackend.getScanProgress returned values that after computation are outside of allowed range 0-100%."
        case .rustGetWalletSummary: return "Error from rust layer when calling ZcashRustBackend.getWalletSummary"
        case .rustProposeTransferFromURI: return "Error from rust layer when calling ZcashRustBackend."
        case .rustListAccounts: return "Error from rust layer when calling ZcashRustBackend."
        case .rustIsSeedRelevantToAnyDerivedAccount: return "Error from rust layer when calling ZcashRustBackend.rustIsSeedRelevantToAnyDerivedAccount"
        case .rustPutOrchardSubtreeRootsAllocationProblem: return "Unable to allocate memory required to write blocks when calling ZcashRustBackend.putOrchardSubtreeRoots"
        case .rustPutOrchardSubtreeRoots: return "Error from rust layer when calling ZcashRustBackend.putOrchardSubtreeRoots"
        case .rustTorClientInit: return "Error from rust layer when calling TorClient.init"
        case .rustTorClientGet: return "Error from rust layer when calling TorClient.get"
        case .rustTransactionDataRequests: return "Error from rust layer when calling ZcashRustBackend.transactionDataRequests"
        case .rustDeriveArbitraryWalletKey: return "Error from rust layer when calling ZcashRustBackend.deriveArbitraryWalletKey"
        case .rustDeriveArbitraryAccountKey: return "Error from rust layer when calling ZcashRustBackend.deriveArbitraryAccountKey"
        case .rustImportAccountUfvk: return "Error from rust layer when calling ZcashRustBackend.importAccountUfvk"
        case .rustDeriveAddressFromUfvk: return "Error from rust layer when calling ZcashRustBackend.deriveAddressFromUfvk"
        case .rustCreatePCZTFromProposal: return "Error from rust layer when calling ZcashRustBackend.createPCZTFromProposal"
        case .rustAddProofsToPCZT: return "Error from rust layer when calling ZcashRustBackend.addProofsToPCZT"
        case .rustExtractAndStoreTxFromPCZT: return "Error from rust layer when calling ZcashRustBackend.extractAndStoreTxFromPCZT"
        case .rustUUIDAccountNotFound: return "Error from rust layer when calling ZcashRustBackend.getAccount"
        case .rustTxidPtrIncorrectLength: return "Error from rust layer when calling ZcashRustBackend.extractAndStoreTxFromPCZT"
        case .rustRedactPCZTForSigner: return "Error from rust layer when calling ZcashRustBackend.redactPCZTForSigner"
        case .rustDeriveAccountMetadataKey: return "Error from rust layer when calling AccountMetadatKey.init with a seed."
        case .rustDerivePrivateUseMetadataKey: return "Error from rust layer when calling AccountMetadatKey.derivePrivateUseMetadataKey"
        case .rustTorIsolatedClient: return "Error from rust layer when calling TorClient.isolatedClient"
        case .rustTorConnectToLightwalletd: return "Error from rust layer when calling TorClient.connectToLightwalletd"
        case .rustTorLwdFetchTransaction: return "Error from rust layer when calling TorLwdConn.fetchTransaction"
        case .rustTorLwdSubmit: return "Error from rust layer when calling TorLwdConn.submit"
        case .rustTorLwdGetInfo: return "Error from rust layer when calling TorLwdConn.getInfo"
        case .rustTorLwdLatestBlockHeight: return "Error from rust layer when calling TorLwdConn.latestBlockHeight"
        case .rustTorLwdGetTreeState: return "Error from rust layer when calling TorLwdConn.getTreeState"
        case .rustTorHttpRequest: return "Error from rust layer when calling TorClient.httpRequest"
        case .rustGetSingleUseTransparentAddress: return "Error from rust layer when calling ZcashRustBackend.getSingleUseTransparentAddress"
        case .rustGetSingleUseTransparentAddressInvalidAddress: return "Single use transparent address generated by rust layer is invalid when calling ZcashRustBackend.getSingleUseTransparentAddress"
        case .rustCheckSingleUseTransparentAddresses: return "Error from rust layer when calling ZcashRustBackend.checkSingleUseTransparentAddresses"
        case .rustUpdateTransparentAddressTransactions: return "Error from rust layer when calling ZcashRustBackend.updateTransparentAddressTransactions"
        case .rustFetchUTXOsByAddress: return "Error from rust layer when calling ZcashRustBackend.fetchUTXOsByAddress"
        case .rustDeleteAccount: return "Error from rust layer when calling ZcashRustBackend.deleteAccount"
        case .rustOpenDb: return "Error from rust layer when opening the database handle."
        case .accountDAOGetAll: return "SQLite query failed when fetching all accounts from the database."
        case .accountDAOGetAllCantDecode: return "Fetched accounts from SQLite but can't decode them."
        case .accountDAOFindBy: return "SQLite query failed when seaching for accounts in the database."
        case .accountDAOFindByCantDecode: return "Fetched accounts from SQLite but can't decode them."
        case .accountDAOUpdateInvalidAccount: return "Object passed to update() method conforms to `AccountEntity` protocol but isn't exactly `Account` type."
        case .accountDAOUpdate: return "SQLite query failed when updating account in the database."
        case .accountDAOUpdatedZeroRows: return "Update of the account updated 0 rows in the database. One row should be updated."
        case .blockRepositoryWriteBlock: return "Failed to write block to disk."
        case .blockRepositoryGetFilename: return "Failed to get filename for the block from file URL."
        case .blockRepositoryParseHeightFromFilename: return "Failed to parse block height from filename."
        case .blockRepositoryRemoveExistingBlock: return "Failed to remove existing block from disk."
        case .blockRepositoryGetFilenameAndIsDirectory: return "Failed to get filename and information if url points to directory from file URL."
        case .blockRepositoryCreateBlocksCacheDirectory: return "Failed to create blocks cache directory."
        case .blockRepositoryReadDirectoryContent: return "Failed to read content of directory."
        case .blockRepositoryRemoveBlockAfterRewind: return "Failed to remove block from disk after rewind operation."
        case .blockRepositoryRemoveBlocksCacheDirectory: return "Failed to remove blocks cache directory while clearing storage."
        case .blockRepositoryRemoveBlockClearingCache: return "Failed to remove block from cache when clearing cache up to some height."
        case .blockDownloadSyncRangeNotSet: return "Trying to download blocks before sync range is set in `BlockDownloaderImpl`. This means that download stream is not created and download cant' start."
        case .blockDownloaderServiceDownloadBlockRange: return "Stream downloading the given block range failed."
        case .zcashTransactionOverviewInit: return "Initialization of `ZcashTransaction.Overview` failed."
        case .zcashTransactionReceivedInit: return "Initialization of `ZcashTransaction.Received` failed."
        case .zcashTransactionSentInit: return "Initialization of `ZcashTransaction.Sent` failed."
        case .zcashTransactionOutputInit: return "Initialization of `ZcashTransaction.Output` failed."
        case .zcashTransactionOutputInconsistentRecipient: return "Initialization of `ZcashTransaction.Output` failed because there an inconsistency in the output recipient."
        case .transactionRepositoryEntityNotFound: return "Entity not found in the database, result of `createEntity` execution."
        case .transactionRepositoryTransactionMissingRequiredFields: return "`Find` call is missing fields, required fields are transaction `index` and `blockTime`."
        case .transactionRepositoryCountAll: return "Counting all transactions failed."
        case .transactionRepositoryCountUnmined: return "Counting all unmined transactions failed."
        case .transactionRepositoryQueryExecute: return "Execution of a query failed."
        case .transactionRepositoryFindMemos: return "Finding memos in the database failed."
        case .compactBlockEncode: return "Can't encode `ZcashCompactBlock` object."
        case .memoTextInvalidUTF8: return "Invalid UTF-8 Bytes where detected when attempting to create a MemoText."
        case .memoTextInputEndsWithNullBytes: return "Trailing null-bytes were found when attempting to create a MemoText."
        case .memoTextInputTooLong: return "The resulting bytes provided are too long to be stored as a MemoText."
        case .memoBytesInputTooLong: return "The resulting bytes provided are too long to be stored as a MemoBytes."
        case .memoBytesInvalidUTF8: return "Invalid UTF-8 Bytes where detected when attempting to convert MemoBytes to Memo."
        case .checkpointCantLoadFromDisk: return "Failed to load JSON with checkpoint from disk."
        case .checkpointDecode: return "Failed to decode `Checkpoint` object."
        case .unspentTransactionOutputDAOCreateTable: return "Creation of the table for unspent transaction output failed."
        case .unspentTransactionOutputDAOStore: return "SQLite query failed when storing unspent transaction output."
        case .unspentTransactionOutputDAOClearAll: return "SQLite query failed when removing all the unspent transation outputs."
        case .unspentTransactionOutputDAOGetAllCantDecode: return "Fetched information about unspent transaction output from the DB but it can't be decoded to `UTXO` object."
        case .unspentTransactionOutputDAOGetAll: return "SQLite query failed when getting all the unspent transation outputs."
        case .unspentTransactionOutputDAOBalance: return "SQLite query failed when getting balance."
        case .spendingKeyInvalidInput: return "Can't create `SaplingExtendedSpendingKey` because input is invalid."
        case .unifiedFullViewingKeyInvalidInput: return "Can't create `UnifiedFullViewingKey` because input is invalid."
        case .extetendedFullViewingKeyInvalidInput: return "Can't create `SaplingExtendedFullViewingKey` because input is invalid."
        case .transparentAddressInvalidInput: return "Can't create `TransparentAddress` because input is invalid."
        case .saplingAddressInvalidInput: return "Can't create `SaplingAddress` because input is invalid."
        case .unifiedAddressInvalidInput: return "Can't create `UnifiedAddress` because input is invalid."
        case .recipientInvalidInput: return "Can't create `Recipient` because input is invalid."
        case .texAddressInvalidInput: return "Can't create `TexAddress` because input is invalid."
        case .walletTransEncoderCreateTransactionMissingSaplingParams: return "WalletTransactionEncoder wants to create transaction but files with sapling parameters are not present on disk."
        case .walletTransEncoderShieldFundsMissingSaplingParams: return "WalletTransactionEncoder wants to shield funds but files with sapling parameters are not present on disk."
        case .zatoshiDecode: return "Initiatilzation fo `Zatoshi` from a decoder failed."
        case .zatoshiEncode: return "Encode of `Zatoshi` failed."
        case .unspentTransactionFetcherStream: return "Awaiting transactions from the stream failed."
        case .compactBlockProcessorInvalidConfiguration: return "CompactBlockProcessor was started with an invalid configuration."
        case .compactBlockProcessorMissingDbPath: return "CompactBlockProcessor was set up with path but that location couldn't be reached."
        case .compactBlockProcessorDataDbInitFailed: return "Data Db file couldn't be initialized at path."
        case .compactBlockProcessorConnection: return "There's a problem with the network connection."
        case .compactBlockProcessorGrpcError: return "Error on gRPC happened."
        case .compactBlockProcessorConnectionTimeout: return "Network connection timeout."
        case .compactBlockProcessorMaxAttemptsReached: return "Compact Block failed and reached the maximum amount of retries it was set up to do."
        case .compactBlockProcessorUnspecified: return "Unspecified error occured."
        case .compactBlockProcessorCritical: return "Critical error occured."
        case .compactBlockProcessorInvalidAccount: return "Invalid Account."
        case .compactBlockProcessorWrongConsensusBranchId: return "The remote server you are connecting to is publishing a different branch ID than the one your App is expecting This could be caused by your App being out of date or the server you are connecting you being either on a different network or out of date after a network upgrade."
        case .compactBlockProcessorNetworkMismatch: return "A server was reached, but it's targeting the wrong network Type. Make sure you are pointing to the right server."
        case .compactBlockProcessorSaplingActivationMismatch: return "A server was reached, it's showing a different sapling activation. Are you sure you are pointing to the right server?"
        case .compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL: return "when the given URL is the same URL than the one provided as `self.fsBlockDbRoot` assuming that's a programming error being the `legacyCacheDbURL` a sqlite database file and not a directory"
        case .compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb: return "Deletion of readable file at the provided URL failed."
        case .compactBlockProcessorChainName: return "Chain name does not match. Expected either 'test' or 'main'. This is probably an API or programming error."
        case .compactBlockProcessorConsensusBranchID: return "Consensus BranchIDs don't match this is probably an API or programming error."
        case .compactBlockProcessorDownloadBlockActionRewind: return "Rewind of DownloadBlockAction failed as no action is possible to unwrapp."
        case .compactBlockProcessorPutSaplingSubtreeRoots: return "Put sapling subtree roots to the DB failed."
        case .compactBlockProcessorLastScannedHeight: return "Getting the `lastScannedHeight` failed but it's supposed to always provide some value."
        case .compactBlockProcessorSupportedSyncAlgorithm: return "Getting the `supportedSyncAlgorithm` failed but it's supposed to always provide some value."
        case .compactBlockProcessorPutOrchardSubtreeRoots: return "Put Orchard subtree roots to the DB failed."
        case .synchronizerNotPrepared: return "The synchronizer is unprepared."
        case .synchronizerSendMemoToTransparentAddress: return "Memos can't be sent to transparent addresses."
        case .synchronizerShieldFundsInsuficientTransparentFunds: return "There is not enough transparent funds to cover fee for the shielding."
        case .synchronizerLatestUTXOsInvalidTAddress: return "LatestUTXOs for the address failed, invalid t-address."
        case .synchronizerRewindUnknownArchorHeight: return "Rewind failed, unknown archor height"
        case .synchronizerDisconnected: return "Indicates that this Synchronizer is disconnected from its lightwalletd server."
        case .synchronizerServerSwitch: return "The attempt to switch endpoints failed. Check that the hostname and port are correct, and are formatted as <hostname>:<port>."
        case .synchronizerSpendingKeyDoesNotBelongToTheWallet: return "The spending key does not belong to the wallet."
        case .txIdNot32Bytes: return "Attempt to init TxId with input that is not 32 bytes."
        case .txIdInvalidHexEncoding: return "Attempt to init TxId with invalid hex encoding."
        }
    }

    public var code: ZcashErrorCode {
        switch self {
        case .unknown: return .unknown
        case .initializerCantUpdateURLWithAlias: return .initializerCantUpdateURLWithAlias
        case .initializerAliasAlreadyInUse: return .initializerAliasAlreadyInUse
        case .initializerGeneralStorageExistsButIsFile: return .initializerGeneralStorageExistsButIsFile
        case .initializerGeneralStorageCantCreate: return .initializerGeneralStorageCantCreate
        case .initializerCantSetNoBackupFlagToGeneralStorageURL: return .initializerCantSetNoBackupFlagToGeneralStorageURL
        case .serviceUnknownError: return .serviceUnknownError
        case .serviceGetInfoFailed: return .serviceGetInfoFailed
        case .serviceLatestBlockFailed: return .serviceLatestBlockFailed
        case .serviceLatestBlockHeightFailed: return .serviceLatestBlockHeightFailed
        case .serviceBlockRangeFailed: return .serviceBlockRangeFailed
        case .serviceSubmitFailed: return .serviceSubmitFailed
        case .serviceFetchTransactionFailed: return .serviceFetchTransactionFailed
        case .serviceFetchUTXOsFailed: return .serviceFetchUTXOsFailed
        case .serviceBlockStreamFailed: return .serviceBlockStreamFailed
        case .serviceSubtreeRootsStreamFailed: return .serviceSubtreeRootsStreamFailed
        case .serviceGetTaddressTxidsFailed: return .serviceGetTaddressTxidsFailed
        case .serviceGetMempoolStreamFailed: return .serviceGetMempoolStreamFailed
        case .torServiceMissingEndpoint: return .torServiceMissingEndpoint
        case .torServiceUnresolvedMode: return .torServiceUnresolvedMode
        case .grpcServiceCalledWithTorMode: return .grpcServiceCalledWithTorMode
        case .torClientUnavailable: return .torClientUnavailable
        case .torNotEnabled: return .torNotEnabled
        case .simpleConnectionProvider: return .simpleConnectionProvider
        case .saplingParamsInvalidSpendParams: return .saplingParamsInvalidSpendParams
        case .saplingParamsInvalidOutputParams: return .saplingParamsInvalidOutputParams
        case .saplingParamsDownload: return .saplingParamsDownload
        case .saplingParamsCantMoveDownloadedFile: return .saplingParamsCantMoveDownloadedFile
        case .blockDAOBlock: return .blockDAOBlock
        case .blockDAOCantDecode: return .blockDAOCantDecode
        case .blockDAOLatestBlockHeight: return .blockDAOLatestBlockHeight
        case .blockDAOLatestBlock: return .blockDAOLatestBlock
        case .blockDAOLatestBlockCantDecode: return .blockDAOLatestBlockCantDecode
        case .blockDAOFirstUnenhancedHeight: return .blockDAOFirstUnenhancedHeight
        case .blockDAOFirstUnenhancedCantDecode: return .blockDAOFirstUnenhancedCantDecode
        case .rustCreateAccount: return .rustCreateAccount
        case .rustCreateToAddress: return .rustCreateToAddress
        case .rustDecryptAndStoreTransaction: return .rustDecryptAndStoreTransaction
        case .rustGetBalance: return .rustGetBalance
        case .rustGetCurrentAddress: return .rustGetCurrentAddress
        case .rustGetCurrentAddressInvalidAddress: return .rustGetCurrentAddressInvalidAddress
        case .rustGetNearestRewindHeight: return .rustGetNearestRewindHeight
        case .rustGetNextAvailableAddress: return .rustGetNextAvailableAddress
        case .rustGetNextAvailableAddressInvalidAddress: return .rustGetNextAvailableAddressInvalidAddress
        case .rustGetTransparentBalance: return .rustGetTransparentBalance
        case .rustGetVerifiedBalance: return .rustGetVerifiedBalance
        case .rustGetVerifiedTransparentBalanceNegativeAccount: return .rustGetVerifiedTransparentBalanceNegativeAccount
        case .rustGetVerifiedTransparentBalance: return .rustGetVerifiedTransparentBalance
        case .rustInitDataDb: return .rustInitDataDb
        case .rustInitAccountsTableViewingKeyCotainsNullBytes: return .rustInitAccountsTableViewingKeyCotainsNullBytes
        case .rustInitAccountsTableViewingKeyIsInvalid: return .rustInitAccountsTableViewingKeyIsInvalid
        case .rustInitAccountsTableDataDbNotEmpty: return .rustInitAccountsTableDataDbNotEmpty
        case .rustInitAccountsTable: return .rustInitAccountsTable
        case .rustInitBlockMetadataDb: return .rustInitBlockMetadataDb
        case .rustWriteBlocksMetadataAllocationProblem: return .rustWriteBlocksMetadataAllocationProblem
        case .rustWriteBlocksMetadata: return .rustWriteBlocksMetadata
        case .rustInitBlocksTableHashContainsNullBytes: return .rustInitBlocksTableHashContainsNullBytes
        case .rustInitBlocksTableSaplingTreeContainsNullBytes: return .rustInitBlocksTableSaplingTreeContainsNullBytes
        case .rustInitBlocksTableDataDbNotEmpty: return .rustInitBlocksTableDataDbNotEmpty
        case .rustInitBlocksTable: return .rustInitBlocksTable
        case .rustListTransparentReceivers: return .rustListTransparentReceivers
        case .rustListTransparentReceiversInvalidAddress: return .rustListTransparentReceiversInvalidAddress
        case .rustPutUnspentTransparentOutput: return .rustPutUnspentTransparentOutput
        case .rustValidateCombinedChainValidationFailed: return .rustValidateCombinedChainValidationFailed
        case .rustRewindToHeight: return .rustRewindToHeight
        case .rustRewindCacheToHeight: return .rustRewindCacheToHeight
        case .rustScanBlocks: return .rustScanBlocks
        case .rustShieldFunds: return .rustShieldFunds
        case .rustNoConsensusBranchId: return .rustNoConsensusBranchId
        case .rustReceiverTypecodesOnUnifiedAddressContainsNullBytes: return .rustReceiverTypecodesOnUnifiedAddressContainsNullBytes
        case .rustRustReceiverTypecodesOnUnifiedAddressMalformed: return .rustRustReceiverTypecodesOnUnifiedAddressMalformed
        case .rustDeriveUnifiedSpendingKey: return .rustDeriveUnifiedSpendingKey
        case .rustDeriveUnifiedFullViewingKey: return .rustDeriveUnifiedFullViewingKey
        case .rustDeriveUnifiedFullViewingKeyInvalidDerivedKey: return .rustDeriveUnifiedFullViewingKeyInvalidDerivedKey
        case .rustGetSaplingReceiverInvalidAddress: return .rustGetSaplingReceiverInvalidAddress
        case .rustGetSaplingReceiverInvalidReceiver: return .rustGetSaplingReceiverInvalidReceiver
        case .rustGetTransparentReceiverInvalidAddress: return .rustGetTransparentReceiverInvalidAddress
        case .rustGetTransparentReceiverInvalidReceiver: return .rustGetTransparentReceiverInvalidReceiver
        case .rustPutSaplingSubtreeRootsAllocationProblem: return .rustPutSaplingSubtreeRootsAllocationProblem
        case .rustPutSaplingSubtreeRoots: return .rustPutSaplingSubtreeRoots
        case .rustUpdateChainTip: return .rustUpdateChainTip
        case .rustSuggestScanRanges: return .rustSuggestScanRanges
        case .rustGetMemoInvalidTxIdLength: return .rustGetMemoInvalidTxIdLength
        case .rustGetScanProgress: return .rustGetScanProgress
        case .rustFullyScannedHeight: return .rustFullyScannedHeight
        case .rustMaxScannedHeight: return .rustMaxScannedHeight
        case .rustLatestCachedBlockHeight: return .rustLatestCachedBlockHeight
        case .rustScanProgressOutOfRange: return .rustScanProgressOutOfRange
        case .rustGetWalletSummary: return .rustGetWalletSummary
        case .rustProposeTransferFromURI: return .rustProposeTransferFromURI
        case .rustListAccounts: return .rustListAccounts
        case .rustIsSeedRelevantToAnyDerivedAccount: return .rustIsSeedRelevantToAnyDerivedAccount
        case .rustPutOrchardSubtreeRootsAllocationProblem: return .rustPutOrchardSubtreeRootsAllocationProblem
        case .rustPutOrchardSubtreeRoots: return .rustPutOrchardSubtreeRoots
        case .rustTorClientInit: return .rustTorClientInit
        case .rustTorClientGet: return .rustTorClientGet
        case .rustTransactionDataRequests: return .rustTransactionDataRequests
        case .rustDeriveArbitraryWalletKey: return .rustDeriveArbitraryWalletKey
        case .rustDeriveArbitraryAccountKey: return .rustDeriveArbitraryAccountKey
        case .rustImportAccountUfvk: return .rustImportAccountUfvk
        case .rustDeriveAddressFromUfvk: return .rustDeriveAddressFromUfvk
        case .rustCreatePCZTFromProposal: return .rustCreatePCZTFromProposal
        case .rustAddProofsToPCZT: return .rustAddProofsToPCZT
        case .rustExtractAndStoreTxFromPCZT: return .rustExtractAndStoreTxFromPCZT
        case .rustUUIDAccountNotFound: return .rustUUIDAccountNotFound
        case .rustTxidPtrIncorrectLength: return .rustTxidPtrIncorrectLength
        case .rustRedactPCZTForSigner: return .rustRedactPCZTForSigner
        case .rustDeriveAccountMetadataKey: return .rustDeriveAccountMetadataKey
        case .rustDerivePrivateUseMetadataKey: return .rustDerivePrivateUseMetadataKey
        case .rustTorIsolatedClient: return .rustTorIsolatedClient
        case .rustTorConnectToLightwalletd: return .rustTorConnectToLightwalletd
        case .rustTorLwdFetchTransaction: return .rustTorLwdFetchTransaction
        case .rustTorLwdSubmit: return .rustTorLwdSubmit
        case .rustTorLwdGetInfo: return .rustTorLwdGetInfo
        case .rustTorLwdLatestBlockHeight: return .rustTorLwdLatestBlockHeight
        case .rustTorLwdGetTreeState: return .rustTorLwdGetTreeState
        case .rustTorHttpRequest: return .rustTorHttpRequest
        case .rustGetSingleUseTransparentAddress: return .rustGetSingleUseTransparentAddress
        case .rustGetSingleUseTransparentAddressInvalidAddress: return .rustGetSingleUseTransparentAddressInvalidAddress
        case .rustCheckSingleUseTransparentAddresses: return .rustCheckSingleUseTransparentAddresses
        case .rustUpdateTransparentAddressTransactions: return .rustUpdateTransparentAddressTransactions
        case .rustFetchUTXOsByAddress: return .rustFetchUTXOsByAddress
        case .rustDeleteAccount: return .rustDeleteAccount
        case .rustOpenDb: return .rustOpenDb
        case .accountDAOGetAll: return .accountDAOGetAll
        case .accountDAOGetAllCantDecode: return .accountDAOGetAllCantDecode
        case .accountDAOFindBy: return .accountDAOFindBy
        case .accountDAOFindByCantDecode: return .accountDAOFindByCantDecode
        case .accountDAOUpdateInvalidAccount: return .accountDAOUpdateInvalidAccount
        case .accountDAOUpdate: return .accountDAOUpdate
        case .accountDAOUpdatedZeroRows: return .accountDAOUpdatedZeroRows
        case .blockRepositoryWriteBlock: return .blockRepositoryWriteBlock
        case .blockRepositoryGetFilename: return .blockRepositoryGetFilename
        case .blockRepositoryParseHeightFromFilename: return .blockRepositoryParseHeightFromFilename
        case .blockRepositoryRemoveExistingBlock: return .blockRepositoryRemoveExistingBlock
        case .blockRepositoryGetFilenameAndIsDirectory: return .blockRepositoryGetFilenameAndIsDirectory
        case .blockRepositoryCreateBlocksCacheDirectory: return .blockRepositoryCreateBlocksCacheDirectory
        case .blockRepositoryReadDirectoryContent: return .blockRepositoryReadDirectoryContent
        case .blockRepositoryRemoveBlockAfterRewind: return .blockRepositoryRemoveBlockAfterRewind
        case .blockRepositoryRemoveBlocksCacheDirectory: return .blockRepositoryRemoveBlocksCacheDirectory
        case .blockRepositoryRemoveBlockClearingCache: return .blockRepositoryRemoveBlockClearingCache
        case .blockDownloadSyncRangeNotSet: return .blockDownloadSyncRangeNotSet
        case .blockDownloaderServiceDownloadBlockRange: return .blockDownloaderServiceDownloadBlockRange
        case .zcashTransactionOverviewInit: return .zcashTransactionOverviewInit
        case .zcashTransactionReceivedInit: return .zcashTransactionReceivedInit
        case .zcashTransactionSentInit: return .zcashTransactionSentInit
        case .zcashTransactionOutputInit: return .zcashTransactionOutputInit
        case .zcashTransactionOutputInconsistentRecipient: return .zcashTransactionOutputInconsistentRecipient
        case .transactionRepositoryEntityNotFound: return .transactionRepositoryEntityNotFound
        case .transactionRepositoryTransactionMissingRequiredFields: return .transactionRepositoryTransactionMissingRequiredFields
        case .transactionRepositoryCountAll: return .transactionRepositoryCountAll
        case .transactionRepositoryCountUnmined: return .transactionRepositoryCountUnmined
        case .transactionRepositoryQueryExecute: return .transactionRepositoryQueryExecute
        case .transactionRepositoryFindMemos: return .transactionRepositoryFindMemos
        case .compactBlockEncode: return .compactBlockEncode
        case .memoTextInvalidUTF8: return .memoTextInvalidUTF8
        case .memoTextInputEndsWithNullBytes: return .memoTextInputEndsWithNullBytes
        case .memoTextInputTooLong: return .memoTextInputTooLong
        case .memoBytesInputTooLong: return .memoBytesInputTooLong
        case .memoBytesInvalidUTF8: return .memoBytesInvalidUTF8
        case .checkpointCantLoadFromDisk: return .checkpointCantLoadFromDisk
        case .checkpointDecode: return .checkpointDecode
        case .unspentTransactionOutputDAOCreateTable: return .unspentTransactionOutputDAOCreateTable
        case .unspentTransactionOutputDAOStore: return .unspentTransactionOutputDAOStore
        case .unspentTransactionOutputDAOClearAll: return .unspentTransactionOutputDAOClearAll
        case .unspentTransactionOutputDAOGetAllCantDecode: return .unspentTransactionOutputDAOGetAllCantDecode
        case .unspentTransactionOutputDAOGetAll: return .unspentTransactionOutputDAOGetAll
        case .unspentTransactionOutputDAOBalance: return .unspentTransactionOutputDAOBalance
        case .spendingKeyInvalidInput: return .spendingKeyInvalidInput
        case .unifiedFullViewingKeyInvalidInput: return .unifiedFullViewingKeyInvalidInput
        case .extetendedFullViewingKeyInvalidInput: return .extetendedFullViewingKeyInvalidInput
        case .transparentAddressInvalidInput: return .transparentAddressInvalidInput
        case .saplingAddressInvalidInput: return .saplingAddressInvalidInput
        case .unifiedAddressInvalidInput: return .unifiedAddressInvalidInput
        case .recipientInvalidInput: return .recipientInvalidInput
        case .texAddressInvalidInput: return .texAddressInvalidInput
        case .walletTransEncoderCreateTransactionMissingSaplingParams: return .walletTransEncoderCreateTransactionMissingSaplingParams
        case .walletTransEncoderShieldFundsMissingSaplingParams: return .walletTransEncoderShieldFundsMissingSaplingParams
        case .zatoshiDecode: return .zatoshiDecode
        case .zatoshiEncode: return .zatoshiEncode
        case .unspentTransactionFetcherStream: return .unspentTransactionFetcherStream
        case .compactBlockProcessorInvalidConfiguration: return .compactBlockProcessorInvalidConfiguration
        case .compactBlockProcessorMissingDbPath: return .compactBlockProcessorMissingDbPath
        case .compactBlockProcessorDataDbInitFailed: return .compactBlockProcessorDataDbInitFailed
        case .compactBlockProcessorConnection: return .compactBlockProcessorConnection
        case .compactBlockProcessorGrpcError: return .compactBlockProcessorGrpcError
        case .compactBlockProcessorConnectionTimeout: return .compactBlockProcessorConnectionTimeout
        case .compactBlockProcessorMaxAttemptsReached: return .compactBlockProcessorMaxAttemptsReached
        case .compactBlockProcessorUnspecified: return .compactBlockProcessorUnspecified
        case .compactBlockProcessorCritical: return .compactBlockProcessorCritical
        case .compactBlockProcessorInvalidAccount: return .compactBlockProcessorInvalidAccount
        case .compactBlockProcessorWrongConsensusBranchId: return .compactBlockProcessorWrongConsensusBranchId
        case .compactBlockProcessorNetworkMismatch: return .compactBlockProcessorNetworkMismatch
        case .compactBlockProcessorSaplingActivationMismatch: return .compactBlockProcessorSaplingActivationMismatch
        case .compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL: return .compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL
        case .compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb: return .compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb
        case .compactBlockProcessorChainName: return .compactBlockProcessorChainName
        case .compactBlockProcessorConsensusBranchID: return .compactBlockProcessorConsensusBranchID
        case .compactBlockProcessorDownloadBlockActionRewind: return .compactBlockProcessorDownloadBlockActionRewind
        case .compactBlockProcessorPutSaplingSubtreeRoots: return .compactBlockProcessorPutSaplingSubtreeRoots
        case .compactBlockProcessorLastScannedHeight: return .compactBlockProcessorLastScannedHeight
        case .compactBlockProcessorSupportedSyncAlgorithm: return .compactBlockProcessorSupportedSyncAlgorithm
        case .compactBlockProcessorPutOrchardSubtreeRoots: return .compactBlockProcessorPutOrchardSubtreeRoots
        case .synchronizerNotPrepared: return .synchronizerNotPrepared
        case .synchronizerSendMemoToTransparentAddress: return .synchronizerSendMemoToTransparentAddress
        case .synchronizerShieldFundsInsuficientTransparentFunds: return .synchronizerShieldFundsInsuficientTransparentFunds
        case .synchronizerLatestUTXOsInvalidTAddress: return .synchronizerLatestUTXOsInvalidTAddress
        case .synchronizerRewindUnknownArchorHeight: return .synchronizerRewindUnknownArchorHeight
        case .synchronizerDisconnected: return .synchronizerDisconnected
        case .synchronizerServerSwitch: return .synchronizerServerSwitch
        case .synchronizerSpendingKeyDoesNotBelongToTheWallet: return .synchronizerSpendingKeyDoesNotBelongToTheWallet
        case .txIdNot32Bytes: return .txIdNot32Bytes
        case .txIdInvalidHexEncoding: return .txIdInvalidHexEncoding
        }
    }

    public static func == (lhs: ZcashError, rhs: ZcashError) -> Bool {
        return lhs.code == rhs.code
    }
}
