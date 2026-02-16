// Generated using Sourcery 2.3.0 — https://github.com/krzysztofzablocki/Sourcery
// DO NOT EDIT

/*
!!!!! To edit this file go to ZcashErrorCodeDefinition first and udate/add codes. Then run generateErrorCode.sh script to regenerate this file.

By design each error code should be used only at one place in the app. Thanks to that it is possible to identify exact line in the code from which the
error originates. And it can help with debugging.
*/

public enum ZcashErrorCode: String {
    /// Some error happened that is not handled as `ZcashError`. All errors in the SDK are (should be) `ZcashError`.
    case unknown = "ZUNKWN0001"
    /// Updating of paths in `Initilizer` according to alias failed.
    case initializerCantUpdateURLWithAlias = "ZINIT0001"
    /// Alias used to create this instance of the `SDKSynchronizer` is already used by other instance.
    case initializerAliasAlreadyInUse = "ZINIT0002"
    /// Object on disk at `generalStorageURL` path exists. But it file not directory.
    case initializerGeneralStorageExistsButIsFile = "ZINIT0003"
    /// Can't create directory at `generalStorageURL` path.
    case initializerGeneralStorageCantCreate = "ZINIT0004"
    /// Can't set `isExcludedFromBackup` flag to `generalStorageURL`.
    case initializerCantSetNoBackupFlagToGeneralStorageURL = "ZINIT0005"
    /// Unknown GRPC Service error
    case serviceUnknownError = "ZSRVC0001"
    /// LightWalletService.getInfo failed.
    case serviceGetInfoFailed = "ZSRVC0002"
    /// LightWalletService.latestBlock failed.
    case serviceLatestBlockFailed = "ZSRVC0003"
    /// LightWalletService.latestBlockHeight failed.
    case serviceLatestBlockHeightFailed = "ZSRVC0004"
    /// LightWalletService.blockRange failed.
    case serviceBlockRangeFailed = "ZSRVC0005"
    /// LightWalletService.submit failed.
    case serviceSubmitFailed = "ZSRVC0006"
    /// LightWalletService.fetchTransaction failed.
    case serviceFetchTransactionFailed = "ZSRVC0007"
    /// LightWalletService.fetchUTXOs failed.
    case serviceFetchUTXOsFailed = "ZSRVC0008"
    /// LightWalletService.blockStream failed.
    case serviceBlockStreamFailed = "ZSRVC0000"
    /// LightWalletService.getSubtreeRoots failed.
    case serviceSubtreeRootsStreamFailed = "ZSRVC0009"
    /// LightWalletService.getTaddressTxids failed.
    case serviceGetTaddressTxidsFailed = "ZSRVC0010"
    /// LightWalletService.getMempoolStream failed.
    case serviceGetMempoolStreamFailed = "ZSRVC0011"
    /// Endpoint is not provided
    case torServiceMissingEndpoint = "ZTSRV0001"
    /// Tor client fails to resolve ServiceMode
    case torServiceUnresolvedMode = "ZTSRV0002"
    /// GRPC Service is called with a Tor mode instead of direct one
    case grpcServiceCalledWithTorMode = "ZTSRV0003"
    /// TorClient is nil
    case torClientUnavailable = "ZTSRV0004"
    /// TorClient is called but SDKFlags are set as Tor disabled
    case torNotEnabled = "ZTSRV0005"
    /// SimpleConnectionProvider init of Connection failed.
    case simpleConnectionProvider = "ZSCPC0001"
    /// Downloaded file with sapling spending parameters isn't valid.
    case saplingParamsInvalidSpendParams = "ZSAPP0001"
    /// Downloaded file with sapling output parameters isn't valid.
    case saplingParamsInvalidOutputParams = "ZSAPP0002"
    /// Failed to download sapling parameters file
    case saplingParamsDownload = "ZSAPP0003"
    /// Failed to move sapling parameters file to final destination after download.
    case saplingParamsCantMoveDownloadedFile = "ZSAPP0004"
    /// SQLite query failed when fetching block information from database.
    case blockDAOBlock = "ZBDAO0001"
    /// Fetched block information from DB but can't decode them.
    case blockDAOCantDecode = "ZBDAO0002"
    /// SQLite query failed when fetching height of the latest block from the database.
    case blockDAOLatestBlockHeight = "ZBDAO0003"
    /// SQLite query failed when fetching the latest block from the database.
    case blockDAOLatestBlock = "ZBDAO0004"
    /// Fetched latest block information from DB but can't decode them.
    case blockDAOLatestBlockCantDecode = "ZBDAO0005"
    /// SQLite query failed when fetching the first unenhanced block from the database.
    case blockDAOFirstUnenhancedHeight = "ZBDAO0006"
    /// Fetched unenhanced block information from DB but can't decode them.
    case blockDAOFirstUnenhancedCantDecode = "ZBDAO0007"
    /// Error from rust layer when calling ZcashRustBackend.createAccount
    case rustCreateAccount = "ZRUST0001"
    /// Error from rust layer when calling ZcashRustBackend.createToAddress
    case rustCreateToAddress = "ZRUST0002"
    /// Error from rust layer when calling ZcashRustBackend.decryptAndStoreTransaction
    case rustDecryptAndStoreTransaction = "ZRUST0003"
    /// Error from rust layer when calling ZcashRustBackend.getBalance
    case rustGetBalance = "ZRUST0004"
    /// Error from rust layer when calling ZcashRustBackend.getCurrentAddress
    case rustGetCurrentAddress = "ZRUST0005"
    /// Unified address generated by rust layer is invalid when calling ZcashRustBackend.getCurrentAddress
    case rustGetCurrentAddressInvalidAddress = "ZRUST0006"
    /// Error from rust layer when calling ZcashRustBackend.getNearestRewindHeight
    case rustGetNearestRewindHeight = "ZRUST0007"
    /// Error from rust layer when calling ZcashRustBackend.getNextAvailableAddress
    case rustGetNextAvailableAddress = "ZRUST0008"
    /// Unified address generated by rust layer is invalid when calling ZcashRustBackend.getNextAvailableAddress
    case rustGetNextAvailableAddressInvalidAddress = "ZRUST0009"
    /// Error from rust layer when calling ZcashRustBackend.getTransparentBalance
    case rustGetTransparentBalance = "ZRUST0011"
    /// Error from rust layer when calling ZcashRustBackend.getVerifiedBalance
    case rustGetVerifiedBalance = "ZRUST0012"
    /// account parameter is lower than 0 when calling ZcashRustBackend.getVerifiedTransparentBalance
    case rustGetVerifiedTransparentBalanceNegativeAccount = "ZRUST0013"
    /// Error from rust layer when calling ZcashRustBackend.getVerifiedTransparentBalance
    case rustGetVerifiedTransparentBalance = "ZRUST0014"
    /// Error from rust layer when calling ZcashRustBackend.initDataDb
    case rustInitDataDb = "ZRUST0015"
    /// Any of the viewing keys passed to the ZcashRustBackend.initAccountsTable method contains null bytes before end
    case rustInitAccountsTableViewingKeyCotainsNullBytes = "ZRUST0016"
    /// Any of the viewing keys passed to the ZcashRustBackend.initAccountsTable method isn't valid
    case rustInitAccountsTableViewingKeyIsInvalid = "ZRUST0017"
    /// Error from rust layer when calling ZcashRustBackend.initAccountsTable
    case rustInitAccountsTableDataDbNotEmpty = "ZRUST0018"
    /// Error from rust layer when calling ZcashRustBackend.initAccountsTable
    case rustInitAccountsTable = "ZRUST0019"
    /// Error from rust layer when calling ZcashRustBackend.initBlockMetadataDb
    case rustInitBlockMetadataDb = "ZRUST0020"
    /// Unable to allocate memory required to write blocks when calling ZcashRustBackend.writeBlocksMetadata
    case rustWriteBlocksMetadataAllocationProblem = "ZRUST0021"
    /// Error from rust layer when calling ZcashRustBackend.writeBlocksMetadata
    case rustWriteBlocksMetadata = "ZRUST0022"
    /// hash passed to the ZcashRustBackend.initBlocksTable method contains null bytes before end
    case rustInitBlocksTableHashContainsNullBytes = "ZRUST0023"
    /// saplingTree passed to the ZcashRustBackend.initBlocksTable method contains null bytes before end
    case rustInitBlocksTableSaplingTreeContainsNullBytes = "ZRUST0024"
    /// Error from rust layer when calling ZcashRustBackend.initBlocksTable
    case rustInitBlocksTableDataDbNotEmpty = "ZRUST0025"
    /// Error from rust layer when calling ZcashRustBackend.initBlocksTable
    case rustInitBlocksTable = "ZRUST0026"
    /// Error from rust layer when calling ZcashRustBackend.listTransparentReceivers
    case rustListTransparentReceivers = "ZRUST0027"
    /// Transparent receiver generated by rust layer is invalid when calling ZcashRustBackend.listTransparentReceivers
    case rustListTransparentReceiversInvalidAddress = "ZRUST0028"
    /// Error from rust layer when calling ZcashRustBackend.putUnspentTransparentOutput
    case rustPutUnspentTransparentOutput = "ZRUST0029"
    /// Error unrelated to chain validity from rust layer when calling ZcashRustBackend.validateCombinedChain
    case rustValidateCombinedChainValidationFailed = "ZRUST0030"
    /// Error from rust layer when calling ZcashRustBackend.rewindToHeight
    case rustRewindToHeight = "ZRUST0032"
    /// Error from rust layer when calling ZcashRustBackend.rewindCacheToHeight
    case rustRewindCacheToHeight = "ZRUST0033"
    /// Error from rust layer when calling ZcashRustBackend.scanBlocks
    case rustScanBlocks = "ZRUST0034"
    /// Error from rust layer when calling ZcashRustBackend.shieldFunds
    case rustShieldFunds = "ZRUST0035"
    /// Error from rust layer when calling ZcashRustBackend.consensusBranchIdFor
    case rustNoConsensusBranchId = "ZRUST0036"
    /// address passed to the ZcashRustBackend.receiverTypecodesOnUnifiedAddress method contains null bytes before end
    case rustReceiverTypecodesOnUnifiedAddressContainsNullBytes = "ZRUST0037"
    /// Error from rust layer when calling ZcashRustBackend.receiverTypecodesOnUnifiedAddress
    case rustRustReceiverTypecodesOnUnifiedAddressMalformed = "ZRUST0038"
    /// Error from rust layer when calling ZcashRustBackend.deriveUnifiedSpendingKey
    case rustDeriveUnifiedSpendingKey = "ZRUST0039"
    /// Error from rust layer when calling ZcashRustBackend.deriveUnifiedFullViewingKey
    case rustDeriveUnifiedFullViewingKey = "ZRUST0040"
    /// Viewing key derived by rust layer is invalid when calling ZcashRustBackend.deriveUnifiedFullViewingKey
    case rustDeriveUnifiedFullViewingKeyInvalidDerivedKey = "ZRUST0041"
    /// Error from rust layer when calling ZcashRustBackend.getSaplingReceiver
    case rustGetSaplingReceiverInvalidAddress = "ZRUST0042"
    /// Sapling receiver generated by rust layer is invalid when calling ZcashRustBackend.getSaplingReceiver
    case rustGetSaplingReceiverInvalidReceiver = "ZRUST0043"
    /// Error from rust layer when calling ZcashRustBackend.getTransparentReceiver
    case rustGetTransparentReceiverInvalidAddress = "ZRUST0044"
    /// Transparent receiver generated by rust layer is invalid when calling ZcashRustBackend.getTransparentReceiver
    case rustGetTransparentReceiverInvalidReceiver = "ZRUST0045"
    /// Unable to allocate memory required to write blocks when calling ZcashRustBackend.putSaplingSubtreeRoots
    case rustPutSaplingSubtreeRootsAllocationProblem = "ZRUST0046"
    /// Error from rust layer when calling ZcashRustBackend.putSaplingSubtreeRoots
    case rustPutSaplingSubtreeRoots = "ZRUST0047"
    /// Error from rust layer when calling ZcashRustBackend.updateChainTip
    case rustUpdateChainTip = "ZRUST0048"
    /// Error from rust layer when calling ZcashRustBackend.suggestScanRanges
    case rustSuggestScanRanges = "ZRUST0049"
    /// Invalid transaction ID length when calling ZcashRustBackend.getMemo. txId must be 32 bytes.
    case rustGetMemoInvalidTxIdLength = "ZRUST0050"
    /// Error from rust layer when calling ZcashRustBackend.getScanProgress
    case rustGetScanProgress = "ZRUST0051"
    /// Error from rust layer when calling ZcashRustBackend.fullyScannedHeight
    case rustFullyScannedHeight = "ZRUST0052"
    /// Error from rust layer when calling ZcashRustBackend.maxScannedHeight
    case rustMaxScannedHeight = "ZRUST0053"
    /// Error from rust layer when calling ZcashRustBackend.latestCachedBlockHeight
    case rustLatestCachedBlockHeight = "ZRUST0054"
    /// Rust layer's call ZcashRustBackend.getScanProgress returned values that after computation are outside of allowed range 0-100%.
    case rustScanProgressOutOfRange = "ZRUST0055"
    /// Error from rust layer when calling ZcashRustBackend.getWalletSummary
    case rustGetWalletSummary = "ZRUST0056"
    /// Error from rust layer when calling ZcashRustBackend.
    case rustProposeTransferFromURI = "ZRUST0057"
    /// Error from rust layer when calling ZcashRustBackend.
    case rustListAccounts = "ZRUST0058"
    /// Error from rust layer when calling ZcashRustBackend.rustIsSeedRelevantToAnyDerivedAccount
    case rustIsSeedRelevantToAnyDerivedAccount = "ZRUST0059"
    /// Unable to allocate memory required to write blocks when calling ZcashRustBackend.putOrchardSubtreeRoots
    case rustPutOrchardSubtreeRootsAllocationProblem = "ZRUST0060"
    /// Error from rust layer when calling ZcashRustBackend.putOrchardSubtreeRoots
    case rustPutOrchardSubtreeRoots = "ZRUST0061"
    /// Error from rust layer when calling TorClient.init
    case rustTorClientInit = "ZRUST0062"
    /// Error from rust layer when calling TorClient.get
    case rustTorClientGet = "ZRUST0063"
    /// Error from rust layer when calling ZcashRustBackend.transactionDataRequests
    case rustTransactionDataRequests = "ZRUST0064"
    /// Error from rust layer when calling ZcashRustBackend.deriveArbitraryWalletKey
    case rustDeriveArbitraryWalletKey = "ZRUST0065"
    /// Error from rust layer when calling ZcashRustBackend.deriveArbitraryAccountKey
    case rustDeriveArbitraryAccountKey = "ZRUST0066"
    /// Error from rust layer when calling ZcashRustBackend.importAccountUfvk
    case rustImportAccountUfvk = "ZRUST0067"
    /// Error from rust layer when calling ZcashRustBackend.deriveAddressFromUfvk
    case rustDeriveAddressFromUfvk = "ZRUST0068"
    /// Error from rust layer when calling ZcashRustBackend.createPCZTFromProposal
    case rustCreatePCZTFromProposal = "ZRUST0069"
    /// Error from rust layer when calling ZcashRustBackend.addProofsToPCZT
    case rustAddProofsToPCZT = "ZRUST0070"
    /// Error from rust layer when calling ZcashRustBackend.extractAndStoreTxFromPCZT
    case rustExtractAndStoreTxFromPCZT = "ZRUST0071"
    /// Error from rust layer when calling ZcashRustBackend.getAccount
    case rustUUIDAccountNotFound = "ZRUST0072"
    /// Error from rust layer when calling ZcashRustBackend.extractAndStoreTxFromPCZT
    case rustTxidPtrIncorrectLength = "ZRUST0073"
    /// Error from rust layer when calling ZcashRustBackend.redactPCZTForSigner
    case rustRedactPCZTForSigner = "ZRUST0074"
    /// Error from rust layer when calling AccountMetadatKey.init with a seed.
    case rustDeriveAccountMetadataKey = "ZRUST0075"
    /// Error from rust layer when calling AccountMetadatKey.derivePrivateUseMetadataKey
    case rustDerivePrivateUseMetadataKey = "ZRUST0076"
    /// Error from rust layer when calling TorClient.isolatedClient
    case rustTorIsolatedClient = "ZRUST0077"
    /// Error from rust layer when calling TorClient.connectToLightwalletd
    case rustTorConnectToLightwalletd = "ZRUST0078"
    /// Error from rust layer when calling TorLwdConn.fetchTransaction
    case rustTorLwdFetchTransaction = "ZRUST0079"
    /// Error from rust layer when calling TorLwdConn.submit
    case rustTorLwdSubmit = "ZRUST0080"
    /// Error from rust layer when calling TorLwdConn.getInfo
    case rustTorLwdGetInfo = "ZRUST0081"
    /// Error from rust layer when calling TorLwdConn.latestBlockHeight
    case rustTorLwdLatestBlockHeight = "ZRUST0082"
    /// Error from rust layer when calling TorLwdConn.getTreeState
    case rustTorLwdGetTreeState = "ZRUST0083"
    /// Error from rust layer when calling TorClient.httpRequest
    case rustTorHttpRequest = "ZRUST0084"
    /// Error from rust layer when calling ZcashRustBackend.getSingleUseTransparentAddress
    case rustGetSingleUseTransparentAddress = "ZRUST0085"
    /// Single use transparent address generated by rust layer is invalid when calling ZcashRustBackend.getSingleUseTransparentAddress
    case rustGetSingleUseTransparentAddressInvalidAddress = "ZRUST0086"
    /// Error from rust layer when calling ZcashRustBackend.checkSingleUseTransparentAddresses
    case rustCheckSingleUseTransparentAddresses = "ZRUST0087"
    /// Error from rust layer when calling ZcashRustBackend.updateTransparentAddressTransactions
    case rustUpdateTransparentAddressTransactions = "ZRUST0088"
    /// Error from rust layer when calling ZcashRustBackend.fetchUTXOsByAddress
    case rustFetchUTXOsByAddress = "ZRUST0089"
    /// Error from rust layer when calling ZcashRustBackend.deleteAccount
    case rustDeleteAccount = "ZRUST0090"
    /// Error from rust layer when calling ZcashEip681Backend.parseTransactionRequest
    case rustEip681Parse = "ZRUST0091"
    /// SQLite query failed when fetching all accounts from the database.
    case accountDAOGetAll = "ZADAO0001"
    /// Fetched accounts from SQLite but can't decode them.
    case accountDAOGetAllCantDecode = "ZADAO0002"
    /// SQLite query failed when seaching for accounts in the database.
    case accountDAOFindBy = "ZADAO0003"
    /// Fetched accounts from SQLite but can't decode them.
    case accountDAOFindByCantDecode = "ZADAO0004"
    /// Object passed to update() method conforms to `AccountEntity` protocol but isn't exactly `Account` type.
    case accountDAOUpdateInvalidAccount = "ZADAO0005"
    /// SQLite query failed when updating account in the database.
    case accountDAOUpdate = "ZADAO0006"
    /// Update of the account updated 0 rows in the database. One row should be updated.
    case accountDAOUpdatedZeroRows = "ZADAO0007"
    /// Failed to write block to disk.
    case blockRepositoryWriteBlock = "ZBLRP00001"
    /// Failed to get filename for the block from file URL.
    case blockRepositoryGetFilename = "ZBLRP0002"
    /// Failed to parse block height from filename.
    case blockRepositoryParseHeightFromFilename = "ZBLRP0003"
    /// Failed to remove existing block from disk.
    case blockRepositoryRemoveExistingBlock = "ZBLRP0004"
    /// Failed to get filename and information if url points to directory from file URL.
    case blockRepositoryGetFilenameAndIsDirectory = "ZBLRP0005"
    /// Failed to create blocks cache directory.
    case blockRepositoryCreateBlocksCacheDirectory = "ZBLRP0006"
    /// Failed to read content of directory.
    case blockRepositoryReadDirectoryContent = "ZBLRP0007"
    /// Failed to remove block from disk after rewind operation.
    case blockRepositoryRemoveBlockAfterRewind = "ZBLRP0008"
    /// Failed to remove blocks cache directory while clearing storage.
    case blockRepositoryRemoveBlocksCacheDirectory = "ZBLRP0009"
    /// Failed to remove block from cache when clearing cache up to some height.
    case blockRepositoryRemoveBlockClearingCache = "ZBLRP0010"
    /// Trying to download blocks before sync range is set in `BlockDownloaderImpl`. This means that download stream is not created and download cant' start.
    case blockDownloadSyncRangeNotSet = "ZBDWN0001"
    /// Stream downloading the given block range failed.
    case blockDownloaderServiceDownloadBlockRange = "ZBDSEO0001"
    /// Initialization of `ZcashTransaction.Overview` failed.
    case zcashTransactionOverviewInit = "ZTEZT0001"
    /// Initialization of `ZcashTransaction.Received` failed.
    case zcashTransactionReceivedInit = "ZTEZT0002"
    /// Initialization of `ZcashTransaction.Sent` failed.
    case zcashTransactionSentInit = "ZTEZT0003"
    /// Initialization of `ZcashTransaction.Output` failed.
    case zcashTransactionOutputInit = "ZTEZT0004"
    /// Initialization of `ZcashTransaction.Output` failed because there an inconsistency in the output recipient.
    case zcashTransactionOutputInconsistentRecipient = "ZTEZT0005"
    /// Entity not found in the database, result of `createEntity` execution.
    case transactionRepositoryEntityNotFound = "ZTREE0001"
    /// `Find` call is missing fields, required fields are transaction `index` and `blockTime`.
    case transactionRepositoryTransactionMissingRequiredFields = "ZTREE0002"
    /// Counting all transactions failed.
    case transactionRepositoryCountAll = "ZTREE0003"
    /// Counting all unmined transactions failed.
    case transactionRepositoryCountUnmined = "ZTREE0004"
    /// Execution of a query failed.
    case transactionRepositoryQueryExecute = "ZTREE0005"
    /// Finding memos in the database failed.
    case transactionRepositoryFindMemos = "ZTREE0006"
    /// Can't encode `ZcashCompactBlock` object.
    case compactBlockEncode = "ZCMPB0001"
    /// Invalid UTF-8 Bytes where detected when attempting to create a MemoText.
    case memoTextInvalidUTF8 = "ZMEMO0001"
    /// Trailing null-bytes were found when attempting to create a MemoText.
    case memoTextInputEndsWithNullBytes = "ZMEMO0002"
    /// The resulting bytes provided are too long to be stored as a MemoText.
    case memoTextInputTooLong = "ZMEMO0003"
    /// The resulting bytes provided are too long to be stored as a MemoBytes.
    case memoBytesInputTooLong = "ZMEMO0004"
    /// Invalid UTF-8 Bytes where detected when attempting to convert MemoBytes to Memo.
    case memoBytesInvalidUTF8 = "ZMEMO0005"
    /// Failed to load JSON with checkpoint from disk.
    case checkpointCantLoadFromDisk = "ZCHKP0001"
    /// Failed to decode `Checkpoint` object.
    case checkpointDecode = "ZCHKP0002"
    /// Creation of the table for unspent transaction output failed.
    case unspentTransactionOutputDAOCreateTable = "ZUTOD0001"
    /// SQLite query failed when storing unspent transaction output.
    case unspentTransactionOutputDAOStore = "ZUTOD0002"
    /// SQLite query failed when removing all the unspent transation outputs.
    case unspentTransactionOutputDAOClearAll = "ZUTOD0003"
    /// Fetched information about unspent transaction output from the DB but it can't be decoded to `UTXO` object.
    case unspentTransactionOutputDAOGetAllCantDecode = "ZUTOD0004"
    /// SQLite query failed when getting all the unspent transation outputs.
    case unspentTransactionOutputDAOGetAll = "ZUTOD0005"
    /// SQLite query failed when getting balance.
    case unspentTransactionOutputDAOBalance = "ZUTOD0006"
    /// Can't create `SaplingExtendedSpendingKey` because input is invalid.
    case spendingKeyInvalidInput = "ZWLTP0001"
    /// Can't create `UnifiedFullViewingKey` because input is invalid.
    case unifiedFullViewingKeyInvalidInput = "ZWLTP0002"
    /// Can't create `SaplingExtendedFullViewingKey` because input is invalid.
    case extetendedFullViewingKeyInvalidInput = "ZWLTP0003"
    /// Can't create `TransparentAddress` because input is invalid.
    case transparentAddressInvalidInput = "ZWLTP0004"
    /// Can't create `SaplingAddress` because input is invalid.
    case saplingAddressInvalidInput = "ZWLTP0005"
    /// Can't create `UnifiedAddress` because input is invalid.
    case unifiedAddressInvalidInput = "ZWLTP0006"
    /// Can't create `Recipient` because input is invalid.
    case recipientInvalidInput = "ZWLTP0007"
    /// Can't create `TexAddress` because input is invalid.
    case texAddressInvalidInput = "ZWLTP0008"
    /// WalletTransactionEncoder wants to create transaction but files with sapling parameters are not present on disk.
    case walletTransEncoderCreateTransactionMissingSaplingParams = "ZWLTE0001"
    /// WalletTransactionEncoder wants to shield funds but files with sapling parameters are not present on disk.
    case walletTransEncoderShieldFundsMissingSaplingParams = "ZWLTE0002"
    /// Initiatilzation fo `Zatoshi` from a decoder failed.
    case zatoshiDecode = "ZTSHO0001"
    /// Encode of `Zatoshi` failed.
    case zatoshiEncode = "ZTSHO0002"
    /// Awaiting transactions from the stream failed.
    case unspentTransactionFetcherStream = "ZUTXO0001"
    /// CompactBlockProcessor was started with an invalid configuration.
    case compactBlockProcessorInvalidConfiguration = "ZCBPEO0001"
    /// CompactBlockProcessor was set up with path but that location couldn't be reached.
    case compactBlockProcessorMissingDbPath = "ZCBPEO0002"
    /// Data Db file couldn't be initialized at path.
    case compactBlockProcessorDataDbInitFailed = "ZCBPEO0003"
    /// There's a problem with the network connection.
    case compactBlockProcessorConnection = "ZCBPEO0004"
    /// Error on gRPC happened.
    case compactBlockProcessorGrpcError = "ZCBPEO0005"
    /// Network connection timeout.
    case compactBlockProcessorConnectionTimeout = "ZCBPEO0006"
    /// Compact Block failed and reached the maximum amount of retries it was set up to do.
    case compactBlockProcessorMaxAttemptsReached = "ZCBPEO0007"
    /// Unspecified error occured.
    case compactBlockProcessorUnspecified = "ZCBPEO0008"
    /// Critical error occured.
    case compactBlockProcessorCritical = "ZCBPEO0009"
    /// Invalid Account.
    case compactBlockProcessorInvalidAccount = "ZCBPEO0010"
    /// The remote server you are connecting to is publishing a different branch ID than the one your App is expecting This could be caused by your App being out of date or the server you are connecting you being either on a different network or out of date after a network upgrade.
    case compactBlockProcessorWrongConsensusBranchId = "ZCBPEO0011"
    /// A server was reached, but it's targeting the wrong network Type. Make sure you are pointing to the right server.
    case compactBlockProcessorNetworkMismatch = "ZCBPEO0012"
    /// A server was reached, it's showing a different sapling activation. Are you sure you are pointing to the right server?
    case compactBlockProcessorSaplingActivationMismatch = "ZCBPEO0013"
    /// when the given URL is the same URL than the one provided as `self.fsBlockDbRoot` assuming that's a programming error being the `legacyCacheDbURL` a sqlite database file and not a directory
    case compactBlockProcessorCacheDbMigrationFsCacheMigrationFailedSameURL = "ZCBPEO0014"
    /// Deletion of readable file at the provided URL failed.
    case compactBlockProcessorCacheDbMigrationFailedToDeleteLegacyDb = "ZCBPEO0015"
    /// Chain name does not match. Expected either 'test' or 'main'. This is probably an API or programming error.
    case compactBlockProcessorChainName = "ZCBPEO0016"
    /// Consensus BranchIDs don't match this is probably an API or programming error.
    case compactBlockProcessorConsensusBranchID = "ZCBPEO0017"
    /// Rewind of DownloadBlockAction failed as no action is possible to unwrapp.
    case compactBlockProcessorDownloadBlockActionRewind = "ZCBPEO0018"
    /// Put sapling subtree roots to the DB failed.
    case compactBlockProcessorPutSaplingSubtreeRoots = "ZCBPEO0019"
    /// Getting the `lastScannedHeight` failed but it's supposed to always provide some value.
    case compactBlockProcessorLastScannedHeight = "ZCBPEO0020"
    /// Getting the `supportedSyncAlgorithm` failed but it's supposed to always provide some value.
    case compactBlockProcessorSupportedSyncAlgorithm = "ZCBPEO0021"
    /// Put Orchard subtree roots to the DB failed.
    case compactBlockProcessorPutOrchardSubtreeRoots = "ZCBPEO0022"
    /// The synchronizer is unprepared.
    case synchronizerNotPrepared = "ZSYNCO0001"
    /// Memos can't be sent to transparent addresses.
    case synchronizerSendMemoToTransparentAddress = "ZSYNCO0002"
    /// There is not enough transparent funds to cover fee for the shielding.
    case synchronizerShieldFundsInsuficientTransparentFunds = "ZSYNCO0003"
    /// LatestUTXOs for the address failed, invalid t-address.
    case synchronizerLatestUTXOsInvalidTAddress = "ZSYNCO0004"
    /// Rewind failed, unknown archor height
    case synchronizerRewindUnknownArchorHeight = "ZSYNCO0005"
    /// Indicates that this Synchronizer is disconnected from its lightwalletd server.
    case synchronizerDisconnected = "ZSYNCO0006"
    /// The attempt to switch endpoints failed. Check that the hostname and port are correct, and are formatted as <hostname>:<port>.
    case synchronizerServerSwitch = "ZSYNCO0007"
    /// The spending key does not belong to the wallet.
    case synchronizerSpendingKeyDoesNotBelongToTheWallet = "ZSYNCO0008"
    /// Attempt to init TxId with input that is not 32 bytes.
    case txIdNot32Bytes = "ZMODEL0001"
    /// Attempt to init TxId with invalid hex encoding.
    case txIdInvalidHexEncoding = "ZMODEL0002"
}
