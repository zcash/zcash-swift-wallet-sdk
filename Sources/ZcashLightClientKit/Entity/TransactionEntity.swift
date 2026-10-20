//
//  TransactionEntity.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/14/19.
//

import Foundation
import SQLite

public enum ZcashTransaction {
    public struct Overview: Equatable, Identifiable {
        /// Represents the transaction state based on current height of the chain,
        /// mined height and expiry height of a transaction.
        public enum State {
            /// transaction has a `minedHeight` that's greater or equal than
            /// `ZcashSDK.defaultStaleTolerance` confirmations.
            case confirmed
            /// transaction has no `minedHeight` but current known height is less than `expiryHeight`.
            case pending
            /// transaction has no `minedHeight` and current known height is greater or equal than `expiryHeight`.
            case expired

            init(
                currentHeight: BlockHeight,
                minedHeight: BlockHeight?,
                expiredUnmined: Bool?,
                expiryHeight: BlockHeight? = nil
            ) {
                guard let expiredUnmined, !expiredUnmined else {
                    self = .expired
                    return
                }

                if let minedHeight, (currentHeight - minedHeight) >= ZcashSDK.defaultStaleTolerance {
                    self = .confirmed
                } else if let minedHeight, (currentHeight - minedHeight) < ZcashSDK.defaultStaleTolerance {
                    self = .pending
                } else if minedHeight == nil {
                    // Fallback for when `expired_unmined` lags: a tx whose expiry has passed
                    // is physically unminable regardless of column state.
                    if let expiryHeight, expiryHeight > 0, currentHeight >= expiryHeight {
                        self = .expired
                    } else {
                        self = .pending
                    }
                } else {
                    self = .expired
                }
            }
        }

        /// How a transaction classifies against ZIP 318, the Orchard to Ironwood
        /// pool migration. This is a conformance class and never a provenance: it
        /// cannot establish that a transaction came from this wallet's own
        /// migration run. The encoding is stable and append-only.
        public enum ZIP318Kind: Equatable {
            /// Not classified. Either the transaction predates this column or the
            /// wallet has not decrypted it yet; deciding requires rescanning the
            /// transaction. This is the absence of a decision, not the decision
            /// that the transaction is not a ZIP 318 one, so present no label for
            /// it. An unrecognized encoding decodes here as well, because an SDK
            /// that does not know a code has learned nothing about the
            /// transaction.
            case notClassified
            /// Classified, and not a ZIP 318 transaction.
            case nonconforming
            /// A note-preparation self-send that a migration run makes before it
            /// crosses.
            case preparation
            /// A pool crossing paying the account's own internal address, so a
            /// migration transfer.
            case transfer
            /// A canonical pool crossing that pays a third party. It has the
            /// same on-chain shape as a migration transfer but is not a
            /// migration this account made.
            case canonicalCrossingPayment

            init(rawValue: Int) {
                switch rawValue {
                case 1:
                    self = .nonconforming
                case 2:
                    self = .preparation
                case 3:
                    self = .transfer
                case 4:
                    self = .canonicalCrossingPayment
                default:
                    self = .notClassified
                }
            }
        }

        public var id: Data { rawID }

        public let accountUUID: AccountUUID
        public var blockTime: TimeInterval?
        public let expiryHeight: BlockHeight?
        public let fee: Zatoshi?
        public let index: Int?
        public var isSentTransaction: Bool { value < Zatoshi(0) }
        public var isShielding: Bool
        public let hasChange: Bool
        public let memoCount: Int
        public let minedHeight: BlockHeight?
        public let raw: Data?
        public let rawID: Data
        public let receivedNoteCount: Int
        public let sentNoteCount: Int
        public let value: Zatoshi
        public let isExpiredUmined: Bool?
        public let totalSpent: Zatoshi?
        public let totalReceived: Zatoshi?
        /// Number of the account's own notes this transaction spent.
        public let spentNoteCount: Int
        /// The value that crossed shielded pools when this transaction is a
        /// wallet-internal transfer between them, such as an Orchard to
        /// Ironwood migration; `nil` when it is not such a transfer.
        ///
        /// For such a transaction `value` is just the negated fee, so this is
        /// the amount to present to a user rather than the balance delta.
        public let poolCrossingValue: Zatoshi?
        /// Whether this transaction is considered trusted, meaning its outputs
        /// are spendable after the trusted confirmation count rather than the
        /// untrusted one.
        public let isTrusted: Bool
        /// How this transaction classifies against ZIP 318, the Orchard to
        /// Ironwood pool migration. Only `preparation` and `transfer` are a
        /// migration this account made.
        public let zip318Kind: ZIP318Kind
        public var state: State?
    }

    public struct Output: Equatable, Identifiable {
        public enum Pool: Equatable {
            case transaparent
            case sapling
            case orchard
            /// The Ironwood (NU6.3) shielded pool. Every shielded output a wallet receives after
            /// NU6.3 activation lands here, so this is the common case post-activation — before
            /// it existed, such outputs decoded as `.other(4)`.
            case ironwood
            case other(Int)
            init(rawValue: Int) {
                switch rawValue {
                case 0:
                    self = .transaparent
                case 2:
                    self = .sapling
                case 3:
                    self = .orchard
                case 4:
                    self = .ironwood
                default:
                    self = .other(rawValue)
                }
            }
        }

        public var id: Data { rawID }

        public let rawID: Data
        public let pool: Pool
        public let index: Int
        public let fromAccount: AccountUUID?
        public let recipient: TransactionRecipient
        public let value: Zatoshi
        public let isChange: Bool
        public let memo: Memo?
    }

    /// Used when fetching blocks from the lightwalletd
    struct Fetched: Equatable {
        public let rawID: Data
        public let minedHeight: UInt32?
        public let raw: Data
    }
}

extension ZcashTransaction.Output {
    enum Column {
        static let rawID = SQLite.Expression<Blob>("txid")
        static let pool = SQLite.Expression<Int>("output_pool")
        static let index = SQLite.Expression<Int>("output_index")
        static let toAccount = SQLite.Expression<Blob?>("to_account_uuid")
        static let fromAccount = SQLite.Expression<Blob?>("from_account_uuid")
        static let toAddress = SQLite.Expression<String?>("to_address")
        static let value = SQLite.Expression<Int64>("value")
        static let isChange = SQLite.Expression<Bool>("is_change")
        static let memo = SQLite.Expression<Blob?>("memo")
    }

    init(row: Row) throws {
        do {
            rawID = Data(blob: try row.get(Column.rawID))
            pool = .init(rawValue: try row.get(Column.pool))
            index = try row.get(Column.index)
            if let accountId = try row.get(Column.fromAccount) {
                fromAccount = AccountUUID(id: [UInt8](Data(blob: accountId)))
            } else {
                fromAccount = nil
            }
            value = Zatoshi(try row.get(Column.value))
            isChange = try row.get(Column.isChange)

            if
                let outputRecipient = try row.get(Column.toAddress),
                let metadata = DerivationTool.getAddressMetadata(outputRecipient)
            {
                recipient = TransactionRecipient.address(try Recipient(outputRecipient, network: metadata.networkType))
            } else if let toAccount = try row.get(Column.toAccount) {
                recipient = .internalAccount(AccountUUID(id: [UInt8](Data(blob: toAccount))))
            } else {
                throw ZcashError.zcashTransactionOutputInconsistentRecipient
            }

            if let memoData = try row.get(Column.memo) {
                memo = try Memo(bytes: memoData.bytes)
            } else {
                memo = nil
            }
        } catch {
            throw ZcashError.zcashTransactionOutputInit(error)
        }
    }
}

extension ZcashTransaction.Overview {
    enum Column {
        static let accountUUID = SQLite.Expression<Blob>("account_uuid")
        static let minedHeight = SQLite.Expression<BlockHeight?>("mined_height")
        static let index = SQLite.Expression<Int?>("tx_index")
        static let rawID = SQLite.Expression<Blob>("txid")
        static let expiryHeight = SQLite.Expression<BlockHeight?>("expiry_height")
        static let raw = SQLite.Expression<Blob?>("raw")
        static let value = SQLite.Expression<Int64>("account_balance_delta")
        static let fee = SQLite.Expression<Int64?>("fee_paid")
        static let hasChange = SQLite.Expression<Bool>("has_change")
        static let sentNoteCount = SQLite.Expression<Int>("sent_note_count")
        static let receivedNoteCount = SQLite.Expression<Int>("received_note_count")
        static let isShielding = SQLite.Expression<Bool>("is_shielding")
        static let memoCount = SQLite.Expression<Int>("memo_count")
        static let blockTime = SQLite.Expression<Int64?>("block_time")
        static let expiredUnmined = SQLite.Expression<Bool?>("expired_unmined")
        static let totalSpent = SQLite.Expression<Int64?>("total_spent")
        static let totalReceived = SQLite.Expression<Int64?>("total_received")
        static let spentNoteCount = SQLite.Expression<Int>("spent_note_count")
        static let poolCrossingValue = SQLite.Expression<Int64?>("pool_crossing_value")
        // Optional by contract: `trust_status` is an opt-in marker (`set_tx_trust`) with no
        // default, no backfill, and — today — no caller anywhere, so it is NULL on every row of
        // every real wallet. librustzcash's own readers consume it as IFNULL(trust_status, 0);
        // decoding it strictly threw on the first row and emptied the entire transaction list
        // (field, 2026-08-04). NULL decodes as "never evaluated" → untrusted.
        static let trustStatus = SQLite.Expression<Bool?>("trust_status")
        static let zip318Kind = SQLite.Expression<Int>("zip318_kind")
    }

    init(row: Row) throws {
        do {
            self.accountUUID = AccountUUID(id: [UInt8](Data(blob: try row.get(Column.accountUUID))))
            self.expiryHeight = try row.get(Column.expiryHeight)
            self.index = try row.get(Column.index)
            self.hasChange = try row.get(Column.hasChange)
            self.memoCount = try row.get(Column.memoCount)
            self.minedHeight = try row.get(Column.minedHeight)
            self.rawID = Data(blob: try row.get(Column.rawID))
            self.receivedNoteCount = try row.get(Column.receivedNoteCount)
            self.isShielding = try row.get(Column.isShielding)
            self.sentNoteCount = try row.get(Column.sentNoteCount)
            self.value = Zatoshi(try row.get(Column.value))
            self.isExpiredUmined = try row.get(Column.expiredUnmined)
            self.spentNoteCount = try row.get(Column.spentNoteCount)
            self.isTrusted = (try row.get(Column.trustStatus)) ?? false
            self.zip318Kind = .init(rawValue: try row.get(Column.zip318Kind))

            if let poolCrossingValue = try row.get(Column.poolCrossingValue) {
                self.poolCrossingValue = Zatoshi(poolCrossingValue)
            } else {
                self.poolCrossingValue = nil
            }
            if let blockTime = try row.get(Column.blockTime) {
                self.blockTime = TimeInterval(blockTime)
            } else {
                self.blockTime = nil
            }

            if let fee = try row.get(Column.fee) {
                self.fee = Zatoshi(fee)
            } else {
                self.fee = nil
            }

            if let totalSpent = try row.get(Column.totalSpent) {
                self.totalSpent = Zatoshi(totalSpent)
            } else {
                self.totalSpent = nil
            }

            if let totalReceived = try row.get(Column.totalReceived) {
                self.totalReceived = Zatoshi(totalReceived)
            } else {
                self.totalReceived = nil
            }

            if let raw = try row.get(Column.raw) {
                self.raw = Data(blob: raw)
            } else {
                self.raw = nil
            }
        } catch {
            throw ZcashError.zcashTransactionOverviewInit(error)
        }
    }

    func anchor(network: ZcashNetwork) -> BlockHeight? {
        guard let minedHeight = self.minedHeight else { return nil }
        if minedHeight != -1 {
            return max(minedHeight - ZcashSDK.defaultStaleTolerance, network.saplingActivationHeight)
        }

        guard let expiryHeight = self.expiryHeight else { return nil }
        if expiryHeight != -1 {
            return max(expiryHeight - ZcashSDK.expiryOffset - ZcashSDK.defaultStaleTolerance, network.saplingActivationHeight)
        }

        return nil
    }
}

/// extension to handle pending states
public extension ZcashTransaction.Overview {
    func getState(for currentHeight: BlockHeight) -> State {
        State(
            currentHeight: currentHeight,
            minedHeight: minedHeight,
            expiredUnmined: self.isExpiredUmined,
            expiryHeight: self.expiryHeight
        )
    }

    func isPending(currentHeight: BlockHeight) -> Bool {
        getState(for: currentHeight) == .pending
    }
}

/**
Capabilities of an entity that can be uniquely identified by a raw transaction id
*/
public protocol RawIdentifiable {
    var rawTransactionId: Data? { get set }
}
