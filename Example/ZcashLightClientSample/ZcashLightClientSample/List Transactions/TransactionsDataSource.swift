//
//  TransactionsDataSource.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 12/4/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation
import UIKit
import ZcashLightClientKit

class TransactionsDataSource: NSObject {
    enum TransactionType {
        case sent
        case received
        case cleared
        case all
    }

    static let cellIdentifier = "TransactionCell"

    // swiftlint:disable:next implicitly_unwrapped_optional
    var synchronizer: Synchronizer!
    var transactions: [TransactionDetailModel] = []

    private var status: TransactionType

    init(status: TransactionType, synchronizer: Synchronizer) {
        self.status = status
        self.synchronizer = synchronizer
    }

    func load() async throws {
        transactions = []
        switch status {
        case .cleared:
            let rawTransactions = await synchronizer.transactions
            for transaction in rawTransactions where transaction.minedHeight != nil {
                let memos = try await synchronizer.getMemos(for: transaction)
                transactions.append(TransactionDetailModel(transaction: transaction, memos: memos))
            }
        case .received:
            let rawTransactions = await synchronizer.receivedTransactions
            for transaction in rawTransactions {
                let memos = try await synchronizer.getMemos(for: transaction)
                transactions.append(TransactionDetailModel(receivedTransaction: transaction, memos: memos))
            }
        case .sent:
            let rawTransactions = await synchronizer.sentTransactions
            for transaction in rawTransactions {
                let memos = try await synchronizer.getMemos(for: transaction)
                transactions.append(TransactionDetailModel(sendTransaction: transaction, memos: memos))
            }
        case .all:
            let rawClearedTransactions = await synchronizer.transactions
            for transaction in rawClearedTransactions {
                let memos = try await synchronizer.getMemos(for: transaction)
                transactions.append(TransactionDetailModel(transaction: transaction, memos: memos))
            }
        }
    }
}

// MARK: - UITableViewDataSource

extension TransactionsDataSource: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return transactions.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: Self.cellIdentifier, for: indexPath)

        let transaction = transactions[indexPath.row]
        cell.detailTextLabel?.text = transaction.id?.toHexStringTxId() ?? "no id"
        cell.textLabel?.text = "\(transaction.dateDescription) \t\(transaction.amountDescription)"

        cell.accessoryType = .disclosureIndicator
        return cell
    }
}
