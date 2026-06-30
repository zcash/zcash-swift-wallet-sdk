//
//  PaginatedTransactionsViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 12/13/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit
import PaginatedTableView
class PaginatedTransactionsViewController: UIViewController {
    static let cellIdentifier = "TransactionCell"

    @IBOutlet weak var tableView: PaginatedTableView!

    // swiftlint:disable:next implicitly_unwrapped_optional
    var paginatedRepository: PaginatedTransactionRepository!
    var transactions: [ZcashTransaction.Overview] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        // Add paginated delegates only
        self.tableView.pageSize = paginatedRepository.pageSize
        self.tableView.firstPage = 0
        tableView.paginatedDelegate = self
        tableView.paginatedDataSource = self

        // More settings
        tableView.enablePullToRefresh = true
        tableView.loadData(refresh: true)
    }

    func loadMore(_ pageNumber: Int, _ pageSize: Int, onSuccess: ((Bool) -> Void)?, onError: ((Error) -> Void)?) {
        Task {
            // Call your api here
            // Send true in onSuccess in case new data exists, sending false will disable pagination
            do {
                guard let txs = try await paginatedRepository.page(pageNumber) else {
                    DispatchQueue.main.async {
                        onSuccess?(false)
                    }
                    return
                }
                if pageNumber == 0 { transactions.removeAll() }

                transactions.append(contentsOf: txs)
                let pageCount = await self.paginatedRepository.pageCount
                DispatchQueue.main.async {
                    onSuccess?(pageNumber < pageCount)
                }
            } catch {
                DispatchQueue.main.async {
                    onError?(error)
                }
            }
        }
    }

    var selectedRow: Int?

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        selectedRow = indexPath.row

        tableView.deselectRow(at: indexPath, animated: true)

        if shouldPerformSegue(withIdentifier: "TransactionDetail", sender: self) {
            performSegue(withIdentifier: "TransactionDetail", sender: self)
        }
    }

    override func shouldPerformSegue(withIdentifier identifier: String, sender: Any?) -> Bool {
        identifier == "TransactionDetail" && selectedRow != nil
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let destination = segue.destination as? TransactionDetailViewController, let row = selectedRow {
            let transaction = transactions[row]
            destination.model = TransactionDetailModel(transaction: transaction, memos: [])
            selectedRow = nil
        }
    }
}

extension PaginatedTransactionsViewController: PaginatedTableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        transactions.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: Self.cellIdentifier, for: indexPath)

        let transaction = transactions[indexPath.row]
        cell.detailTextLabel?.text = transaction.rawID.toHexStringTxId()
        cell.textLabel?.text = transaction.blockTime?.description

        return cell
    }

    func numberOfSections(in tableView: UITableView) -> Int {
        1
    }
}

extension PaginatedTransactionsViewController: PaginatedTableViewDelegate {
    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        96
    }
}
