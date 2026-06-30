//
//  PendingTransactionsTableViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 12/4/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit

class TransactionsTableViewController: UITableViewController {
    var datasource: TransactionsDataSource? {
        didSet {
            self.tableView.dataSource = datasource
            Task {
                try? await datasource?.load()
                DispatchQueue.main.async { [weak self] in
                    if self?.viewIfLoaded != nil {
                        self?.tableView.reloadData()
                    }
                }
            }
        }
    }

    var selectedTx: TransactionDetailModel?
    var selectedRow: Int?

    override func viewDidLoad() {
        super.viewDidLoad()
        self.tableView.dataSource = datasource
        self.tableView.reloadData()

        Task {
            try? await datasource?.load()
            DispatchQueue.main.async { [weak self] in
                self?.tableView.reloadData()
            }
        }
    }
}

// MARK: - UITableViewDataSource

extension TransactionsTableViewController {
    override func numberOfSections(in tableView: UITableView) -> Int {
        // #warning Incomplete implementation, return the number of sections
        0
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        // #warning Incomplete implementation, return the number of rows
        0
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        selectedRow = indexPath.row

        tableView.deselectRow(at: indexPath, animated: true)

        if shouldPerformSegue(withIdentifier: "TransactionDetail", sender: self) {
            performSegue(withIdentifier: "TransactionDetail", sender: self)
        }
    }

    override func shouldPerformSegue(withIdentifier identifier: String, sender: Any?) -> Bool {
        if identifier == "TransactionDetail", let row = selectedRow, let transaction = datasource?.transactions[row] {
            selectedTx = transaction
            return true
        }
        return false
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let destination = segue.destination as? TransactionDetailViewController, let transaction = selectedTx {
            destination.model = transaction
            selectedTx = nil
            selectedRow = nil
        }
    }
}

