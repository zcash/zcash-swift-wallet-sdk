//
//  ViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 06/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Combine
import UIKit

class MainTableViewController: UITableViewController {
    override func viewDidLoad() {
        super.viewDidLoad()

        self.navigationItem.rightBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .trash,
            target: self,
            action: #selector(wipe(_:))
        )
    }

    @objc func wipe(_ sender: Any?) {
        let alert = UIAlertController(
            title: "Wipe the wallet?",
            message: """
            You are about to clear existing databases. All synced blocks, stored TXs, etc will be removed form this device only. If the sync is in
            progress it may take some time. Please be patient.
            """,
            preferredStyle: .alert
        )

        alert.addAction(
            UIAlertAction(
                title: "Drop it like it's FIAT",
                style: UIAlertAction.Style.destructive
            ) { [weak self] _ in
                guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else { return }
                appDelegate.wipe() { [weak self] possibleError in
                    if let error = possibleError {
                        self?.wipeFailedAlert(error: error)
                    } else {
                        self?.wipeSuccessfullAlert()
                    }
                }
            }
        )

        alert.addAction(UIAlertAction(title: "No please! Have mercy!", style: UIAlertAction.Style.cancel, handler: nil))

        self.present(alert, animated: true, completion: nil)
    }

    private func wipeSuccessfullAlert() {
        let alert = UIAlertController(
            title: "Wipe is done!",
            message: nil,
            preferredStyle: .alert
        )

        alert.addAction(UIAlertAction(title: "Ok", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    private func wipeFailedAlert(error: Error) {
        loggerProxy.error("Wipe error: \(error)")

        let alert = UIAlertController(
            title: "Wipe FAILED!",
            message: """
            Something bad happened and wipe failed. This may happen only when some basic IO disk operations failed. The SDK may end up in \
            inconsistent state. It's suggested to call the wipe again until it succeeds. Sorry.

            \(error)
            """,
            preferredStyle: .alert
        )

        alert.addAction(UIAlertAction(title: "Ok", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let destination = segue.destination as? TransactionsTableViewController {
            if let id = segue.identifier, id == "Sent" {
                destination.datasource = TransactionsDataSource(
                    status: .sent,
                    synchronizer: AppDelegate.shared.sharedSynchronizer
                )
                destination.title = "Sent Transactions"
            } else if let id = segue.identifier, id == "Received" {
                destination.datasource = TransactionsDataSource(
                    status: .received,
                    synchronizer: AppDelegate.shared.sharedSynchronizer
                )
                destination.title = "Received Transactions"
            } else if let id = segue.identifier, id == "Cleared" {
                destination.datasource = TransactionsDataSource(
                    status: .cleared,
                    synchronizer: AppDelegate.shared.sharedSynchronizer
                )
                destination.title = "Cleared Transactions"
            } else if let id = segue.identifier, id == "All" {
                destination.datasource = TransactionsDataSource(
                    status: .all,
                    synchronizer: AppDelegate.shared.sharedSynchronizer
                )
                destination.title = "All Transactions"
            }
        } else if let destination = segue.destination as? PaginatedTransactionsViewController {
            let paginatedRepo = AppDelegate.shared.sharedSynchronizer.paginatedTransactions()
            destination.paginatedRepository = paginatedRepo
        }
        super.prepare(for: segue, sender: sender)
    }
}
