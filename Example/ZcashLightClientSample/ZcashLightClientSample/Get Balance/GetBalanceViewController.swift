//
//  GetBalanceViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 11/26/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit
import Combine

class GetBalanceViewController: UIViewController {
    @IBOutlet weak var balance: UILabel!
    @IBOutlet weak var verified: UILabel!

    var cancellable: AnyCancellable?

    var accountBalance: AccountBalance?
    var rate: FiatCurrencyResult?

    override func viewDidLoad() {
        super.viewDidLoad()
        let synchronizer = AppDelegate.shared.sharedSynchronizer
        self.title = "Account 0 Balance"

        Task { @MainActor [weak self] in
            guard let account = try? await synchronizer.listAccounts().first else {
                return
            }

            self?.accountBalance = try? await synchronizer.getAccountsBalances()[account.id]
            self?.updateLabels()
        }

        cancellable = synchronizer.exchangeRateUSDStream.sink { [weak self] result in
            self?.rate = result
            self?.updateLabels()
        }

        synchronizer.refreshExchangeRateUSD()
    }

    func updateLabels() {
        DispatchQueue.main.async { [weak self] in
            let balanceText = (self?.accountBalance?.saplingBalance.total().formattedString) ?? "0.0"
            let verifiedText = (self?.accountBalance?.saplingBalance.spendableValue.formattedString) ?? "0.0"

            if let usdZecRate = self?.rate {
                let usdBalance = (self?.accountBalance?.saplingBalance.total().decimalValue ?? 0).multiplying(by: usdZecRate.rate)
                let usdVerified = (self?.accountBalance?.saplingBalance.spendableValue.decimalValue ?? 0).multiplying(by: usdZecRate.rate)
                self?.balance.text = "\(balanceText) ZEC\n\(usdBalance) USD\n\n(\(usdZecRate.rate) USD/ZEC)"
                self?.verified.text = "\(verifiedText) ZEC\n\(usdVerified) USD"
            } else {
                self?.balance.text = "\(balanceText) ZEC"
                self?.verified.text = "\(verifiedText) ZEC"
            }
        }
    }
}

extension Zatoshi {
    var formattedString: String? {
        decimalString(formatter: NumberFormatter.zcashNumberFormatter)
    }
}
