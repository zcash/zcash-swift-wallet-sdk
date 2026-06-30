//
//  GetUTXOsViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 12/9/20.
//  Copyright © 2020 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit
import KRProgressHUD
class GetUTXOsViewController: UIViewController {
    @IBOutlet weak var transparentAddressLabel: UILabel!
    @IBOutlet weak var verifiedBalanceLabel: UILabel!
    @IBOutlet weak var totalBalanceLabel: UILabel!
    @IBOutlet weak var messageLabel: UILabel!
    @IBOutlet weak var shieldFundsButton: UIButton!

    let accountIndex = Zip32AccountIndex(0)

    override func viewDidLoad() {
        super.viewDidLoad()

        updateUI()
    }

    func updateUI() {
        let synchronizer = SDKSynchronizer.shared

        Task { @MainActor in
            guard let account = try? await synchronizer.listAccounts().first else {
                return
            }

            let tAddress = (try? await synchronizer.getTransparentAddress(accountUUID: account.id))?.stringEncoded ?? "no t-address found"

            self.transparentAddressLabel.text = tAddress

            // swiftlint:disable:next force_try
            let balance = try! await AppDelegate.shared.sharedSynchronizer.getAccountsBalances()[account.id]?.unshielded ?? .zero

            self.totalBalanceLabel.text = NumberFormatter.zcashNumberFormatter.string(from: NSNumber(value: balance.amount))
            self.verifiedBalanceLabel.text = NumberFormatter.zcashNumberFormatter.string(from: NSNumber(value: balance.amount))
        }
    }
}

extension GetUTXOsViewController: UITextFieldDelegate {
    func textField(
        _ textField: UITextField,
        shouldChangeCharactersIn range: NSRange,
        replacementString string: String
    ) -> Bool {
        updateUI()
        return true
    }

    func textFieldDidEndEditing(_ textField: UITextField) {
        updateUI()
    }
}
