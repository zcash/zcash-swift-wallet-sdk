//
//  GetAddressViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 11/1/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit
class GetAddressViewController: UIViewController {
    @IBOutlet weak var unifiedAddressLabel: UILabel! // This is your Unified Address
    @IBOutlet weak var tAddressLabel: UILabel! // this is the transparent receiver of your UA above
    @IBOutlet weak var saplingAddress: UILabel! // this is the sapling receiver of your UA above

    override func viewDidLoad() {
        super.viewDidLoad()

        let synchronizer = SDKSynchronizer.shared

        Task { @MainActor in
            guard let account = try? await synchronizer.listAccounts().first else {
                return
            }

            guard let uAddress = try? await synchronizer.getUnifiedAddress(accountUUID: account.id) else {
                unifiedAddressLabel.text = "could not derive UA"
                tAddressLabel.text = "could not derive tAddress"
                saplingAddress.text = "could not derive zAddress"
                return
            }

            // you can either try to extract receivers from the UA itself or request the Synchronizer to do it for you. Certain UAs might not contain all the receivers you expect.
            unifiedAddressLabel.text = uAddress.stringEncoded

            tAddressLabel.text = (try? uAddress.transparentReceiver())?.stringEncoded ?? "could not extract transparent receiver from UA"
            saplingAddress.text = (try? uAddress.saplingReceiver())?.stringEncoded ?? "could not extract sapling receiver from UA"

            unifiedAddressLabel.addGestureRecognizer(
                UITapGestureRecognizer(
                    target: self,
                    action: #selector(addressTapped(_:))
                )
            )
            unifiedAddressLabel.isUserInteractionEnabled = true

            tAddressLabel.isUserInteractionEnabled = true
            tAddressLabel.addGestureRecognizer(
                UITapGestureRecognizer(
                    target: self,
                    action: #selector(tAddressTapped(_:))
                )
            )
            saplingAddress.addGestureRecognizer(
                UITapGestureRecognizer(
                    target: self,
                    action: #selector(spendingKeyTapped(_:))
                )
            )
            saplingAddress.isUserInteractionEnabled = true
            loggerProxy.info("Address: \(String(describing: uAddress))")
        }
    }

    @IBAction func spendingKeyTapped(_ gesture: UIGestureRecognizer) {
        loggerProxy.event("copied to clipboard")

        UIPasteboard.general.string = self.saplingAddress.text
        let alert = UIAlertController(
            title: "",
            message: "Sapling Address Copied to clipboard",
            preferredStyle: UIAlertController.Style.alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    @IBAction func addressTapped(_ gesture: UIGestureRecognizer) {
        loggerProxy.event("copied to clipboard")

        UIPasteboard.general.string = unifiedAddressLabel.text

        let alert = UIAlertController(
            title: "",
            message: "Address Copied to clipboard",
            preferredStyle: UIAlertController.Style.alert
        )

        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    @IBAction func tAddressTapped(_ gesture: UIGestureRecognizer) {
        loggerProxy.event("copied to clipboard")

        UIPasteboard.general.string = tAddressLabel.text

        let alert = UIAlertController(
            title: "",
            message: "Address Copied to clipboard",
            preferredStyle: UIAlertController.Style.alert
        )

        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }
}
