//
//  SendViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 12/3/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Combine
import UIKit
import ZcashLightClientKit
import KRProgressHUD

class SendViewController: UIViewController {
    @IBOutlet weak var addressLabel: UILabel!
    @IBOutlet weak var amountLabel: UILabel!
    @IBOutlet weak var addressTextField: UITextField!
    @IBOutlet weak var amountTextField: UITextField!
    @IBOutlet weak var balanceLabel: UILabel!
    @IBOutlet weak var verifiedBalanceLabel: UILabel!
    @IBOutlet weak var maxFunds: UISwitch!
    @IBOutlet weak var sendButton: UIButton!
    @IBOutlet weak var synchronizerStatusLabel: UILabel!
    @IBOutlet weak var memoField: UITextView!
    @IBOutlet weak var charactersLeftLabel: UILabel!

    let characterLimit: Int = 512
    var wallet = Initializer.shared

    // swiftlint:disable:next implicitly_unwrapped_optional
    var synchronizer: Synchronizer!
    // swiftlint:disable:next implicitly_unwrapped_optional
    var closureSynchronizer: ClosureSynchronizer!

    var cancellables: [AnyCancellable] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        synchronizer = AppDelegate.shared.sharedSynchronizer
        closureSynchronizer = ClosureSDKSynchronizer(synchronizer: AppDelegate.shared.sharedSynchronizer)
        let tapRecognizer = UITapGestureRecognizer(target: self, action: #selector(viewTapped(_:)))
        self.view.addGestureRecognizer(tapRecognizer)
        setUp()

        closureSynchronizer.prepare(
            with: DemoAppConfig.defaultSeed,
            walletBirthday: DemoAppConfig.defaultBirthdayHeight,
            for: .existingWallet,
            name: "",
            keySource: nil
        ) { result in
            loggerProxy.debug("Prepare result: \(result)")
        }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        closureSynchronizer.start(retry: false) { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                self.synchronizerStatusLabel.text = SDKSynchronizer.textFor(state: self.synchronizer.latestState.syncStatus)

                if let error {
                    self.fail(error)
                }
            }
        }
    }

    @objc func viewTapped(_ recognizer: UITapGestureRecognizer) {
        let point = recognizer.location(in: self.view)
        if addressTextField.isFirstResponder && !addressTextField.frame.contains(point) {
            addressTextField.resignFirstResponder()
        } else if amountTextField.isFirstResponder && !amountTextField.frame.contains(point) {
            amountTextField.resignFirstResponder()
        } else if memoField.isFirstResponder &&
            !memoField.frame.contains(point) {
            memoField.resignFirstResponder()
        }
    }

    func setUp() {
        Task { @MainActor in
            await updateBalance()
            await toggleSendButton()
        }
        memoField.text = ""
        memoField.layer.borderColor = UIColor.gray.cgColor
        memoField.layer.borderWidth = 1
        memoField.layer.cornerRadius = 5
        charactersLeftLabel.text = textForCharacterCount(0)

        synchronizer.stateStream
            .throttle(for: .seconds(0.2), scheduler: DispatchQueue.main, latest: true)
            .sink(
                receiveValue: { [weak self] state in
                    Task { @MainActor in
                        await self?.updateBalance()
                    }
                    self?.synchronizerStatusLabel.text = SDKSynchronizer.textFor(state: state.syncStatus)
                }
            )
            .store(in: &cancellables)
    }

    func updateBalance() async {
        Task { @MainActor in
            guard let account = try? await synchronizer.listAccounts().first else {
                return
            }
            balanceLabel.text = format(
                balance: (try? await synchronizer.getAccountsBalances()[account.id])?.saplingBalance.total() ?? .zero
            )
            verifiedBalanceLabel.text = format(
                balance: (try? await synchronizer.getAccountsBalances()[account.id])?.saplingBalance.spendableValue ?? .zero
            )
        }
    }

    func format(balance: Zatoshi = Zatoshi()) -> String {
        "Zec \(balance.formattedString ?? "0.0")"
    }

    func toggleSendButton() async {
        sendButton.isEnabled = await isFormValid()
    }

    func maxFundsOn() {
        Task { @MainActor in
            guard let account = try? await synchronizer.listAccounts().first else {
                return
            }

            let fee = Zatoshi(10000)
            let max: Zatoshi = ((try? await synchronizer.getAccountsBalances()[account.id])?.saplingBalance.spendableValue ?? .zero) - fee
            amountTextField.text = format(balance: max)
            amountTextField.isEnabled = false
        }
    }

    func maxFundsOff() {
        amountTextField.isEnabled = true
    }

    func isFormValid() async -> Bool {
        switch synchronizer.latestState.syncStatus {
        case .upToDate:
            let isBalanceValid = await self.isBalanceValid()
            let isAmountValid = await self.isAmountValid()
            return isBalanceValid && isAmountValid && isRecipientValid()
        default:
            return false
        }
    }

    func isBalanceValid() async -> Bool {
        guard let account = try? await synchronizer.listAccounts().first else {
            return false
        }
        let balance = (try? await synchronizer.getAccountsBalances()[account.id])?.saplingBalance.spendableValue ?? .zero
        return balance > .zero
    }

    func isAmountValid() async -> Bool {
        guard let account = try? await synchronizer.listAccounts().first else {
            return false
        }
        let balance = (try? await synchronizer.getAccountsBalances()[account.id])?.saplingBalance.spendableValue ?? .zero
        guard
            let value = amountTextField.text,
            let amount = NumberFormatter.zcashNumberFormatter.number(from: value).flatMap({ Zatoshi($0.int64Value) }),
            amount <= balance
        else {
            return false
        }

        return true
    }

    func isRecipientValid() -> Bool {
        guard let addr = self.addressTextField.text else {
            return false
        }
        return wallet.isValidSaplingAddress(addr) || wallet.isValidTransparentAddress(addr)
    }

    @IBAction func maxFundsValueChanged(_ sender: Any) {
        if maxFunds.isOn {
            maxFundsOn()
        } else {
            maxFundsOff()
        }
    }

    @IBAction func send(_ sender: Any) {
        Task { @MainActor in
            guard await isFormValid() else {
                loggerProxy.warn("WARNING: Form is invalid")
                return
            }

            let alert = UIAlertController(
                title: "About To send funds!",
                message: """
            This is an ugly confirmation message. You should come up with something fancier that lets the user be sure about sending funds without \
            disturbing the user experience with an annoying alert like this one
            """,
                preferredStyle: UIAlertController.Style.alert
            )

            let sendAction = UIAlertAction(
                title: "Send!",
                style: UIAlertAction.Style.default,
                handler: { _ in
                    self.send()
                }
            )

            let cancelAction = UIAlertAction(
                title: "Go back! I'm not sure about this.",
                style: UIAlertAction.Style.destructive,
                handler: { _ in
                    self.cancel()
                }
            )

            alert.addAction(sendAction)
            alert.addAction(cancelAction)

            self.present(alert, animated: true, completion: nil)
        }
    }

    func send() {
        Task { @MainActor in
            guard
                await isFormValid(),
                let amount = amountTextField.text,
                NumberFormatter.zcashNumberFormatter.number(from: amount).flatMap({ Zatoshi($0.int64Value) }) != nil,
                addressTextField.text != nil
            else {
                loggerProxy.warn("WARNING: Form is invalid")
                return
            }

            let derivationTool = DerivationTool(networkType: kZcashNetwork.networkType)
            let usk = try? derivationTool.deriveUnifiedSpendingKey(seed: DemoAppConfig.defaultSeed, accountIndex: Zip32AccountIndex(0))
            guard usk != nil else {
                loggerProxy.error("NO SPENDING KEY")
                return
            }

            KRProgressHUD.show()

            KRProgressHUD.dismiss()
        }
    }

    func fail(_ error: Error) {
        let alert = UIAlertController(
            title: "Send failed!",
            message: "\(error)",
            preferredStyle: UIAlertController.Style.alert
        )

        let action = UIAlertAction(title: "OK :(", style: UIAlertAction.Style.default, handler: nil)
        alert.addAction(action)
        self.present(alert, animated: true, completion: nil)
    }

    func cancel() {}

    func textForCharacterCount(_ count: Int) -> String {
        "\(count) of \(characterLimit) bytes left"
    }
}

extension SendViewController: UITextFieldDelegate {
    func textFieldShouldBeginEditing(_ textField: UITextField) -> Bool {
        if textField == amountTextField {
            return !maxFunds.isOn
        }
        return true
    }

    func textFieldDidEndEditing(_ textField: UITextField) {
        textField.resignFirstResponder()
        Task { @MainActor in
            await toggleSendButton()
        }
    }

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        if textField == amountTextField {
            addressTextField.becomeFirstResponder()
            return false
        }
        textField.resignFirstResponder()
        return true
    }
}

extension SendViewController: UITextViewDelegate {
    func textView(_ textView: UITextView, shouldChangeTextIn range: NSRange, replacementText text: String) -> Bool {
        let userPressedDelete = text.isEmpty && range.length > 0
        return textView.text.utf8.count < characterLimit || userPressedDelete
    }

    func textViewDidChange(_ textView: UITextView) {
        self.charactersLeftLabel.text = textForCharacterCount(textView.text.utf8.count)
    }
}

extension SDKSynchronizer {
    static func textFor(state: SyncStatus) -> String {
        switch state {
        case let .syncing(syncProgress, areFundsSpendable):
            return "Syncing \(syncProgress * 100.0)% spendable: \(areFundsSpendable)"

        case .upToDate:
            return "Up to Date 😎"

        case .unprepared:
            return "Unprepared 😅"

        case .stopped:
            return "Stopped"

        case .error(ZcashError.synchronizerDisconnected):
            return "disconnected 💔"

        case .error(let error):
            return "Error: \(error)"
        }
    }
}

extension Optional where Wrapped == String {
    func asMemo() throws -> Memo {
        switch self {
        case .some(let string):
            return try Memo(string: string)
        case .none:
            return .empty
        }
    }
}
