//
//  SaplingParametersViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 10/7/20.
//  Copyright © 2020 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit

// swiftlint:disable force_try
class SaplingParametersViewController: UIViewController {
    @IBOutlet weak var outputPath: UILabel!
    @IBOutlet weak var spendPath: UILabel!
    @IBOutlet weak var downloadButton: UIButton!
    @IBOutlet weak var deleteButton: UIButton!

    override func viewDidLoad() {
        super.viewDidLoad()
        let spendParamPath = try! spendParamsURLHelper().path
        let outputParamPath = try! outputParamsURLHelper().path

        self.spendPath.text = spendParamPath
        self.outputPath.text = outputParamPath
        self.updateColor()
        self.spendPath.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(spendPathTapped(_:))))
        self.outputPath.addGestureRecognizer(UITapGestureRecognizer(target: self, action: #selector(outputPathTapped(_:))))
        self.outputPath.isUserInteractionEnabled = true
        self.spendPath.isUserInteractionEnabled = true

        self.updateButtons()
    }

    func updateButtons() {
        let spendParamPath = try! spendParamsURLHelper().path
        let outputParamPath = try! outputParamsURLHelper().path
        self.downloadButton.isHidden = fileExists(outputParamPath) && fileExists(spendParamPath)
        self.deleteButton.isHidden = !(fileExists(outputParamPath) || fileExists(spendParamPath))
    }

    func updateColor() {
        let spendParamPath = try! spendParamsURLHelper().path
        let outputParamPath = try! outputParamsURLHelper().path
        self.spendPath.textColor = fileExists(spendParamPath) ? UIColor.green : UIColor.red
        self.outputPath.textColor = fileExists(outputParamPath) ? UIColor.green : UIColor.red
    }

    @objc func spendPathTapped(_ gesture: UIGestureRecognizer) {
        loggerProxy.event("copied to clipboard:\(self.spendPath.text ?? "")")

        UIPasteboard.general.string = self.spendPath.text

        let alert = UIAlertController(
            title: "",
            message: "Path Copied to clipboard",
            preferredStyle: UIAlertController.Style.alert
        )

        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    @objc func outputPathTapped(_ gesture: UIGestureRecognizer) {
        loggerProxy.event("copied to clipboard:\(self.outputPath.text ?? "")")

        UIPasteboard.general.string = self.outputPath.text

        let alert = UIAlertController(
            title: "",
            message: "Path Copied to clipboard",
            preferredStyle: UIAlertController.Style.alert
        )

        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    @IBAction func download(_ sender: Any) {
        let outputParameter = try! outputParamsURLHelper()
        let spendParameter = try! spendParamsURLHelper()

        Task { @MainActor in
            do {
                let urls = try await SaplingParameterDownloader.downloadParamsIfnotPresent(
                    spendURL: spendParameter,
                    spendSourceURL: SaplingParamsSourceURL.default.spendParamFileURL,
                    outputURL: outputParameter,
                    outputSourceURL: SaplingParamsSourceURL.default.outputParamFileURL,
                    logger: loggerProxy
                )
                spendPath.text = urls.spend.path
                outputPath.text = urls.output.path
                updateColor()
                updateButtons()
            } catch {
                showError(error)
            }
        }
    }

    func fileExists(_ path: String) -> Bool {
        (try? FileManager.default.attributesOfItem(atPath: path)) != nil
    }

    func showError(_ error: Error) {
        let alert = UIAlertController(
            title: "Download Failed",
            message: "\(error)",
            preferredStyle: UIAlertController.Style.alert
        )

        alert.addAction(UIAlertAction(title: "OK", style: UIAlertAction.Style.default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    @IBAction func deleteFiles(_ sender: Any) {
        let spendParamURL = try! spendParamsURLHelper()
        let outputParamURL = try! outputParamsURLHelper()

        try? FileManager.default.removeItem(at: spendParamURL)
        try? FileManager.default.removeItem(at: outputParamURL)
        self.updateColor()
        self.updateButtons()
    }
}
