//
//  TestServersViewController.swift
//  ZcashLightClientSample
//
//  Created by Lukáš Korba on 05.07.2024.
//  Copyright © 2024 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit

class TestServersViewController: UIViewController {
    let endpoints: [LightWalletEndpoint] = [
        LightWalletEndpoint(address: "zec.rocks", port: 443),
        LightWalletEndpoint(address: "na.zec.rocks", port: 443),
        LightWalletEndpoint(address: "sa.zec.rocks", port: 443),
        LightWalletEndpoint(address: "eu.zec.rocks", port: 443),
        LightWalletEndpoint(address: "ap.zec.rocks", port: 443),
        LightWalletEndpoint(address: "lwd1.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd2.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd3.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd4.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd5.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd6.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd7.zcash-infra.com", port: 9067),
        LightWalletEndpoint(address: "lwd8.zcash-infra.com", port: 9067)
    ]

    @IBOutlet weak var resultsLabel: UILabel!
    @IBOutlet weak var testServersBtn: UIButton!

    var startTime: TimeInterval = 0.0

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    @IBAction func testServers(_ sender: Any) {
        let synchronizer = AppDelegate.shared.sharedSynchronizer
        testServersBtn.isEnabled = false

        startTime = Date().timeIntervalSince1970

        Task {
            let results = await synchronizer.evaluateBestOf(endpoints: endpoints)

            await showResults(results)
        }
    }

    @MainActor func showResults(_ endpoints: [LightWalletEndpoint]) async {
        testServersBtn.isEnabled = true

        var resultStr = ""

        var counter = 1
        endpoints.forEach {
            resultStr = "\(resultStr) \(counter). \($0.host):\($0.port)\n"
            counter += 1
        }

        resultStr = "\(resultStr) \n"

        resultStr = "\(resultStr) time to evaluate all: \(Date().timeIntervalSince1970 - startTime)s"

        resultsLabel.text = resultStr
    }
}
