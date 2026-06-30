//
//  LatestHeightViewController.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 10/31/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import UIKit
import ZcashLightClientKit

class LatestHeightViewController: UIViewController {
    @IBOutlet weak var blockHeightLabel: UILabel!

    let synchronizer = AppDelegate.shared.sharedSynchronizer
    var model: BlockHeight? {
        didSet {
            if viewIfLoaded != nil {
                setup()
            }
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        setup()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)

        /// Note: It's safe to modify model or call fail() because all methods of a UIViewController are MainActor methods by default.
        Task {
            do {
                model = try await synchronizer.latestHeight()
            } catch {
                fail(error)
            }
        }
    }

    func setup() {
        guard let model = self.model else {
            return
        }

        blockHeightLabel.text = String(model)
    }

    func fail(_ error: Error) {
        self.blockHeightLabel.text = "Error"

        let alert = UIAlertController(title: "Error", message: String(describing: error), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .cancel, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }
}
