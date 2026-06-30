//
//  AppDelegate.swift
//  ZcashLightClientSample
//
//  Created by Francisco Gindre on 06/09/2019.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Combine
import UIKit
import ZcashLightClientKit
import NotificationBubbles

var loggerProxy = OSLogger(logLevel: .debug)

// swiftlint:disable force_cast force_try force_unwrapping
@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    var cancellables: [AnyCancellable] = []
    var window: UIWindow?
    private var wallet: Initializer?
    private var synchronizer: SDKSynchronizer?

    let accountIndex = Zip32AccountIndex(0)

    var sharedSynchronizer: SDKSynchronizer {
        if let sync = synchronizer {
            return sync
        } else {
            let sync = SDKSynchronizer(initializer: sharedWallet) // this must break if fails
            self.synchronizer = sync
            return sync
        }
    }

    var sharedViewingKey: UnifiedFullViewingKey {
        let derivationTool = DerivationTool(networkType: kZcashNetwork.networkType)
        let spendingKey = try! derivationTool
            .deriveUnifiedSpendingKey(seed: DemoAppConfig.defaultSeed, accountIndex: accountIndex)

        return try! derivationTool.deriveUnifiedFullViewingKey(from: spendingKey)
    }

    var sharedWallet: Initializer {
        if let wallet {
            return wallet
        } else {
            let wallet = Initializer(
                cacheDbURL: nil,
                fsBlockDbRoot: try! fsBlockDbRootURLHelper(),
                generalStorageURL: try! generalStorageURLHelper(),
                dataDbURL: try! dataDbURLHelper(),
                torDirURL: try! torDirURLHelper(),
                endpoint: DemoAppConfig.endpoint,
                network: kZcashNetwork,
                spendParamsURL: try! spendParamsURLHelper(),
                outputParamsURL: try! outputParamsURLHelper(),
                saplingParamsSourceURL: SaplingParamsSourceURL.default,
                isTorEnabled: false,
                isExchangeRateEnabled: false
            )

            self.wallet = wallet
            return wallet
        }
    }

    func subscribeToMinedTxNotifications() {
        sharedSynchronizer.eventStream
            .map { event in
                guard case let .minedTransaction(transaction) = event else { return nil }
                return transaction
            }
            .compactMap { $0 }
            .receive(on: DispatchQueue.main)
            .sink(
                receiveValue: { [weak self] transaction in self?.txMined(transaction) }
            )
            .store(in: &cancellables)
    }

    func txMined(_ transaction: ZcashTransaction.Overview) {
        NotificationBubble.display(
            in: window!.rootViewController!.view,
            options: NotificationBubble.sucessOptions(
                animation: NotificationBubble.Animation.fade(duration: 1)
            ),
            attributedText: NSAttributedString(string: "Transaction \(String(describing: transaction.rawID))mined!"),
            handleTap: {}
        )
    }

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.
        subscribeToMinedTxNotifications()

        return true
    }

    func applicationWillResignActive(_ application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
    }
}

/**
The functions below are convenience functions for THIS SAMPLE APP.
*/
extension AppDelegate {
    static var shared: AppDelegate {
        UIApplication.shared.delegate as! AppDelegate
    }

    func wipe(completion completionClosure: @escaping (Error?) -> Void) {
        guard let synchronizer = (UIApplication.shared.delegate as? AppDelegate)?.sharedSynchronizer else { return }

        // At this point app should show some loader or some UI that indicates action. If the sync is not running then wipe happens immediately.
        // But if the sync is in progress then the SDK must first stop it. And it may take some time.

        synchronizer.wipe()
            // Delay is here to be sure that previously showed alerts are gone and it's safe to show another. Or I want to show loading UI for at
            // least one second in case that wipe happens immediately.
            .delay(for: .seconds(1), scheduler: DispatchQueue.main, options: .none)
            .sink(
                receiveCompletion: { completion in
                    switch completion {
                    case .finished:
                        completionClosure(nil)
                    case .failure(let error):
                        completionClosure(error)
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)
    }
}

extension Initializer {
    static var shared: Initializer {
        AppDelegate.shared.sharedWallet // AppDelegate or DIE.
    }
}

extension Synchronizer {
    static var shared: Synchronizer {
        AppDelegate.shared.sharedSynchronizer
    }
}

func documentsDirectoryHelper() throws -> URL {
    try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
}

func fsBlockDbRootURLHelper() throws -> URL {
    try documentsDirectoryHelper()
        .appendingPathComponent(kZcashNetwork.networkType.chainName)
        .appendingPathComponent(
            ZcashSDK.defaultFsCacheName,
            isDirectory: true
        )
}

func generalStorageURLHelper() throws -> URL {
    try documentsDirectoryHelper()
        .appendingPathComponent(kZcashNetwork.networkType.chainName)
        .appendingPathComponent(
            "general_storage",
            isDirectory: true
        )
}

func cacheDbURLHelper() throws -> URL {
    try documentsDirectoryHelper()
        .appendingPathComponent(
            kZcashNetwork.constants.defaultDbNamePrefix + ZcashSDK.defaultCacheDbName,
            isDirectory: false
        )
}

func dataDbURLHelper() throws -> URL {
    try documentsDirectoryHelper()
        .appendingPathComponent(
            kZcashNetwork.constants.defaultDbNamePrefix + ZcashSDK.defaultDataDbName,
            isDirectory: false
        )
}

func torDirURLHelper() throws -> URL {
    try documentsDirectoryHelper()
        .appendingPathComponent(kZcashNetwork.networkType.chainName)
        .appendingPathComponent(
            ZcashSDK.defaultTorDirName,
            isDirectory: true
        )
}

func spendParamsURLHelper() throws -> URL {
    try documentsDirectoryHelper().appendingPathComponent("sapling-spend.params")
}

func outputParamsURLHelper() throws -> URL {
    try documentsDirectoryHelper().appendingPathComponent("sapling-output.params")
}

public extension NotificationBubble {
    static func sucessOptions(animation: NotificationBubble.Animation) -> [NotificationBubble.Style] {
        return [
            NotificationBubble.Style.animation(animation),
            NotificationBubble.Style.margins(UIEdgeInsets(top: 40, left: 0, bottom: 0, right: 0)),
            NotificationBubble.Style.cornerRadius(8),
            NotificationBubble.Style.duration(timeInterval: 10),
            NotificationBubble.Style.backgroundColor(UIColor.green)
        ]
    }
}
