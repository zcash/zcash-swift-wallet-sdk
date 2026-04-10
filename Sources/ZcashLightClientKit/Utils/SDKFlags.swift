//
//  SDKFlags.swift
//  ZcashLightClientKit
//
//  Created by Lukáš Korba on 2025-07-18.
//

import Foundation

/// A singleton actor with control flags for the SDK.
actor SDKFlags {
    /// `torEnabled` controls `SeviceMode` for the connection to the `LightWalletService`.
    /// When disabled, the `ServiceMode.direct` (GRPC) is enforced.
    /// When enabled, all Tor cases in `ServiceMode` are allowed.
    /// Accessible only internally inside the SDK to control the connection
    var torEnabled: Bool
    
    /// `exchangeRateEnabled` controls whether fetch of exnchage rate is enabled or disabled.
    /// When enabled, the `TorClient` is initialized but is not used for lwdService calls.
    var exchangeRateEnabled: Bool
    
    /// This flag communicates state of initialization of `TorClient`
    /// `nil` = the attempt to initialize `TorClient` hasn't been initiated
    /// `false` = initialization of `TorClient` failed
    /// `true` = initialization of `TorClient` succeeded
    var torClientInitializationSuccessfullyDone: Bool?
    
    /// Runtime helper flag used to mark whether chainTip CBP action has been done.
    var chainTipUpdated = false
    var chainTipUpdatedTimestamp: TimeInterval = 0.0

    /// Set after `checkWalletSpendability` succeeds. When true, Orchard
    /// spendableValue is preserved even before `chainTipUpdated` is set.
    var pirCompleted = false
    var pirCompletedTimestamp: TimeInterval = 0.0

    init(
        torEnabled: Bool,
        exchangeRateEnabled: Bool
    ) {
        self.torEnabled = torEnabled
        self.exchangeRateEnabled = exchangeRateEnabled
    }
    
    /// Helper method that wraps the decision logic for `ServiceMode`.
    /// When Tor is not enabled, it always must use fallback to `.direct` mode.
    func ifTor(_ serviceMode: ServiceMode) -> ServiceMode {
        torEnabled ? serviceMode : .direct
    }
    
    /// Use to update the `torEnabled` flag
    func torFlagUpdate(_ newFlag: Bool) {
        torEnabled = newFlag
    }
    
    // Use to update the `exchangeRateEnabled` flag
    func exchangeRateFlagUpdate(_ newFlag: Bool) {
        exchangeRateEnabled = newFlag
    }
    
    /// Use to update the `torClientInitializationSuccessfullyDone` flag
    func torClientInitializationSuccessfullyDoneFlagUpdate(_ newFlag: Bool?) {
        torClientInitializationSuccessfullyDone = newFlag
    }
    
    /// Use to update the `chainTipUpdated` flag
    func markChainTipAsUpdated() {
        chainTipUpdated = true
        chainTipUpdatedTimestamp = Date().timeIntervalSince1970
    }

    /// Use to mark PIR spendability check as completed
    func markPIRCompleted() {
        pirCompleted = true
        pirCompletedTimestamp = Date().timeIntervalSince1970
    }

    /// The client using the SDK called `start()`.
    /// Use this to reset or update any relevant flags if needed.
    func sdkStarted() {
        let now = Date().timeIntervalSince1970
        // If chain tip has been updated recently and is set to false, re-enable it
        if !chainTipUpdated && now - chainTipUpdatedTimestamp < 120 {
            chainTipUpdated = true
        }
    }

    /// The client using the SDK called `stop()`, for example when the app is about to enter the background lifecycle.
    /// Use this to reset or update any relevant flags if needed.
    func sdkStopped() {
        // The SDK is stopped, so there will be a gap before the next start (doesn’t matter whether it’s a cold or foreground start).
        // The chain tip might be old enough to cause issues when attempting to send or shield funds before the next chain tip update call finishes.
        // Therefore, it is reset here.
        chainTipUpdated = false
    }
}
