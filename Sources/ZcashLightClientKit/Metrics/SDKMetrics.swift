//
//  SDKMetrics.swift
//
//
//  Created by Lukáš Korba on 13.12.2022.
//

import Foundation

protocol SDKMetrics {
    func cbpStart()
    func actionStart(_ action: CBPState)
    func actionDetail(_ detail: String, `for` action: CBPState)
    func actionStop()
    func logCBPOverviewReport(_ logger: Logger, walletSummary: WalletSummary?) async
}

final class SDKMetricsImpl: SDKMetrics {
    public struct CBPStateMetricReport: Equatable {
        static let zero = Self(runs: 0, startTime: 0, cummulativeTime: 0, maxTime: 0, avgTime: 0)

        var runs: Int
        var startTime: TimeInterval
        var cummulativeTime: TimeInterval
        var minTime: TimeInterval = .infinity
        var maxTime: TimeInterval
        var avgTime: TimeInterval

        var details: [String] = []
    }

    // Compact Block Processor Metrics
    var syncs = 0
    var cbpStartTime: TimeInterval = 0
    var cbpOverview: [CBPState: CBPStateMetricReport] = [:]
    var lastActionInRun: CBPState?

    public init() { }

    func cbpStart() {
        syncs += 1
        cbpStartTime = Date().timeIntervalSince1970

        // reset of previous values
        cbpOverview.removeAll()
    }

    func actionStart(_ action: CBPState) {
        actionStop()

        lastActionInRun = action

        var report = CBPStateMetricReport.zero

        if let reportFound = cbpOverview[action] {
            report = reportFound
        }

        report.runs += 1
        report.startTime = Date().timeIntervalSince1970

        cbpOverview[action] = report
    }

    func actionDetail(_ detail: String, `for` action: CBPState) {
        guard var report = cbpOverview[action] else { return }

        report.details.append(detail)

        cbpOverview[action] = report
    }

    func actionStop() {
        guard let lastActionInRun else {
            return
        }

        guard var report = cbpOverview[lastActionInRun] else {
            return
        }

        let endTime = Date().timeIntervalSince1970
        let runTime = endTime - report.startTime

        report.cummulativeTime += runTime

        if runTime < report.minTime {
            report.minTime = runTime
        }

        if runTime > report.maxTime {
            report.maxTime = runTime
        }

        if report.runs > 0 {
            report.avgTime = report.cummulativeTime / Double(report.runs)
        }

        cbpOverview[lastActionInRun] = report
    }

    // swiftlint:disable:next string_concatenation
    func logCBPOverviewReport(_ logger: Logger, walletSummary: WalletSummary?) async {
        actionStop()

        logger.sync(
            """
            SYNC (\(syncs)) REPORT
            finished in: \(Date().timeIntervalSince1970 - cbpStartTime)
            """
        )

        if let accountBalances = walletSummary?.accountBalances {
            for accountBalance in accountBalances {
                logger.sync(
                """
                account index: \(accountBalance.key)
                    verified balance: \(accountBalance.value.saplingBalance.spendableValue.amount)
                    total balance: \(accountBalance.value.saplingBalance.total().amount)
                """
                )
            }
        }

        try? await Task.sleep(nanoseconds: 100_000)

        for action in cbpOverview {
            let report = action.value

            var resText = """
                action:             \(action.key)
                runs:               \(report.runs)
                cummulativeTime:    \(report.cummulativeTime)
                minTime:            \(report.minTime)
                maxTime:            \(report.maxTime)
                avgTime:            \(report.avgTime)
                """

            if !report.details.isEmpty {
                resText = "\(resText)\ndetails:\n"

                for detail in report.details {
                    resText = "\(resText)\t\(detail)\n"
                }
            }

            logger.sync(resText)
        }
    }
}
