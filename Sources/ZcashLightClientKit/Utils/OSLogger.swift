//
//  OSLogger.swift
//
//
//  Created by Lukáš Korba on 26.01.2023.
//

import Foundation
import os

public class OSLogger: Logger {
    public let alias: ZcashSynchronizerAlias?

    public enum LogLevel: Int {
        case debug
        case info
        case event
        case warning
        case error
    }

    public let oslog: OSLog?

    var level: LogLevel

    public init(
        logLevel: LogLevel,
        category: String = "sdkLogs",
        alias: ZcashSynchronizerAlias? = nil
    ) {
        self.alias = alias
        self.level = logLevel
        if let bundleName = Bundle.main.bundleIdentifier {
            var postfix = ""
            if let alias { postfix = "_\(alias.description)" }
            self.oslog = OSLog(subsystem: bundleName, category: "\(category)\(postfix)")
        } else {
            oslog = nil
        }
    }

    public func maxLogLevel() -> LogLevel? {
        self.level
    }

    public func debug(
        _ message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        guard level.rawValue == LogLevel.debug.rawValue else { return }
        log(
            level: "DEBUG 🐞",
            logType: .debug,
            message: message,
            file: file,
            function: function,
            line: line
        )
    }

    public func info(
        _ message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        guard level.rawValue <= LogLevel.info.rawValue else { return }
        log(
            level: "INFO ℹ️",
            logType: .info,
            message: message,
            file: file,
            function: function,
            line: line
        )
    }

    public func event(
        _ message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        guard level.rawValue <= LogLevel.event.rawValue else { return }
        log(
            level: "EVENT ⏱",
            logType: .default,
            message: message,
            file: file,
            function: function,
            line: line
        )
    }

    public func warn(
        _ message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        guard level.rawValue <= LogLevel.warning.rawValue else { return }
        log(
            level: "WARNING ⚠️",
            logType: .default,
            message: message,
            file: file,
            function: function,
            line: line
        )
    }

    public func error(
        _ message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        guard level.rawValue <= LogLevel.error.rawValue else { return }
        log(
            level: "ERROR 💥",
            logType: .error,
            message: message,
            file: file,
            function: function,
            line: line
        )
    }

    public func sync(
        _ message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        log(
            level: "SYNC_METRIC",
            logType: .info,
            message: message,
            file: file,
            function: function,
            line: line
        )
    }

    private func log(
        level: String,
        logType: OSLogType,
        message: String,
        file: StaticString = #file,
        function: StaticString = #function,
        line: Int = #line
    ) {
        guard let oslog else { return }

        let fileName = (String(describing: file) as NSString).lastPathComponent

        os_log(
            "[%{public}@] %{public}@ - %{public}@ - Line: %{public}d -> %{public}@",
            log: oslog,
            type: logType,
            level,
            fileName,
            String(describing: function),
            line,
            message
        )
    }
}
