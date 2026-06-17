//
//  ConsoleLogger.swift
//  TestUtils
//

import Foundation
@testable import ZcashLightClientKit

/// A `Logger` that prints to stdout so SDK lifecycle logs are visible in
/// `swift test` console output.
///
/// The production `OSLogger` routes to `os_log` and is silent when the process
/// has no main-bundle identifier (which is the case under `swift test`), so the
/// submission unit tests use this when you want to *watch* what happens.
final class ConsoleLogger: Logger {
    private let minLevel: OSLogger.LogLevel

    init(minLevel: OSLogger.LogLevel = .debug) {
        self.minLevel = minLevel
    }

    func maxLogLevel() -> OSLogger.LogLevel? { minLevel }

    func debug(_ message: String, file: StaticString, function: StaticString, line: Int) {
        emit("DEBUG 🐞", message, file, line)
    }

    func info(_ message: String, file: StaticString, function: StaticString, line: Int) {
        emit("INFO ℹ️", message, file, line)
    }

    func event(_ message: String, file: StaticString, function: StaticString, line: Int) {
        emit("EVENT ⏱", message, file, line)
    }

    func warn(_ message: String, file: StaticString, function: StaticString, line: Int) {
        emit("WARNING ⚠️", message, file, line)
    }

    func error(_ message: String, file: StaticString, function: StaticString, line: Int) {
        emit("ERROR 💥", message, file, line)
    }

    func sync(_ message: String, file: StaticString, function: StaticString, line: Int) {
        emit("SYNC", message, file, line)
    }

    private func emit(_ level: String, _ message: String, _ file: StaticString, _ line: Int) {
        let fileName = (String(describing: file) as NSString).lastPathComponent
        print("[\(level)] \(fileName):\(line) → \(message)")
    }
}

/// The logger the transaction-submission unit tests inject so a transaction's
/// lifetime (creation, which server it is submitted to, successes, failures,
/// resubmission) is printed to the console during `swift test`.
///
/// Swap the return value to `NullLogger()` to silence the submission lifecycle
/// logs in test output.
func submissionLifecycleLogger() -> Logger {
    ConsoleLogger()
}
