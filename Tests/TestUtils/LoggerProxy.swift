//
//  LoggerProxy.swift
//
//
//  Created by Lukáš Korba on 27.03.2023.
//

import Foundation
import ZcashLightClientKit

var logger = OSLogger(logLevel: .debug)

enum LoggerProxy {
    static func debug(_ message: String, file: StaticString = #file, function: StaticString = #function, line: Int = #line) {
        logger.debug(message, file: file, function: function, line: line)
    }

    static func info(_ message: String, file: StaticString = #file, function: StaticString = #function, line: Int = #line) {
        logger.info(message, file: file, function: function, line: line)
    }

    static func event(_ message: String, file: StaticString = #file, function: StaticString = #function, line: Int = #line) {
        logger.event(message, file: file, function: function, line: line)
    }

    static func warn(_ message: String, file: StaticString = #file, function: StaticString = #function, line: Int = #line) {
        logger.warn(message, file: file, function: function, line: line)
    }

    static func error(_ message: String, file: StaticString = #file, function: StaticString = #function, line: Int = #line) {
        logger.error(message, file: file, function: function, line: line)
    }
}
