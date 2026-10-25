//
//  ZcashError+LocalizedError.swift
//
//  Presents ZcashError values via the Foundation error-reporting machinery.
//  This lives outside ZcashError.swift because that file is generated; see
//  ZcashErrorCodeDefinition.swift.

import Foundation

extension ZcashError: LocalizedError {
    /// The code and the static per-case message, plus the redacted rust detail when there is one.
    ///
    /// The detail is what makes a user's error report actionable. Without it every failure in the
    /// four proposal and transaction-creation paths rendered as the same sentence, so a report
    /// said only that something in the rust layer went wrong (MOB-1201).
    public var errorDescription: String? {
        guard let detail else {
            return "\(code.rawValue): \(message)"
        }

        return "\(code.rawValue): \(message) (\(detail))"
    }
}
