//
//  Zatoshi.swift
//  secant-testnet
//
//  Created by Lukáš Korba on 26.05.2022.
//  Modified and ported to ZcashLightClientKit by Francisco Gindre

import Foundation

public struct Zatoshi {
    public enum Constants {
        public static let oneZecInZatoshi: Int64 = 100_000_000
        public static let maxZecSupply: Int64 = 21_000_000
        public static let maxZatoshi: Int64 = Constants.oneZecInZatoshi * Constants.maxZecSupply
    }

    public static var zero: Zatoshi { Zatoshi() }

    public static let decimalHandler = NSDecimalNumberHandler(
        roundingMode: NSDecimalNumber.RoundingMode.bankers,
        scale: 8,
        raiseOnExactness: true,
        raiseOnOverflow: true,
        raiseOnUnderflow: true,
        raiseOnDivideByZero: true
    )

    @Clamped(-Constants.maxZatoshi...Constants.maxZatoshi)
    public var amount: Int64 = 0

    /// Converts `Zatoshi` to `NSDecimalNumber`
    public var decimalValue: NSDecimalNumber {
        NSDecimalNumber(decimal: Decimal(amount) / Decimal(Constants.oneZecInZatoshi))
    }

    public init(_ amount: Int64 = 0) {
        self.amount = amount
    }
    /// Converts `Zatoshi` to human readable format, up to 8 fraction digits
    public func decimalString(formatter: NumberFormatter = NumberFormatter.zcashNumberFormatter) -> String {
        formatter.string(from: decimalValue.roundedZec) ?? ""
    }

    /// Converts `Decimal` to `Zatoshi`
    public static func from(decimal: Decimal) -> Zatoshi {
        let roundedZec = NSDecimalNumber(decimal: decimal).roundedZec
        let zec2zatoshi = Decimal(Constants.oneZecInZatoshi) * roundedZec.decimalValue
        return Zatoshi(NSDecimalNumber(decimal: zec2zatoshi).int64Value)
    }

    /// Converts `String` to `Zatoshi`
    public static func from(decimalString: String, formatter: NumberFormatter = NumberFormatter.zcashNumberFormatter) -> Zatoshi? {
        if let number = formatter.number(from: decimalString) {
            return Zatoshi.from(decimal: number.decimalValue)
        }

        return nil
    }

    public static func + (left: Zatoshi, right: Zatoshi) -> Zatoshi {
        Zatoshi(left.amount + right.amount)
    }

    public static func - (left: Zatoshi, right: Zatoshi) -> Zatoshi {
        Zatoshi(left.amount - right.amount)
    }
}

extension Zatoshi: Equatable {
    public static func == (lhs: Zatoshi, rhs: Zatoshi) -> Bool {
        lhs.amount == rhs.amount
    }
}

extension Zatoshi: Comparable {
    public static func < (lhs: Zatoshi, rhs: Zatoshi) -> Bool {
        lhs.amount < rhs.amount
    }
}

public extension NSDecimalNumber {
    /// Round the decimal to 8 fraction digits
    var roundedZec: NSDecimalNumber {
        self.rounding(accordingToBehavior: Zatoshi.decimalHandler)
    }

    /// Converts `NSDecimalNumber` to human readable format, up to 8 fraction digits
    var decimalString: String {
        self.roundedZec.stringValue
    }
}

extension Zatoshi: Codable {
    enum CodingKeys: String, CodingKey {
        case amount
    }

    public init(from decoder: Decoder) throws {
        do {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            self.amount = try values.decode(Int64.self, forKey: .amount)
        } catch {
            throw ZcashError.zatoshiDecode(error)
        }
    }

    public func encode(to encoder: Encoder) throws {
        do {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(self.amount, forKey: .amount)
        } catch {
            throw ZcashError.zatoshiEncode(error)
        }
    }
}
