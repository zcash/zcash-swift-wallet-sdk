//
//  undescribable.swift
//
//
//  Created by Francisco Gindre on 8/30/22.
//

public protocol Undescribable: CustomStringConvertible, CustomDebugStringConvertible, CustomLeafReflectable {}

extension Undescribable {
    public var description: String {
        return "--redacted--"
    }

    public var debugDescription: String {
        return "--redacted--"
    }

    public var customMirror: Mirror {
        return Mirror(reflecting: "--redacted--")
    }
}
