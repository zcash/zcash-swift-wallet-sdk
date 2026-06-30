//
//  UsedAliasesChecker.swift
//
//
//  Created by Michal Fousek on 23.03.2023.
//

import Foundation

private var usedAliases: [ZcashSynchronizerAlias: UUID] = [:]
private let usedAliasesLock = NSLock()

// Utility used to track which SDKSynchronizer aliases are already in use.
enum UsedAliasesChecker {
    static func tryToUse(alias: ZcashSynchronizerAlias, id: UUID) -> Bool {
        usedAliasesLock.lock()
        defer { usedAliasesLock.unlock() }

        // Using of `id` allows one instance of the SDKSynchronizer to call is any time it wants and still pass the check. When `wipe()` is called it
        // starts using the alias. Then when `prepare()` is also registers alias. If the check for `id` wouldn't be here one instance of the
        // `SDKSynchronizer` couldn't call `prepare()` after wipe because this check wouldn't pass.
        //
        // `id` is uniquely generated for each instance of the `SDKSynchronizer`.
        if let idUsingAlias = usedAliases[alias] {
            return idUsingAlias == id
        } else {
            usedAliases[alias] = id
            return true
        }
    }

    static func stopUsing(alias: ZcashSynchronizerAlias, id: UUID) {
        usedAliasesLock.lock()
        defer { usedAliasesLock.unlock() }

        // When instance "owns" the alias the alias is removed and it's no longer registered as used.
        if let idUsingAlias = usedAliases[alias], idUsingAlias == id {
            usedAliases.removeValue(forKey: alias)
        }
    }
}
