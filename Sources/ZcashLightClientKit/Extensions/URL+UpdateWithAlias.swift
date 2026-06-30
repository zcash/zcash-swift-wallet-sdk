//
//  URL+UpdateWithAlias.swift
//
//
//  Created by Michal Fousek on 23.03.2023.
//

import Foundation

extension URL {
    /// Try to update URLs with `alias`.
    ///
    /// If the `default` alias is used then the URL isn't changed at all.
    /// If the `custom("anotherInstance")` is used then last path component or the URL is updated like this:
    /// - /some/path/to.file -> /some/path/c_anotherInstance_to.file
    /// - /some/path/to/directory -> /some/path/to/c_anotherInstance_directory
    ///
    /// If the URLs can't be parsed then `nil` is returned.
    func updateLastPathComponent(with alias: ZcashSynchronizerAlias) -> URL? {
        let lastPathComponent = self.lastPathComponent
        guard !lastPathComponent.isEmpty else {
            return nil
        }

        switch alias {
        case .`default`:
            // When using default alias everything should work as before aliases to be backwards compatible.
            return self

        case .custom:
            let newLastPathComponent = "\(alias.description)_\(lastPathComponent)"
            return self.deletingLastPathComponent()
                .appendingPathComponent(newLastPathComponent)
        }
    }
}
