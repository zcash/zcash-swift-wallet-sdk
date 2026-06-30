//
//  ZcashFileManager.swift
//
//
//  Created by Lukáš Korba on 23.05.2023.
//

import Foundation

protocol ZcashFileManager {
    func isReadableFile(atPath path: String) -> Bool
    func removeItem(at URL: URL) throws
    func isDeletableFile(atPath path: String) -> Bool
}

extension FileManager: ZcashFileManager { }
