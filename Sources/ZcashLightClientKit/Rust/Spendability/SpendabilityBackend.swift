// Swift wrapper for the PIR C FFI (spendability.rs + witness.rs).
// Stateless — each call connects to the PIR server and returns.

import Foundation
import libzcashlc

// MARK: - Error

public enum SpendabilityBackendError: LocalizedError, Equatable {
    case rustError(String)

    public var errorDescription: String? {
        switch self {
        case .rustError(let message):
            return "Spendability backend error: \(message)"
        }
    }
}

// MARK: - SpendabilityBackend

/// Wraps the PIR network FFI. Stateless — no DB handle, no persistent connection.
public struct SpendabilityBackend: Sendable {
    public init() {}

    /// Check nullifiers against the PIR server. No database access.
    ///
    /// - Parameters:
    ///   - notes: Unspent notes with nullifiers (from phase 1 DB read).
    ///   - pirServerUrl: Base URL of the spend-server.
    ///   - progress: Optional progress callback (0.0..1.0).
    /// - Returns: A `PIRNullifierCheckResult` with spent flags and server metadata.
    public func checkNullifiersPIR(
        notes: [PIRUnspentNote],
        pirServerUrl: String,
        progress: SpendabilityProgressHandler?
    ) throws -> PIRNullifierCheckResult {
        let urlBytes = [UInt8](pirServerUrl.utf8)

        let nullifiers: [[UInt8]] = notes.map { $0.nf }
        let nullifiersJSON = try JSONEncoder().encode(nullifiers)

        var context = SpendabilityProgressContext(handler: progress)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = urlBytes.withUnsafeBufferPointer { urlBuf in
            nullifiersJSON.withUnsafeBytes { nfBuf in
                withUnsafeMutablePointer(to: &context) { ctxPtr in
                    let callback: (@convention(c) (Double, UnsafeMutableRawPointer?) -> Void)? =
                        progress != nil ? spendabilityProgressTrampoline : nil
                    return zcashlc_check_nullifiers_pir(
                        urlBuf.baseAddress,
                        UInt(urlBuf.count),
                        nfBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        UInt(nfBuf.count),
                        callback,
                        UnsafeMutableRawPointer(ctxPtr)
                    )
                }
            }
        }

        guard let ptr else {
            throw SpendabilityBackendError.rustError(lastErrorMessage(fallback: "`checkNullifiersPIR` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }

        let data = Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len))
        return try JSONDecoder().decode(PIRNullifierCheckResult.self, from: data)
    }

    /// Fetch note commitment witnesses from the PIR server. No database access.
    ///
    /// - Parameters:
    ///   - notes: Notes needing witnesses (from DB read).
    ///   - pirServerUrl: Base URL of the witness PIR server.
    ///   - progress: Optional progress callback (0.0..1.0).
    /// - Returns: A `PIRWitnessResult` with witness data for each note.
    public func fetchWitnesses(
        notes: [PIRNotePosition],
        pirServerUrl: String,
        progress: SpendabilityProgressHandler?
    ) throws -> PIRWitnessResult {
        let urlBytes = [UInt8](pirServerUrl.utf8)

        struct PositionInput: Codable {
            let note_id: Int64
            let position: UInt64
        }

        let positions = notes.map { PositionInput(note_id: $0.id, position: $0.position) }
        let positionsJSON = try JSONEncoder().encode(positions)

        var context = SpendabilityProgressContext(handler: progress)

        let ptr: UnsafeMutablePointer<FfiBoxedSlice>? = urlBytes.withUnsafeBufferPointer { urlBuf in
            positionsJSON.withUnsafeBytes { posBuf in
                withUnsafeMutablePointer(to: &context) { ctxPtr in
                    let callback: (@convention(c) (Double, UnsafeMutableRawPointer?) -> Void)? =
                        progress != nil ? spendabilityProgressTrampoline : nil
                    return zcashlc_fetch_pir_witnesses(
                        urlBuf.baseAddress,
                        UInt(urlBuf.count),
                        posBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        UInt(posBuf.count),
                        callback,
                        UnsafeMutableRawPointer(ctxPtr)
                    )
                }
            }
        }

        guard let ptr else {
            throw SpendabilityBackendError.rustError(lastErrorMessage(fallback: "`fetchWitnesses` failed"))
        }
        defer { zcashlc_free_boxed_slice(ptr) }

        let data = Data(bytes: ptr.pointee.ptr, count: Int(ptr.pointee.len))
        return try JSONDecoder().decode(PIRWitnessResult.self, from: data)
    }
}

// MARK: - Progress callback trampoline

private struct SpendabilityProgressContext {
    let handler: SpendabilityProgressHandler?
}

private func spendabilityProgressTrampoline(progress: Double, context: UnsafeMutableRawPointer?) {
    guard let context else { return }
    let ctx = context.assumingMemoryBound(to: SpendabilityProgressContext.self).pointee
    ctx.handler?(progress)
}
