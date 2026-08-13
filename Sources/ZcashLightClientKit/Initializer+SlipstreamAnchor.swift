//
//  Initializer+SlipstreamAnchor.swift
//  ZcashLightClientKit
//
//  Plain-data seam between the core SDK and the optional ZODLSlipstream module.
//  Core only NAMES this type (in `Initializer.slipstreamAnchorSource`); the engine-driven
//  resolver that produces values lives in the ZODLSlipstream target, so the default
//  (MIT-clean) product carries no code path that can reach an engine symbol.
//

/// [E-6] The engine-resolved wallet-provisioning anchor. RESTORE: `height` = the
/// recover_until to provision (always valid — live tip, or the engine's offline
/// `max(bundled checkpoint, birthday+1)` fallback), `treeState` nil (the host keeps its
/// birthday checkpoint). NEW: the reorg-safe recent server tree state, or nil when
/// offline (the host keeps its bundled checkpoint defaults).
package struct SlipstreamRestoreAnchor {
    package let height: BlockHeight
    package let treeState: TreeState?

    package init(height: BlockHeight, treeState: TreeState?) {
        self.height = height
        self.treeState = treeState
    }
}
