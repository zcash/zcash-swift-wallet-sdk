//
//  VotingConstants.swift
//  ZcashLightClientKit
//

let votingFieldElementByteCount = 32
let votingAccountUuidByteCount = 16
let votingOrchardFvkByteCount = 96
let votingMinSeedByteCount = 32
let votingSeedFingerprintByteCount = 32
let votingHotkeyStoredSecretByteCount = 64
let votingShareNullifierByteCount = 32
let votingShareNullifierHexCharacterCount = votingShareNullifierByteCount * 2
let votingSpendAuthSignatureByteCount = 64
let votingPcztSighashByteCount = 32
let votingRandomizedKeyByteCount = 32
let votingPirRootByteCount = 32
let votingPirNullifierBoundsByteCount = votingPirRootByteCount * 3
let votingPirPathElementCount = 29
let votingPirPathByteCount = votingPirPathElementCount * votingPirRootByteCount
let votingPirNullifierByteCount = 32
