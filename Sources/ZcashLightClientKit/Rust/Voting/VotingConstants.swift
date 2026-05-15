//
//  VotingConstants.swift
//  ZcashLightClientKit
//

let votingFieldElementByteCount = 32
let votingAccountUuidByteCount = 16
let votingOrchardFvkByteCount = 96
let votingMinSeedByteCount = 32
let votingSeedFingerprintByteCount = 32
let votingShareNullifierByteCount = 32
let votingShareNullifierHexCharacterCount = votingShareNullifierByteCount * 2
let votingVoteRoundIdHexCharacterCount = 64
let votingKeystoneSignatureByteCount = 64
let votingPcztSighashByteCount = 32
let votingRandomizedKeyByteCount = 32
let votingHotkeyRawAddressByteCount = 43
let votingPirRootByteCount = 32
let votingPirNullifierBoundsByteCount = votingPirRootByteCount * 3
let votingPirPathElementCount = 29
let votingPirPathByteCount = votingPirPathElementCount * votingPirRootByteCount
let votingPirNullifierByteCount = 32

// ASCII byte bounds used when validating hex-encoded voting inputs.
let votingCharacterByteZero = UInt8(ascii: "0")
let votingCharacterByteNine = UInt8(ascii: "9")
let votingCharacterByteUppercaseA = UInt8(ascii: "A")
let votingCharacterByteUppercaseF = UInt8(ascii: "F")
let votingCharacterByteLowercaseA = UInt8(ascii: "a")
let votingCharacterByteLowercaseF = UInt8(ascii: "f")
