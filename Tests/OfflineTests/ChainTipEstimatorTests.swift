//
//  ChainTipEstimatorTests.swift
//  OfflineTests
//
//  Pure-math tests for `ChainTipEstimator`: the measured-block-rate wall-clock chain-tip
//  projection behind `Synchronizer.estimatedMigrationChainTip()` /
//  `.estimatedMigrationSecondsPerBlock()` and every `useEstimatedTip: true` call site.
//  No network, no FFI, no wallet database -- `ChainTipEstimator` is constructed directly from
//  hand-built `MigrationBlockRateSample` fixtures.
//
//  The rate is a SPAN (total header-time span / total height span), not a mean of per-delta
//  spacings -- see the type doc for the field incident that killed the delta mean. The suite
//  pins the span semantics, the bias cases that distinguish it from the old statistic, and one
//  fixture lifted verbatim from the incident wallet's `blocks` table.
//

import XCTest
@testable import ZcashLightClientKit

final class ChainTipEstimatorTests: XCTestCase {
    private let referenceDate = Date(timeIntervalSince1970: 1_700_000_000)

    private func s(_ height: BlockHeight, _ unixTime: Int64) -> MigrationBlockRateSample {
        MigrationBlockRateSample(height: height, unixTime: unixTime)
    }

    // MARK: - Constants

    /// Pins the constants -- a regression here is a silent behavior change, not a cosmetic one.
    /// The clamps and the fallback still mirror the Android SDK's estimator; the window is
    /// DELIBERATELY diverged from Android's 100 (absence-scale sampling -- see the type doc), and
    /// a change to any of these must be a decision, not drift.
    func testConstants() {
        XCTAssertEqual(ChainTipEstimator.sampleWindow, 1000)
        XCTAssertEqual(ChainTipEstimator.minSecondsPerBlock, 5)
        XCTAssertEqual(ChainTipEstimator.maxSecondsPerBlock, 150)
        XCTAssertEqual(ChainTipEstimator.fallbackSecondsPerBlock, 75)
    }

    // MARK: - secondsPerBlock(): fallback

    func testSecondsPerBlockFallsBackWithNoSamples() {
        let estimator = ChainTipEstimator(samples: [])
        XCTAssertEqual(estimator.secondsPerBlock(), 75)
    }

    func testSecondsPerBlockFallsBackWithExactlyOneSample() {
        let estimator = ChainTipEstimator(samples: [s(1_000_000, 1_700_000_000)])
        XCTAssertEqual(estimator.secondsPerBlock(), 75)
    }

    /// Header times are miner-supplied and can regress; a window whose time span fails to advance
    /// is a broken measurement, not an infinitely fast chain -- it must fall back, never clamp to
    /// the floor (the floor would be the maximum-overshoot answer).
    func testSecondsPerBlockFallsBackWhenTheTimeSpanDoesNotAdvance() {
        let stalled = ChainTipEstimator(samples: [s(1_000_000, 1_700_000_000), s(1_000_001, 1_700_000_000)])
        let backward = ChainTipEstimator(samples: [s(1_000_000, 1_700_000_000), s(1_000_001, 1_699_999_000)])

        XCTAssertEqual(stalled.secondsPerBlock(), 75)
        XCTAssertEqual(backward.secondsPerBlock(), 75)
    }

    /// A hand-built window spanning no height (the DB cannot produce one -- height is the primary
    /// key) still answers the fallback rather than dividing by zero.
    func testSecondsPerBlockFallsBackWhenTheHeightSpanIsZero() {
        let estimator = ChainTipEstimator(samples: [s(1_000_000, 1_700_000_000), s(1_000_000, 1_700_000_060)])
        XCTAssertEqual(estimator.secondsPerBlock(), 75)
    }

    // MARK: - secondsPerBlock(): the span

    /// The boundary: exactly two samples is enough to stop falling back and measure a real span.
    func testSecondsPerBlockComputesASpanWithExactlyTwoSamples() {
        let estimator = ChainTipEstimator(samples: [s(1_000_000, 1_700_000_000), s(1_000_001, 1_700_000_060)])
        XCTAssertEqual(estimator.secondsPerBlock(), 60)
    }

    /// Four samples over three blocks and 210 s: the span is 70 s/block. (On adjacent heights
    /// with no clamps engaged the old delta mean agreed -- the statistics only diverge on bimodal
    /// spacing or non-adjacent heights, pinned below.)
    func testSecondsPerBlockIsTheSpanOfTheWindow() {
        let estimator = ChainTipEstimator(samples: [
            s(1_000_000, 1_700_000_000),
            s(1_000_001, 1_700_000_060),
            s(1_000_002, 1_700_000_130),
            s(1_000_003, 1_700_000_210)
        ])
        XCTAssertEqual(estimator.secondsPerBlock(), 70)
    }

    /// THE BIAS PIN. Burst-then-gap spacing (testnet's min-difficulty pattern): nine 2 s deltas
    /// and one 300 s gap over ten blocks is a true 31.8 s/block. The retired statistic -- mean of
    /// per-delta values clamped to [5, 150] -- answered 19.5 on this same fixture ((9×5 + 150)/10),
    /// biased low because the bursts dominate by count. The span absorbs a gap and the burst it
    /// triggers together.
    func testSecondsPerBlockIsNotBiasedLowByBurstGapSpacing() {
        var samples: [MigrationBlockRateSample] = []
        var time: Int64 = 1_700_000_000
        for index in 0...10 {
            samples.append(s(BlockHeight(1_000_000 + index), time))
            time += index == 9 ? 300 : 2
        }

        let estimator = ChainTipEstimator(samples: samples)

        XCTAssertEqual(estimator.secondsPerBlock(), 31.8, accuracy: 0.0001)
    }

    /// Non-adjacent sample heights divide by the true HEIGHT span, not the row count: three rows
    /// spanning twenty blocks and 1500 s is 75 s/block. The old statistic read the same fixture
    /// as two 750 s "spacings", clamped both to 150, and answered exactly double.
    func testSecondsPerBlockDividesByHeightSpanNotRowCount() {
        let estimator = ChainTipEstimator(samples: [
            s(1_000_000, 0),
            s(1_000_010, 750),
            s(1_000_020, 1_500)
        ])
        XCTAssertEqual(estimator.secondsPerBlock(), 75)
    }

    /// Only the last `sampleWindow` (1000) samples participate: a 1001-sample fixture whose
    /// single OLDEST sample sits a wild 100 000 s before the rest must measure the same span as
    /// the same fixture with that oldest sample removed.
    func testSecondsPerBlockOnlyConsidersTheLastSampleWindowSamples() {
        var samples: [MigrationBlockRateSample] = [s(0, 0)]
        var time: Int64 = 100_000
        for index in 1...1_000 {
            samples.append(s(BlockHeight(index), time))
            time += 60
        }

        let estimator = ChainTipEstimator(samples: samples)
        let estimatorWithoutOutlier = ChainTipEstimator(samples: Array(samples.dropFirst()))

        XCTAssertEqual(estimator.secondsPerBlock(), 60, "the outlier at index 0 must fall outside the last-1000-sample window")
        XCTAssertEqual(estimator.secondsPerBlock(), estimatorWithoutOutlier.secondsPerBlock())
    }

    /// WHY THE WINDOW IS 1000 AND NOT 100. A chain that ran ~31 s/block for hours and then
    /// bursts to 20 s/block for its last 100 blocks: the 1000-sample window blends the regimes
    /// (~29.9 s), where a 100-sample window would have measured only the final burst (20 s) and
    /// projected it across an hours-long absence -- the field incident's dominant error.
    func testSecondsPerBlockWindowSpansRegimeChanges() {
        var samples: [MigrationBlockRateSample] = []
        var time: Int64 = 1_700_000_000
        for index in 0..<1_100 {
            samples.append(s(BlockHeight(2_000_000 + index), time))
            time += index < 1_000 ? 31 : 20
        }

        let estimator = ChainTipEstimator(samples: samples)

        // suffix(1000) spans 999 heights: 900 deltas at 31 s + 99 at 20 s.
        XCTAssertEqual(estimator.secondsPerBlock(), (900.0 * 31.0 + 99.0 * 20.0) / 999.0, accuracy: 0.0001)
    }

    // MARK: - secondsPerBlock(): the final clamps

    /// The clamp applies to the FINAL span rate, never per delta. A 2 s delta next to a 500 s
    /// delta is a true span of 251 s/block -- an absurd rate, clamped to the 150 ceiling. (The
    /// retired statistic clamped each delta first and answered 77.5 -- a plausible-looking number
    /// manufactured from two implausible ones, which is exactly how it hid.)
    func testSecondsPerBlockClampsTheFinalRateNotEachDelta() {
        let estimator = ChainTipEstimator(samples: [
            s(1_000_000, 0),
            s(1_000_001, 2),
            s(1_000_002, 502)
        ])
        XCTAssertEqual(estimator.secondsPerBlock(), 150)
    }

    func testSecondsPerBlockResultNeverGoesBelowTheFloor() {
        let estimator = ChainTipEstimator(samples: [
            s(1_000_000, 0),
            s(1_000_001, 1),
            s(1_000_002, 2)
        ])
        XCTAssertEqual(estimator.secondsPerBlock(), 5, "a 1 s/block span clamps up to the 5 s floor")
    }

    func testSecondsPerBlockResultNeverGoesAboveTheCeiling() {
        let estimator = ChainTipEstimator(samples: [
            s(1_000_000, 0),
            s(1_000_001, 150),
            s(1_000_002, 300)
        ])
        XCTAssertEqual(estimator.secondsPerBlock(), 150)
    }

    // MARK: - The incident fixture

    /// Lifted VERBATIM from the 2026-08-08 incident wallet (`data37`, public testnet): the 100
    /// most recently scanned blocks at the moment the wallet slept -- the exact window the
    /// pre-widening estimator measured when the overnight re-spread fired. Real chain data, warts
    /// included (heights 4244849→4244850 carry header times that go BACKWARD 140 s).
    ///
    /// Span: 1996 s over 99 blocks = 20.1616 s/block. The retired clamped-delta mean read 18.70.
    /// The night this window was projected across averaged 31.1 s/block -- the residual error is
    /// the window's narrowness (33 minutes of burst-heavy chain), which is what
    /// ``ChainTipEstimator/sampleWindow`` = 1000 addresses; this fixture pins the statistic on
    /// real data and documents that a 100-sample window is measurement, not prophecy.
    func testIncidentWindowMeasuresItsTrueSpanRate() {
        let samples: [MigrationBlockRateSample] = [
            s(4244839, 1786136187), s(4244840, 1786136306), s(4244841, 1786136327), s(4244842, 1786136343), s(4244843, 1786136388),
            s(4244844, 1786136426), s(4244845, 1786136627), s(4244846, 1786136758), s(4244847, 1786136760), s(4244848, 1786136767),
            s(4244849, 1786137218), s(4244850, 1786137078), s(4244851, 1786137095), s(4244852, 1786137098), s(4244853, 1786137103),
            s(4244854, 1786137104), s(4244855, 1786137110), s(4244856, 1786137114), s(4244857, 1786137124), s(4244858, 1786137140),
            s(4244859, 1786137149), s(4244860, 1786137156), s(4244861, 1786137157), s(4244862, 1786137158), s(4244863, 1786137164),
            s(4244864, 1786137169), s(4244865, 1786137172), s(4244866, 1786137184), s(4244867, 1786137186), s(4244868, 1786137189),
            s(4244869, 1786137191), s(4244870, 1786137192), s(4244871, 1786137206), s(4244872, 1786137221), s(4244873, 1786137245),
            s(4244874, 1786137253), s(4244875, 1786137297), s(4244876, 1786137302), s(4244877, 1786137302), s(4244878, 1786137318),
            s(4244879, 1786137323), s(4244880, 1786137327), s(4244881, 1786137331), s(4244882, 1786137342), s(4244883, 1786137366),
            s(4244884, 1786137373), s(4244885, 1786137392), s(4244886, 1786137397), s(4244887, 1786137405), s(4244888, 1786137407),
            s(4244889, 1786137413), s(4244890, 1786137415), s(4244891, 1786137443), s(4244892, 1786137478), s(4244893, 1786137484),
            s(4244894, 1786137487), s(4244895, 1786137500), s(4244896, 1786137509), s(4244897, 1786137514), s(4244898, 1786137518),
            s(4244899, 1786137534), s(4244900, 1786137563), s(4244901, 1786137583), s(4244902, 1786137599), s(4244903, 1786137617),
            s(4244904, 1786137620), s(4244905, 1786137625), s(4244906, 1786137634), s(4244907, 1786137655), s(4244908, 1786137665),
            s(4244909, 1786137679), s(4244910, 1786137691), s(4244911, 1786137695), s(4244912, 1786137700), s(4244913, 1786137706),
            s(4244914, 1786137715), s(4244915, 1786137749), s(4244916, 1786137750), s(4244917, 1786137783), s(4244918, 1786137826),
            s(4244919, 1786137830), s(4244920, 1786137846), s(4244921, 1786137848), s(4244922, 1786137851), s(4244923, 1786137860),
            s(4244924, 1786137883), s(4244925, 1786137889), s(4244926, 1786137902), s(4244927, 1786137988), s(4244928, 1786138005),
            s(4244929, 1786138020), s(4244930, 1786138040), s(4244931, 1786138047), s(4244932, 1786138065), s(4244933, 1786138096),
            s(4244934, 1786138100), s(4244935, 1786138116), s(4244936, 1786138124), s(4244937, 1786138142), s(4244938, 1786138183)
        ]

        let estimator = ChainTipEstimator(samples: samples)

        XCTAssertEqual(estimator.secondsPerBlock(), 1_996.0 / 99.0, accuracy: 0.0001, "20.16 s/block -- the window's true span")
    }

    // MARK: - estimatedTip(now:): nil with no samples

    func testEstimatedTipIsNilWithNoSamples() {
        let estimator = ChainTipEstimator(samples: [])
        XCTAssertNil(estimator.estimatedTip(now: referenceDate))
    }

    // MARK: - estimatedTip(now:): floor math

    /// `elapsed / secondsPerBlock()` is FLOORED, not rounded: 200 s elapsed at 75 s/block
    /// (fallback, one sample) is 2.66\u{2026} blocks -- floor gives 2, whereas rounding would give 3.
    func testEstimatedTipFloorsThePartialBlockRatherThanRounding() {
        let latest = s(2_000_000, Int64(referenceDate.timeIntervalSince1970))
        let estimator = ChainTipEstimator(samples: [latest])

        let tip = estimator.estimatedTip(now: referenceDate.addingTimeInterval(200))

        XCTAssertEqual(tip, 2_000_002, "floor(200 / 75) == 2, not round(200 / 75) == 3")
    }

    /// An elapsed duration that divides the block rate exactly still floors correctly (no
    /// off-by-one from floating-point wobble at an exact boundary).
    func testEstimatedTipAtAnExactBlockBoundary() {
        let latest = s(2_000_000, Int64(referenceDate.timeIntervalSince1970))
        let estimator = ChainTipEstimator(samples: [latest])

        let tip = estimator.estimatedTip(now: referenceDate.addingTimeInterval(150))

        XCTAssertEqual(tip, 2_000_002, "exactly 2 whole blocks at the 75 s fallback rate")
    }

    // MARK: - estimatedTip(now:): negative elapsed clamps to zero

    /// `now` at or before the latest sample's header time (clock skew, or a caller re-evaluating
    /// against a stale `now`) must never project BACKWARD past the latest known height.
    func testEstimatedTipClampsNegativeElapsedToTheLatestSampleHeight() {
        let latest = s(2_000_000, Int64(referenceDate.timeIntervalSince1970))
        let estimator = ChainTipEstimator(samples: [latest])

        let tipBeforeLatest = estimator.estimatedTip(now: referenceDate.addingTimeInterval(-1_000))
        let tipExactlyAtLatest = estimator.estimatedTip(now: referenceDate)

        XCTAssertEqual(tipBeforeLatest, 2_000_000, "a header time in the future of `now` must add zero blocks, never go negative")
        XCTAssertEqual(tipExactlyAtLatest, 2_000_000)
    }

    /// The latest (last) sample's height is always the projection's floor, regardless of how many
    /// earlier samples exist.
    func testEstimatedTipProjectsFromTheLatestSampleNotTheFirst() {
        let estimator = ChainTipEstimator(samples: [
            s(1_000_000, 0),
            s(1_000_010, 600)
        ])

        let tip = estimator.estimatedTip(now: Date(timeIntervalSince1970: 600))

        XCTAssertEqual(tip, 1_000_010, "with zero elapsed time past the latest sample, the tip is exactly its height")
    }

    /// End-to-end overnight projection at the incident's scale: latest sample at height H with a
    /// 27 900 s (7.75 h) absence over a 31 s/block window projects +900 blocks -- the real
    /// overnight advance the incident chain produced, and the number the overdue re-spread should
    /// have been sized by.
    func testEstimatedTipProjectsAnOvernightAbsenceAtTheMeasuredRate() {
        var samples: [MigrationBlockRateSample] = []
        var time: Int64 = 1_700_000_000
        for index in 0..<1_000 {
            samples.append(s(BlockHeight(3_000_000 + index), time))
            time += 31
        }
        let latestTime = samples[samples.count - 1].unixTime
        let estimator = ChainTipEstimator(samples: samples)

        let tip = estimator.estimatedTip(now: Date(timeIntervalSince1970: TimeInterval(latestTime + 27_900)))

        XCTAssertEqual(tip, 3_000_999 + 900, "floor(27900 / 31) == 900 blocks across the absence")
    }
}
