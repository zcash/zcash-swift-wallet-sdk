SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

PLATFORMS = ios-device macos ios-simulator
IOS_DEVICE_ARCHS = aarch64-apple-ios
IOS_SIM_ARCHS_STABLE = x86_64-apple-ios  aarch64-apple-ios-sim
MACOS_ARCHS = x86_64-apple-darwin aarch64-apple-darwin
IOS_SIM_ARCHS = $(IOS_SIM_ARCHS_STABLE)
ALL_ARCHS = $(IOS_DEVICE_ARCHS) $(IOS_SIM_ARCHS) $(MACOS_ARCHS)

# ZODL_SLIPSTREAM=1 links the AGPL-3.0-only zodl-slipstream engine (Cargo
# feature `zodl-slipstream`; the `gpu` feature implies it — see Cargo.toml)
# and assembles the libzcashlc-zodl-slipstream artifact instead of the default
# clean one. Output lands in a separate products-zodl-slipstream/ tree so the
# two variants never collide and so the clean tree's paths — which CI cache
# keys are pinned to — stay byte-identical no matter which variant was built
# last. A GPU-enabled build is, at the Cargo level, also a zodl-slipstream
# build; this is the one knob that controls both the feature flags below and
# the header/output-tree split, so there is nothing separate for a GPU build
# to fight.
#
# The engine requires BOTH the cargo feature and the `--cfg zodl_slipstream`
# rustflag to be enabled — the feature alone (e.g. via `--all-features`) must
# not turn it on. CARGO_ENV carries that rustflag, appended to any
# caller-provided RUSTFLAGS rather than clobbering it.
RUSTFLAGS ?=
ZODL_SLIPSTREAM ?= 0
ifeq ($(ZODL_SLIPSTREAM),1)
PRODUCTS_DIR := products-zodl-slipstream
CARGO_FEATURE_FLAGS := --features zodl-slipstream
UNIFDEF_FLAG := -DZCASHLC_ZODL_SLIPSTREAM
CARGO_ENV := RUSTFLAGS="$(RUSTFLAGS) --cfg zodl_slipstream"
else
PRODUCTS_DIR := products
CARGO_FEATURE_FLAGS :=
UNIFDEF_FLAG := -UZCASHLC_ZODL_SLIPSTREAM
CARGO_ENV :=
endif

# Cargo serialises concurrent invocations behind a lock on the shared host
# artifact directory (../target/release), so running one `cargo build --target X`
# per architecture cannot overlap them — `make -j` does not help. That matters
# most for the link step: `lto = true` is a single-threaded whole-program pass
# costing roughly two minutes per architecture, so five of them run back to back.
#
# Passing several `--target` flags to one invocation puts every architecture in a
# single job graph, letting those passes run concurrently.
CARGO_BUILD = RUSTUP_TOOLCHAIN=stable $(CARGO_ENV) cargo build --manifest-path ../Cargo.toml --release $(CARGO_FEATURE_FLAGS)
cargo_targets = $(addprefix --target ,$(1))

# CARGO_TARGET_DIR mirrors cargo's own env var of the same name (default
# below matches cargo's own default, relative to this Makefile's cwd). Every
# path below that reaches into cargo's output reads this variable rather than
# a literal "../target", so overriding it on the command line relocates both
# sides consistently — cargo honours the same env var directly, and command-
# line-assigned make variables are exported to recipe subshells automatically.
#
# This is the local-dev escape hatch for feature-flip rebuild thrash: cargo's
# target dir is shared between the clean and zodl-slipstream variants, so
# flipping ZODL_SLIPSTREAM between local runs changes the active feature set
# for every crate in the graph and pays the ~2-minute-per-architecture LTO
# relink again on the next flip. CI is unaffected (each variant gets its own
# cache, keyed on ZODL_SLIPSTREAM), but local back-and-forth iteration
# thrashes. Point it at a variant-specific directory to keep both fingerprint
# sets warm, e.g.:
#   CARGO_TARGET_DIR=../target-zodl-slipstream make xcframework ZODL_SLIPSTREAM=1
CARGO_TARGET_DIR ?= ../target

RUST_SRCS = $(shell find ../rust -name "*.rs") ../Cargo.toml
STATIC_LIBS = $(shell find $(CARGO_TARGET_DIR) -name "libzcashlc.a")

install:
	rustup toolchain add stable
	rustup +stable target add aarch64-apple-ios x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin aarch64-apple-ios-sim
	
.PHONY: install

release: clean xcframework
.PHONY: release

# Discard assembled build products for the currently selected variant (see
# ZODL_SLIPSTREAM above). CARGO_TARGET_DIR is deliberately preserved so that
# cargo's fingerprints (and CI's restored Rust cache) still apply; cargo
# decides what genuinely needs rebuilding. Every framework under
# $(PRODUCTS_DIR)/ is rebuilt from scratch, so no stale slice can survive this.
clean:
	rm -rf $(PRODUCTS_DIR)
.PHONY: clean

# Additionally discard the cargo target directory, forcing a from-scratch build.
distclean: clean
	rm -rf $(CARGO_TARGET_DIR)
.PHONY: distclean

xcframework: $(PRODUCTS_DIR)/libzcashlc.xcframework
.PHONY: xcframework

# cargo-all is listed first so a full build compiles every architecture in one
# invocation. The per-platform cargo rules below then find their work already
# done and reduce to a fingerprint check.
$(PRODUCTS_DIR)/libzcashlc.xcframework: cargo-all $(PLATFORMS)
	rm -rf $@
	mkdir -p $@
	cp -R $(PRODUCTS_DIR)/ios-device/frameworks $@/ios-arm64
	cp -R $(PRODUCTS_DIR)/ios-simulator/frameworks $@/ios-arm64_x86_64-simulator
	cp -R $(PRODUCTS_DIR)/macos/frameworks $@/macos-arm64_x86_64
	cp Info.plist $@

frameworks: $(PLATFORMS)
.PHONY: frameworks

$(PLATFORMS): %: $(PRODUCTS_DIR)/%/frameworks/libzcashlc.framework
.PHONY: $(PLATFORMS)

$(PRODUCTS_DIR)/%/frameworks/libzcashlc.framework: $(PRODUCTS_DIR)/%/universal/libzcashlc.a
	rm -rf $@
	mkdir -p $@/Headers
	cp $(PRODUCTS_DIR)/$*/universal/libzcashlc.a $@/libzcashlc
	# cbindgen wraps the zodl-slipstream FFI surface in #if defined(ZCASHLC_ZODL_SLIPSTREAM)
	# (rust/build.rs) so a single generated header serves both variants; unifdef
	# specializes the copy that actually ships, per $(UNIFDEF_FLAG) above.
	# -x2: exit status 1 just means "output differs from input", which is the
	# expected, successful case here — only exit 2 (a real parse error) fails the build.
	#
	# NOT $(CARGO_TARGET_DIR): rust/build.rs writes the header via a hardcoded
	# "target/Headers/zcashlc.h" (relative to the crate root, not OUT_DIR), so
	# it always lands here regardless of any CARGO_TARGET_DIR override above.
	unifdef -x2 $(UNIFDEF_FLAG) -o $@/Headers/zcashlc.h ../target/Headers/zcashlc.h
	mkdir $@/Modules
	cp module.modulemap $@/Modules
	# Workaround for a bug in the XCode 15.3 build system.
	# https://github.com/Electric-Coin-Company/zashi-ios/issues/1166
	cp platform-Info.plist $@/Info.plist

$(PRODUCTS_DIR)/macos/universal/libzcashlc.a: $(MACOS_ARCHS)
	mkdir -p $(@D)
	lipo -create $(shell find $(PRODUCTS_DIR)/macos/static-libraries -name "libzcashlc.a") -output $@

$(PRODUCTS_DIR)/ios-simulator/universal/libzcashlc.a: $(IOS_SIM_ARCHS)
	mkdir -p $(@D)
	lipo -create $(shell find $(PRODUCTS_DIR)/ios-simulator/static-libraries -name "libzcashlc.a") -output $@

$(PRODUCTS_DIR)/ios-device/universal/libzcashlc.a: $(IOS_DEVICE_ARCHS)
	mkdir -p $(@D)
	lipo -create $(shell find $(PRODUCTS_DIR)/ios-device/static-libraries -name "libzcashlc.a") -output $@

$(MACOS_ARCHS): %: cargo-macos
	mkdir -p $(PRODUCTS_DIR)/macos/static-libraries/$*
	cp $(CARGO_TARGET_DIR)/$*/release/libzcashlc.a $(PRODUCTS_DIR)/macos/static-libraries/$*
.PHONY: $(MACOS_ARCHS)

$(IOS_DEVICE_ARCHS): %: cargo-ios-device
	mkdir -p $(PRODUCTS_DIR)/ios-device/static-libraries/$*
	cp $(CARGO_TARGET_DIR)/$*/release/libzcashlc.a $(PRODUCTS_DIR)/ios-device/static-libraries/$*
.PHONY: $(IOS_DEVICE_ARCHS)

$(IOS_SIM_ARCHS_STABLE): %: cargo-ios-simulator
	mkdir -p $(PRODUCTS_DIR)/ios-simulator/static-libraries/$*
	cp $(CARGO_TARGET_DIR)/$*/release/libzcashlc.a $(PRODUCTS_DIR)/ios-simulator/static-libraries/$*
.PHONY: $(IOS_SIM_ARCHS_STABLE)

# Each platform builds only its own architectures, so `make macos` still needs
# just the macOS rustup targets installed.
cargo-all:
	$(CARGO_BUILD) $(call cargo_targets,$(ALL_ARCHS))
.PHONY: cargo-all

cargo-macos:
	$(CARGO_BUILD) $(call cargo_targets,$(MACOS_ARCHS))
.PHONY: cargo-macos

cargo-ios-device:
	$(CARGO_BUILD) $(call cargo_targets,$(IOS_DEVICE_ARCHS))
.PHONY: cargo-ios-device

cargo-ios-simulator:
	$(CARGO_BUILD) $(call cargo_targets,$(IOS_SIM_ARCHS))
.PHONY: cargo-ios-simulator
