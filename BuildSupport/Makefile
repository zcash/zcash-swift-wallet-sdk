SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

PLATFORMS = ios-device macos ios-simulator
IOS_DEVICE_ARCHS = aarch64-apple-ios
IOS_SIM_ARCHS_STABLE = x86_64-apple-ios
IOS_SIM_ARCHS_NIGHTLY = aarch64-apple-ios-sim
MACOS_ARCHS = x86_64-apple-darwin aarch64-apple-darwin
IOS_SIM_ARCHS = $(IOS_SIM_ARCHS_STABLE) $(IOS_SIM_ARCHS_NIGHTLY)

RUST_SRCS = $(shell find ../rust -name "*.rs") ../Cargo.toml
STATIC_LIBS = $(shell find ../target -name "libzcashlc.a")

install:
	rustup toolchain add stable
	rustup +stable target add aarch64-apple-ios x86_64-apple-ios x86_64-apple-darwin aarch64-apple-darwin
	rustup toolchain add nightly-2021-09-24
	rustup +nightly-2021-09-24 target add aarch64-apple-ios-sim

	rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim x86_64-apple-darwin aarch64-apple-darwin 
	RUSTUP_TOOLCHAIN=nightly-x86_64-apple-darwin rustup target add aarch64-apple-ios-sim
.PHONY: install

release: clean xcframework
.PHONY: release

clean:
	rm -rf products
	rm -rf ../target
.PHONY: clean

xcframework: products/libzcashlc.xcframework
.PHONY: xcframework

products/libzcashlc.xcframework: $(PLATFORMS)
	rm -rf $@
	mkdir -p $@
	cp -R products/ios-device/frameworks $@/ios-arm64
	cp -R products/ios-simulator/frameworks $@/ios-arm64_x86_64-simulator
	cp -R products/macos/frameworks $@/macos-arm64_x86_64
	cp Info.plist $@

frameworks: $(PLATFORMS)
.PHONY: frameworks

$(PLATFORMS): %: products/%/frameworks/libzcashlc.framework
.PHONY: $(PLATFORMS)

products/%/frameworks/libzcashlc.framework: products/%/universal/libzcashlc.a
	rm -rf $@
	mkdir -p $@
	cp products/$*/universal/libzcashlc.a $@/libzcashlc
	cp -R ../target/Headers $@
	mkdir $@/Modules
	cp module.modulemap $@/Modules

products/macos/universal/libzcashlc.a: $(MACOS_ARCHS)
	mkdir -p $(@D)
	lipo -create $(shell find products/macos/static-libraries -name "libzcashlc.a") -output $@

products/ios-simulator/universal/libzcashlc.a: $(IOS_SIM_ARCHS)
	mkdir -p $(@D)
	lipo -create $(shell find products/ios-simulator/static-libraries -name "libzcashlc.a") -output $@

products/ios-device/universal/libzcashlc.a: $(IOS_DEVICE_ARCHS)
	mkdir -p $(@D)
	lipo -create $(shell find products/ios-device/static-libraries -name "libzcashlc.a") -output $@

$(MACOS_ARCHS): %: stable-%
	mkdir -p products/macos/static-libraries/$*
	cp ../target/$*/release/libzcashlc.a products/macos/static-libraries/$*
.PHONY: $(MACOS_ARCHS)

$(IOS_DEVICE_ARCHS): %: stable-%
	mkdir -p products/ios-device/static-libraries/$*
	cp ../target/$*/release/libzcashlc.a products/ios-device/static-libraries/$*
.PHONY: $(IOS_DEVICE_ARCHS)

$(IOS_SIM_ARCHS_STABLE): %: stable-%
	mkdir -p products/ios-simulator/static-libraries/$*
	cp ../target/$*/release/libzcashlc.a products/ios-simulator/static-libraries/$*
.PHONY: $(IOS_SIM_ARCHS_STABLE)

$(IOS_SIM_ARCHS_NIGHTLY): %: nightly-%
	mkdir -p products/ios-simulator/static-libraries/$*
	cp rust/target/$*/release/libzcashlc.a products/ios-simulator/static-libraries/$*
.PHONY: $(IOS_SIM_ARCHS_NIGHTLY)

nightly-%:
	sh -c "RUSTUP_TOOLCHAIN=nightly-2021-09-24 cargo build --manifest-path rust/Cargo.toml --target $* --release"

stable-%: # target/%/release/libzcashlc.a:
	sh -c "RUSTUP_TOOLCHAIN=stable cargo build --manifest-path ../Cargo.toml --target $* --release"
