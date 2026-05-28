#!/usr/bin/env bash
#
# Build the MamadVPN native library for Android targets.
#
# Prerequisites:
#   - Rust toolchain installed (rustup)
#   - Android NDK installed (via Android Studio or standalone)
#   - cargo-ndk installed: cargo install cargo-ndk
#   - Android targets added:
#       rustup target add aarch64-linux-android
#       rustup target add armv7-linux-androideabi
#       rustup target add x86_64-linux-android
#       rustup target add i686-linux-android
#
# Usage:
#   ./scripts/build-android.sh
#   ./scripts/build-android.sh release  (for release build)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$PROJECT_DIR/app"

BUILD_TYPE="${1:-debug}"
LIB_DIR="$APP_DIR/android/app/src/main/jniLibs"

echo "=== MamadVPN Android Native Build ==="
echo "Project: $PROJECT_DIR"
echo "Build type: $BUILD_TYPE"
echo ""

# Detect ANDROID_HOME
if [ -z "${ANDROID_HOME:-}" ]; then
    if [ -n "${ANDROID_SDK_ROOT:-}" ]; then
        export ANDROID_HOME="$ANDROID_SDK_ROOT"
    elif [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "$HOME/Library/Android/sdk" ]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    else
        echo "ERROR: ANDROID_HOME not set. Set it to your Android SDK path."
        echo "  export ANDROID_HOME=~/Android/Sdk"
        exit 1
    fi
fi
echo "ANDROID_HOME: $ANDROID_HOME"

# Detect NDK
NDK_DIR="$ANDROID_HOME/ndk"
if [ ! -d "$NDK_DIR" ]; then
    echo "ERROR: Android NDK not found at $NDK_DIR"
    echo "Install via Android Studio: SDK Manager → SDK Tools → NDK"
    exit 1
fi

# Use the latest NDK version
LATEST_NDK=$(ls -1 "$NDK_DIR" | sort -V | tail -1)
export ANDROID_NDK_HOME="$NDK_DIR/$LATEST_NDK"
echo "NDK: $ANDROID_NDK_HOME"
echo ""

# Check cargo-ndk
if ! command -v cargo-ndk &>/dev/null; then
    echo "Installing cargo-ndk..."
    cargo install cargo-ndk
fi

# Check Android targets
for target in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo "Adding target: $target"
        rustup target add "$target"
    fi
done

echo ""

# Build the API crate for all Android targets
echo "Building mamadvpn-api for Android..."
cd "$PROJECT_DIR"

CARGO_FLAGS=""
if [ "$BUILD_TYPE" = "release" ]; then
    CARGO_FLAGS="--release"
fi

cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -t x86 \
    -o "$LIB_DIR" \
    build -p mamadvpn-api $CARGO_FLAGS

echo ""
echo "=== Build complete ==="

# Show output
echo "Native libraries:"
find "$LIB_DIR" -name "*.so" -type f 2>/dev/null | while read -r lib; do
    size=$(du -h "$lib" | cut -f1)
    echo "  $size  $lib"
done

echo ""
echo "To build the APK:"
echo "  cd $APP_DIR && flutter build apk"
echo ""
echo "To build the app bundle:"
echo "  cd $APP_DIR && flutter build appbundle"
