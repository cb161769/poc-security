#!/bin/bash
set -e

# Resolve JAVA_HOME (works on amd64 and arm64 hosts)
. /etc/java_home.env
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

echo "[android-build] Java: $(java -version 2>&1 | head -1)"

# /workspace is mounted read-only — copy to a writable build dir
# Exclude node_modules, build artifacts, and www (we rebuild them)
echo "[android-build] Copying source to writable build directory..."
mkdir -p /build
tar -C /workspace \
  --exclude='./node_modules' \
  --exclude='./android/build' \
  --exclude='./android/.gradle' \
  --exclude='./.angular' \
  --exclude='./www' \
  --exclude='./dist' \
  -cf - . | tar -C /build -xf -

cd /build

echo "[android-build] Installing npm dependencies..."
npm ci --prefer-offline --silent

echo "[android-build] Building Angular/Ionic web assets..."
npm run build

echo "[android-build] Syncing Capacitor to Android..."
npx cap sync android

echo "[android-build] Generating test keystore..."
KEYSTORE=/tmp/release-test.jks
keytool -genkeypair -noprompt \
  -alias releasekey \
  -dname "CN=POC-Security-Test,O=Test,C=US" \
  -keystore "$KEYSTORE" \
  -keyalg RSA -keysize 2048 \
  -storepass testpass123 -keypass testpass123 \
  -validity 365

echo "[android-build] Running Gradle assembleRelease..."
cd android
chmod +x gradlew
./gradlew assembleRelease --no-daemon \
  "-Pandroid.injected.signing.store.file=$KEYSTORE" \
  "-Pandroid.injected.signing.store.password=testpass123" \
  "-Pandroid.injected.signing.key.alias=releasekey" \
  "-Pandroid.injected.signing.key.password=testpass123"

APK_SRC="app/build/outputs/apk/release/app-release.apk"
if [ ! -f "$APK_SRC" ]; then
    echo "[android-build] ERROR: APK not found at $APK_SRC" >&2
    exit 1
fi

mkdir -p /output
cp "$APK_SRC" /output/app-release.apk
echo "[android-build] Done. APK: $(du -h /output/app-release.apk | cut -f1)"
