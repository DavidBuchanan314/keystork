# Vendored AIDL stubs

Generated NDK-backend C++ stubs for the `keystore2` Binder interfaces, produced
by Soong from an AOSP tree and committed here as source. Regenerate only when
changing the pinned versions.

## Contents

| Module | Interface version | Files |
|---|---|---|
| `aidl/android.system.keystore2-V6-ndk` | `android.system.keystore2` **V6** | 60 |
| `aidl/android.hardware.security.keymint-V5-ndk` | `android.hardware.security.keymint` **V5** | 100 |
| `aidl/android.hardware.security.secureclock-V1-ndk` | `android.hardware.security.secureclock` **V1** | 12 |

```
<module>/include/aidl/...   headers
<module>/android/...        sources
```

Generator output, unmodified. Do not hand-edit.

## Provenance

- **Source:** <https://android.googlesource.com/platform/manifest>
- **Tag:** `android-17.0.0_r1`

The versions are coupled: `android.system.keystore2` V6 pins keymint V5, which
pins secureclock V1.

| Interface | `.hash` |
|---|---|
| `android.system.keystore2` V6 | `b115fcb5d111eb616a65f0f32e0c2cef131575ec` |
| `android.hardware.security.keymint` V5 | `177877c3782ff5543c231b8616f1ee6a300f810d` |
| `android.hardware.security.secureclock` V1 | `cd55ca9963c6a57fa5f2f120a45c6e0c4fafb423` |

## Reproducing

Requires ~250 GB of disk.

### 1. Check out AOSP

```sh
mkdir aosp && cd aosp

curl -o repo https://storage.googleapis.com/git-repo-downloads/repo
chmod +x repo

./repo init -u https://android.googlesource.com/platform/manifest \
            -b android-17.0.0_r1 \
            --partial-clone --clone-filter=blob:limit=10M --no-tags
./repo sync -c -j8
```

Re-run `repo sync` until it reports no errors. A partial tree fails later,
during Soong analysis, with unrelated-looking errors.

### 2. Generate

```sh
TARGET_PRODUCT=aosp_arm64 \
TARGET_RELEASE=trunk_staging \
TARGET_BUILD_VARIANT=eng \
build/soong/soong_ui.bash --make-mode -j"$(nproc)" \
  android.system.keystore2-V6-ndk \
  android.hardware.security.keymint-V5-ndk \
  android.hardware.security.secureclock-V1-ndk
```

Output:

```
out/soong/.intermediates/system/hardware/interfaces/keystore2/aidl/android.system.keystore2-V6-ndk-source/gen
out/soong/.intermediates/hardware/interfaces/security/keymint/aidl/android.hardware.security.keymint-V5-ndk-source/gen
out/soong/.intermediates/hardware/interfaces/security/secureclock/aidl/android.hardware.security.secureclock-V1-ndk-source/gen
```

### 3. Copy in

For each module, mirror `gen/` into `vendor/aidl/<module>/`:

```sh
rsync -a --exclude='*.d' --exclude='timestamp' --exclude='staging/' \
  "$GEN"/ vendor/aidl/"$MODULE"/
```

### 4. Verify

The hash embedded in each generated header must equal the frozen snapshot's
`.hash`. If they differ, the build used an unfrozen interface; do not commit it.

```sh
grep -o 'hash = "[a-f0-9]*"' \
  vendor/aidl/android.system.keystore2-V6-ndk/include/aidl/android/system/keystore2/IKeystoreService.h

cat aosp/system/hardware/interfaces/keystore2/aidl/aidl_api/android.system.keystore2/6/.hash
```

Update the version and hash tables above.
