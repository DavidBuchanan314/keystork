# Vendored AOSP sources

Two things are vendored here, both from **`android-17.0.0_r1`** and both
committed as source so the project build never touches AOSP:

| Directory | What |
|---|---|
| `aidl/` | Generated NDK-backend C++ stubs for the `keystore2` Binder interfaces |
| `binder_ndk/` | The libbinder_ndk headers and symbol map those stubs are written against |

Neither is hand-edited. Regenerate only when changing the pinned versions.

# AIDL stubs

Produced by Soong from an AOSP tree.

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

---

# libbinder_ndk headers (`binder_ndk/`)

The NDK's Binder support cannot build the AIDL stubs above, so the daemon uses
none of it. These headers and the symbol map replace it entirely; the NDK
supplies only the toolchain, bionic and libc++.

## Why this is vendored rather than taken from the NDK

Three independent problems, none of which a different NDK release fixes. Note
that these motivate the vendoring — they are *not* a constraint on which NDK you
build with. `server/CMakeLists.txt` adds these include dirs `BEFORE` the
sysroot's, so the NDK's Binder headers are never reached whether or not the
release still ships them.

1. **The NDK's headers are older than the generator.** The stubs above were
   emitted by `android-17.0.0_r1`'s `aidl` and call
   `ndk::BpCInterface::asBinderReference()` and the four-argument
   `ICInterface::defineClass()`, neither of which exists in NDK r27's copy of
   `binder_interface_utils.h`. Pairing generated code with the binder headers
   from the *same* tag is what Soong does; doing anything else means patching
   generator output or macro-rewriting its calls.
2. **The NDK ships no platform headers at all.** There is no
   `android/binder_manager.h` (`AServiceManager_*`) and no
   `android/binder_process.h` (`ABinderProcess_*`) at any API level, and
   `AParcel_markSensitive` — which the generated stubs call unconditionally on
   every method carrying key material — is declared nowhere.
3. **NDK r28+ deletes the C++ headers outright.** `binder_auto_utils.h`,
   `binder_interface_utils.h`, `binder_parcelable_utils.h`, `binder_to_string.h`
   and `binder_enums.h` are gone from r28 and r29. Given (1) and (2) this only
   removes an already-unusable fallback: r29 builds fine, because every one of
   those headers comes from here.

## Contents

| Path | Origin | Used for |
|---|---|---|
| `binder_ndk/include_ndk/` | `libs/binder/ndk/include_ndk/` | The C API: `binder_ibinder.h`, `binder_parcel.h`, `binder_status.h` |
| `binder_ndk/include_cpp/` | `libs/binder/ndk/include_cpp/` | The C++ wrappers the generated stubs are built on |
| `binder_ndk/include_platform/` | `libs/binder/ndk/include_platform/` | `binder_manager.h`, `binder_process.h`, `binder_{ibinder,parcel}_platform.h` |
| `binder_ndk/libbinder_ndk.map.txt` | `libs/binder/ndk/` | The version script, used to generate the link stub |
| `binder_ndk/NOTICE` | `libs/binder/ndk/` | Apache-2.0 notice |

`libbinder_ndk.map.txt` is not a header. `server/cmake/gen_binder_ndk_stub.cmake`
turns its 210 exported names into an equally-sized set of empty C functions,
compiled into a shared library named `libbinder_ndk.so`. That library exists
only to satisfy the linker — it is never pushed — and on the device the real
`libbinder_ndk.so` provides every implementation. Generating it from AOSP's own
export list means a symbol that exists on the device can never be missing at
link time, which is exactly the failure mode the NDK's partial stub produces.

## Provenance

- **Source:** <https://android.googlesource.com/platform/frameworks/native>
- **Tag:** `android-17.0.0_r1` — the same tag as the AIDL stubs above
- **Subtree:** `libs/binder/ndk/`
- **License:** Apache-2.0 (see `binder_ndk/NOTICE`)

## Reproducing

Gitiles serves a subtree directly, so this needs no checkout:

```sh
curl -fL -o binder_ndk.tar.gz \
  "https://android.googlesource.com/platform/frameworks/native/+archive/refs/tags/android-17.0.0_r1/libs/binder/ndk.tar.gz"

mkdir -p /tmp/binder_ndk && tar -xzf binder_ndk.tar.gz -C /tmp/binder_ndk

cp -r /tmp/binder_ndk/include_ndk \
      /tmp/binder_ndk/include_cpp \
      /tmp/binder_ndk/include_platform \
      vendor/binder_ndk/
cp /tmp/binder_ndk/libbinder_ndk.map.txt /tmp/binder_ndk/NOTICE vendor/binder_ndk/
```

The `.cpp` files in that subtree are the *implementation*, which lives on the
device. Do not vendor them.
