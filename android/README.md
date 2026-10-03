SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# n3n for Android

A minimal app that runs an n3n edge on an Android phone, through
`VpnService`.  It lives next to the core in this repository and compiles the
core's sources straight from `../src`: every change to the core is in the
next build of the app, with nothing to copy or update by hand.

One network at a time: its state at a glance, connect and disconnect, the
configuration (written on the phone, imported, or scanned), sharing it as
a QR code, and the edge's log.  See
[Mobile and TUN](../docs/develop/MobileAndTun.md) for the design and for
what comes next.

## What it does

- The configuration is the same as on other systems: an edge's `.conf`
  file, typed or pasted into the app, imported from a file, or read from
  a QR code that `tools/n3n-qr` makes of it.  It needs a
  static address, `tuntap.address = 10.0.0.5/24` in `[tuntap]`, because
  Android sets the device up before the edge starts.  `tuntap.mtu` is
  taken too (1290 when not given).
- Connect asks Android for the VPN permission the first time, then sets up
  the device with the address and a route for its network, and starts the
  edge in a foreground service (with its notification).
- The edge runs in TUN mode (`tuntap.type = tun`) on the device that
  Android hands over (`tuntap.fd`), see
  [TAP or TUN](../docs/configure/TapConfiguration.md).  Everything else of
  the configuration is read by the edge itself, as on Linux: supernodes,
  community, key, cipher, compression, transport (`udp://`, `tcp://`, the
  TCP fallback).
- Every socket the edge opens is passed to `VpnService.protect()`, so its
  own traffic does not go into the VPN.
- The management API is there as on other systems, on the unix socket in
  the app's private directory (session `app`); `management.port`, if
  configured, opens the TCP port as well.  The main screen asks it for
  the state: connecting or connected, the supernode with its round trip,
  the peers.
- Share shows the configuration as a QR code on the screen, for another
  phone to join with: with or without this phone's address (each device
  needs one of its own), and optionally sealed with a PIN.

### QR codes sealed with a PIN

`n3n-qr -P` and Share with "Protect with a PIN" seal the configuration:
the code then holds only base64url of a random salt and the ciphertext,
and says neither what it holds nor that it is n3n's.  When the app scans a
code that is no configuration but could be a sealed one, it asks: "if this
is a protected n3n configuration, enter its PIN".

Both use the same code of the core (`src/qr_seal.c`), with n3n's own
ciphers: the key is the Pearson hash of PIN and salt, hashed again 300000
times, and Speck in CTR mode encrypts `n3n1` and a newline in front of the
configuration - what tells, after opening, that the PIN was right.  This
keeps a code from saying what it is at a glance; it is no strong
protection, a short PIN can be found by trying them all.

Limits for now: IPv4 only, one network at a time, no automatic addresses
(`tuntap.address_mode = auto`), no reconnect when the phone changes
networks other than through the edge's own re-registration.

## How it is put together

```
android/
  settings.gradle.kts, build.gradle.kts   the Gradle project
  gradlew, gradle/wrapper/                the Gradle wrapper
  app/build.gradle.kts                    the app: SDK levels, ABIs, CMake
  app/src/main/
    AndroidManifest.xml
    cpp/CMakeLists.txt                    libn3n.so from ../src and ../libs
    cpp/config.h                          what ./configure finds, for Android
    cpp/n3n_jni.c                         the JNI glue to n3n_edge_run()
    java/dev/n3n/android/
      MainActivity.kt                     the main screen: state, connect
      EditActivity.kt                     the configuration: edit, import, scan
      ShareActivity.kt                    the configuration as a QR code
      LogActivity.kt                      the edge's log
      ScanActivity.kt                     the camera, until it sees a QR code
      QrDecode.kt, QrEncode.kt            QR codes, with ZXing's core
      Seal.kt                             sealed codes, from libn3n
      Status.kt                           the edge's state, from its API
      Store.kt                            where the configuration is kept
      N3nVpnService.kt                    the VPN and the edge's thread
      Config.kt                           reads address and MTU of a .conf
    res/                                  layout, strings, icon
```

- **libn3n.so** is the edge-only build of the core, as
  `./configure --disable-relay` makes it: `CMakeLists.txt` takes all of
  `src/` less the relay role and the devices of other systems, plus
  minilzo and connslot.  The management page's script is turned into C by
  CMake itself, so no Perl is needed.  The version is `git describe` of
  the repository, or `VERSION`.
- **n3n_jni.c** calls `n3n_edge_run()` of
  [`include/n3n/embed.h`](../include/n3n/embed.h), on the service's
  thread, with callbacks for `protect()` and the log; `nativeStop()` calls
  `n3n_edge_stop()`.
- **The app** uses the platform's own classes (no AndroidX), to keep it
  small and its dependencies few.  Minimum Android 7.0 (API 24).  The one
  library is ZXing's core (Apache-2.0), which reads the QR codes on the
  phone itself: no network, no Google Play services, no scanner app.

## Building

With Android Studio: open the `android/` directory.

On the command line, with the Android SDK (`ANDROID_HOME` set, or
`sdk.dir` in `android/local.properties`) and Java 17 or newer:

```sh
cd android
./gradlew assembleDebug
```

The APK is then in `app/build/outputs/apk/debug/`.  The Android Gradle
plugin installs the NDK and CMake versions it needs, if the SDK's licenses
are accepted (`sdkmanager --licenses`).

The GitHub workflow `Android` (`.github/workflows/android.yml`) builds the
debug APK on every change to `android/`, `src/`, `include/` or `libs/`, and
keeps it as the artifact `n3n-android-debug` of the run.

### Checking the native part without the NDK

`CMakeLists.txt` also builds on a Linux host, with the JDK's JNI headers
instead of the NDK: a quick way to see whether a change to the core still
compiles and links for the app.

```sh
cmake -S android/app/src/main/cpp -B build-android-native
cmake --build build-android-native
```

## Trying it

1. Install the APK (`adb install app-debug.apk`, or open it on the phone).
2. Get a configuration into the field, for example:

   ```ini
   [community]
   name = mynetwork
   key = mysecret
   supernode = supernode.example.org:7777

   [tuntap]
   address = 10.0.0.5/24
   ```

   Three ways to get it there:
   - **QR code**: make one on a computer with `tools/n3n-qr phone.conf`
     (a PNG, or `-t` for the terminal; `-P` seals it with a PIN), or show
     one on another phone with *Share*; tap *Scan QR code* and point the camera
     at it.  The first time, the app asks for the camera.
   - **Import file** (in *Configuration*): a `.conf` file, or an image with a QR code (the PNG of
     `n3n-qr` sent to the phone, a screenshot).
   - Type or paste it in *Configuration*.

   The app asks before it replaces a configuration already in the field,
   and nothing starts before *Connect*: check it, or change the address
   for this phone, first.

3. Connect, and allow the VPN.  The log shows the registration with the
   supernode; the other edges of the community are reachable at their
   addresses, and see the phone at `10.0.0.5`.

`adb logcat -s n3n` shows the edge's log as well.
