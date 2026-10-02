SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# n3n for Android

A minimal app that runs an n3n edge on an Android phone, through
`VpnService`.  It lives next to the core in this repository and compiles the
core's sources straight from `../src`: every change to the core is in the
next build of the app, with nothing to copy or update by hand.

This is a first version, for trying it out: one network, configured by a
`.conf` file, connect and disconnect, and the edge's log.  See
[Mobile and TUN](../docs/develop/MobileAndTun.md) for the design and for
what comes next.

## What it does

- The configuration is the same as on other systems: an edge's `.conf`
  file, typed or pasted into the app, or imported from a file.  It needs a
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
  configured, opens the TCP port as well.

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
      MainActivity.kt                     the one screen
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
- **The app** uses the platform's own classes only (no AndroidX), to keep
  it small and its dependencies few.  Minimum Android 7.0 (API 24).

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
2. Paste or import a configuration, for example:

   ```ini
   [community]
   name = mynetwork
   key = mysecret
   supernode = supernode.example.org:7777

   [tuntap]
   address = 10.0.0.5/24
   ```

3. Connect, and allow the VPN.  The log shows the registration with the
   supernode; the other edges of the community are reachable at their
   addresses, and see the phone at `10.0.0.5`.

`adb logcat -s n3n` shows the edge's log as well.
