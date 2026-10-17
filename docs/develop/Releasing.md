<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Releasing n3n-be

How a release of n3n-be gets its packages, and what has to be settled
before the first one.  The workflow is there, `.github/workflows/release.yml`,
but it has not run yet: it starts only by hand, never by a pushed tag.

## What a release is

An annotated tag, `3.4.8` say, on a commit whose `VERSION` says the same.
From the tag, the workflow `Release` builds:

| file | for | built |
|------|-----|-------|
| `n3n-be_3.4.8-1_amd64.deb`, `_arm64`, `_armhf`, `_i386` | Debian 12 and newer, Ubuntu 22.04 and newer | on Ubuntu 22.04 (arm64 natively, armhf and i386 cross) |
| `n3n-be-3.4.8-1.x86_64.rpm` | Fedora | in a `fedora:latest` container |
| `n3n-be-3.4.8-1-x86_64.pkg.tar.zst` | Arch Linux | in an `archlinux:base-devel` container, from `packages/arch/PKGBUILD` |
| `n3n-be-android-3.4.8.apk` | Android 7.0 and newer | signed with the release key, see below |
| `n3n-be-3.4.8-windows-x86_64.zip` | Windows 10 and newer, 64 bit | on `windows-latest` as tests.yml builds and tests it, but linked statically (no `libwinpthread-1.dll` of the toolchain to bring along); `n3n.exe` alone, without the copies `n3n-edge.exe` and `n3n-supernode.exe` (`n3n.exe edge`, `n3n.exe supernode`), the sample configurations, `n3nctl`, the licences and a README (`packages/windows/README.txt`, from the workflow's commit, so that older tags get it too) |
| `SHA256SUMS` | checking the downloads | |

With "draft" ticked, it then makes a draft GitHub Release of the tag with
all of them, the tag's message as its notes, and an attestation for each
file: a statement signed by GitHub of the workflow and the commit it was
built from (`gh attestation verify FILE --repo HoneyBunnyQT/n3n-be`).  A
draft is seen only by those who can write to the repository; it becomes
public when someone publishes it, by hand, after a look at it.

The packages are named `n3n-be`.  They install the same programs as
upstream's `n3n` packages (`n3n`, `n3n-edge`, `n3n-supernode`, `n3nctl`,
the systemd units) and so provide, conflict with and replace `n3n`: one
goes in place of the other.  The user `n3n`, which the supernode's unit
runs as and the edge drops its privileges to, comes from a sysusers.d file
(and from the postinst of the .deb).

The .deb of armhf and i386 are cross built, where dpkg-shlibdeps finds no
libraries to look at: they do not say which version of libc6 they need.

The Windows programs need the TAP driver of OpenVPN (tap-windows6), which
the zip does not bring, as before; the job fails if `n3n.exe` needs a DLL
that is not Windows' own.  They are not signed: SmartScreen warns on the
first start.

## Steps

1. `VERSION` to the new version, commit, `git tag -a 3.4.8` with the
   changes as its message, push both.
2. Actions, Release, Run workflow: the tag, and "draft" ticked.
3. Approve the run's use of the environment `release` (it holds the
   signing key).
4. Look at the draft: the files, the notes; install a package or two.
5. Publish it.

## Before the first release

- **The Android application ID** (settled 2026-10-15):
  `io.github.honeybunnyqt.n3nbe`, the GitHub account's own name space (a
  `-` is not allowed in it).  It was `dev.n3n.android`, upstream's domain
  (n3n.dev, whose `pkg.n3n.dev` is its apt repository).  It is the app's
  identity for good: another ID is another app, which users install anew -
  a build from before has to be uninstalled.  The code's package stays
  `dev.n3n.android` (`namespace`), a name in the source only.
- **The signing key of the app.**  Made once, kept for good: every update
  has to be signed with the same key, or Android will not install it over
  the old one.  Made with the JDK's `keytool`, under any name - a
  pseudonym is fine, nobody checks it, but anyone can read it from the
  APK, so put nothing in it that should stay private:

  ```sh
  keytool -genkeypair -v -keystore n3n-be-release.jks -alias n3n-be \
      -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=Honey Bunny QT"
  ```

  Keep the file and its passwords in two safe places offline.  For the
  workflow, in Settings, Environments, an environment `release` (with
  yourself as required reviewer, so that no run gets the key unasked) and
  in it the secrets `ANDROID_KEYSTORE` (the file in base64:
  `base64 -w0 n3n-be-release.jks`), `ANDROID_KEYSTORE_PASSWORD`,
  `ANDROID_KEY_ALIAS` (`n3n-be`) and `ANDROID_KEY_PASSWORD`.
- **The versions of the actions** release.yml uses: brought up to date
  on 2026-10-15 (`download-artifact@v8`, Node 24 as the others;
  `attest-build-provenance@v4`, now a wrapper of `actions/attest`, with
  the same inputs and permissions).
- `tests.yml` no longer reacts to releases: it used to build its own
  packages for a published release and put them on it as a prerelease,
  which would now come on top of release.yml's.

## Later: where users get it from

Each of these needs a decision and an account or a key of its own, and
none is set up yet:

- **Debian/Ubuntu**: an apt repository, signed with an OpenPGP key (which
  can be made under the pseudonym too: `gpg --quick-generate-key "Honey
  Bunny QT <honeybunnyqt.official@proton.me>" ed25519 sign 2y`), on GitHub
  Pages; or the openSUSE Build Service, which builds and hosts repositories
  for Debian, Ubuntu, Fedora, openSUSE and Arch from one place.
- **Arch**: an AUR package `n3n-be`, with the source of the release
  instead of the tree; pushed to the AUR with an SSH key.
- **Fedora**: COPR, which builds from the spec.
- **Android**: Obtainium follows the GitHub Releases as they are; the
  IzzyOnDroid repository takes the APKs from them for the F-Droid app;
  F-Droid itself builds from the source, a merge request to fdroiddata.
- Not built yet: the OpenWrt packages and the macOS programs (tests.yml
  builds them), and aarch64 for the .rpm and the Arch package.
