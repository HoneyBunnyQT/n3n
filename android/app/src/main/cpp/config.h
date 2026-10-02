/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * What ./configure --disable-relay writes to include/config.h, for the
 * Android build, which runs no configure (see CMakeLists.txt)
 */

#define HAVE_LIBPTHREAD 1
#define N3N_NO_RELAY 1

#define PACKAGE_BUGREPORT ""
#define PACKAGE_NAME "n3n"
#define PACKAGE_STRING "n3n android"
#define PACKAGE_TARNAME "n3n"
#define PACKAGE_URL ""
#define PACKAGE_VERSION VERSION
