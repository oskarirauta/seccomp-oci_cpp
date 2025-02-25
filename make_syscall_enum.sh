#!/bin/sh
# syscall reporting example for seccomp
#
# Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
# Authors:
#  Kees Cook <keescook@chromium.org>
#
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CC=$1
[ -n "$TARGET_CC_NOCACHE" ] && CC=$TARGET_CC_NOCACHE

echo "enum TYPE {"

#echo "static const char *__syscall_names[] = {"
echo "#include <sys/syscall.h>" | ${CC} -E -dM - | grep '^#define __NR_[a-z0-9_]\+[ \t].*[0-9].*$' | \
	LC_ALL=C sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([ ()+0-9a-zNR_LSYCABE]+)(.*)/ \U\1,/p'
echo "};"
