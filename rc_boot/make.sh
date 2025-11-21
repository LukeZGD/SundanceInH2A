#!/bin/bash

set -e

xcrun -sdk iphoneos clang -arch armv7 -miphoneos-version-min=6.0 -lz main.c -o rc.boot
codesign -s - -f rc.boot
