#!/bin/bash

set -e

xcrun -sdk iphoneos clang -arch armv7 -miphoneos-version-min=5.0 -lz -L. main.c -o rc.boot
codesign -s - -f rc.boot
