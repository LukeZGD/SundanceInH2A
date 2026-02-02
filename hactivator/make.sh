#!/bin/bash

set -e

xcrun -sdk iphoneos clang \
    -arch armv7 \
    -dynamiclib \
    -framework CoreFoundation \
    -miphoneos-version-min=6.0 \
    main.c libMobileGestalt.tbd \
    -o hactivator.dylib

codesign -s - -f hactivator.dylib
