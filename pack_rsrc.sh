#!/bin/bash

set -e

FILES=("artifacts/kernelcache.*.bin"
       "resources/IMGSGX535GLDriver-*")

tar -c --no-mac-metadata --no-fflags --no-xattrs --numeric-owner -vf SundanceResources.tar ${FILES[*]}
xz -f9 SundanceResources.tar
base64 -b 64 -i SundanceResources.tar.xz -o SundanceResources.b64
