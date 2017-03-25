#!/bin/bash

set -e

if ! [ -f $HOME/.src/openssl-$OPENSSL_VERSION.tar.gz ]; then
  wget -P $HOME/.src https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz
fi

if [[ "$COVERAGE" -eq 1 ]] && ! [ -f $HOME/.src/lcov-$LCOV_VERSION.tar.gz ]; then
  wget -P $HOME/.src https://github.com/linux-test-project/lcov/releases/download/v$LCOV_VERSION/lcov-$LCOV_VERSION.tar.gz
fi
