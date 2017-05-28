#!/bin/bash

set -e

export CC="ccache cc"
export CXX="ccache c++"

mkdir $HOME/.deps
pushd $HOME/.deps

tar xzf $HOME/.src/openssl-$OPENSSL_VERSION.tar.gz
pushd openssl-$OPENSSL_VERSION
configs="--prefix=$HOME/.local --openssldir=$HOME/.local"
if [[ $CMAKE_BUILD_TYPE = "Debug" ]]; then
  configs="$configs -d"
fi
chronic ./config $configs
chronic make
chronic make install
popd

if [[ "$COVERAGE" -eq 1 ]]; then
  tar xzf $HOME/.src/lcov-$LCOV_VERSION.tar.gz
  pushd lcov-$LCOV_VERSION
  chronic make -e PREFIX=$HOME/.local install
  popd
fi

popd
