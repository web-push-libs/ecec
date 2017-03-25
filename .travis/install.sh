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
if ! ./config $configs &>> build.log ||
   ! make &>> build.log ||
   ! make install &>> build.log; then
  cat build.log
  exit 1
fi
popd

if [[ "$COVERAGE" -eq 1 ]]; then
  tar xzf $HOME/.src/lcov-$LCOV_VERSION.tar.gz
  pushd lcov-$LCOV_VERSION
  if ! make -e PREFIX=$HOME/.local install &>> build.log; then
    cat build.log
    exit 1
  fi
  popd
fi

popd
