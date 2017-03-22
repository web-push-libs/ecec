#!/bin/bash

set -e

export CC="ccache cc"
export CXX="ccache c++"

mkdir $HOME/.deps
pushd $HOME/.deps

tar xzf $HOME/.src/openssl-$OPENSSL_VERSION.tar.gz
pushd openssl-$OPENSSL_VERSION
if ! ./config --prefix=$HOME/.local &>> build.log ||
   ! make &>> build.log ||
   ! make install &>> build.log; then
  cat build.log
  exit 1
fi
popd

tar xzf $HOME/.src/lcov-$LCOV_VERSION.tar.gz
pushd lcov-$LCOV_VERSION
if ! make -e PREFIX=$HOME/.local install &>> build.log; then
  cat build.log
  exit 1
fi
popd

popd
