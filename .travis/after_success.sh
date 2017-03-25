#!/bin/bash

set -e

if [[ "$COVERAGE" -eq 1 ]]; then
  lcov --directory . --no-external --capture --output-file coverage.info
  bash <(curl -s https://codecov.io/bash) -X gcov -X coveragepy
fi
