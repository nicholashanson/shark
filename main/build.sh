#!/bin/bash

# Ensure script stops on error
set -e

# Define current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Compile main application
g++ -g -O0 -std=c++23 "$SCRIPT_DIR/main.cpp" "$SCRIPT_DIR/../src/ipv4.cpp" \
    -I"$SCRIPT_DIR/../include" -o shark \
    -lpcap
    
# Compile test application
g++ -g -O0 -std=c++23 -fPIC "$SCRIPT_DIR/../tests/test_ipv4_header_extraction.cpp" \
    "$SCRIPT_DIR/../src/utils.cpp" \
    "$SCRIPT_DIR/../src/ipv4.cpp" \
    `pkg-config --cflags --libs Qt5Widgets` \
    -I"$SCRIPT_DIR/../include" -L"$SCRIPT_DIR/../lib" \
    -lgtest -lgtest_main -o shark_tests

echo "Build complete."
