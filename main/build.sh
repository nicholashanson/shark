#!/bin/bash

# Ensure script stops on error
set -e

# Define current directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SRC_DIR="$SCRIPT_DIR/../src"
INCLUDE_DIR="$SCRIPT_DIR/../include"

TEST_DIR="$SCRIPT_DIR/../tests"

# Find all .cpp files in src
SRC_FILES=$(find "$SRC_DIR" -name '*.cpp')

# Find all .cpp files in tests
TEST_FILES=$(find "$TEST_DIR" -name '*.cpp')

# Compile main application
g++ -g -O0 -std=c++23 "$SCRIPT_DIR/main.cpp" \
    $SRC_FILES \
    -I"$SCRIPT_DIR/../include" -o shark \
    -lpcap \
    -lssl -lcrypto 
    
# Compile test application
g++ -g -O0 -std=c++23 -fPIC \
    $TEST_FILES \
    $SRC_FILES \
    `pkg-config --cflags --libs Qt5Widgets Qt5Multimedia Qt5MultimediaWidgets` \
    -I"$TEST_DIR" \
    -I"$SCRIPT_DIR/../include" -L"$SCRIPT_DIR/../lib" \
    -lgtest -lgtest_main \
    -lssl -lcrypto \
    -o shark_tests

echo "Build complete."
