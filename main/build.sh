#!/bin/bash

set -e

# Directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SRC_DIR="$SCRIPT_DIR/../src"
INCLUDE_DIR="$SCRIPT_DIR/../include"
TEST_DIR="$SCRIPT_DIR/../tests"
BUILD_DIR="$SCRIPT_DIR/../build"
LIB_DIR="$SCRIPT_DIR/../lib"

# Executables in current directory
MAIN_BIN="$SCRIPT_DIR/ntk"
TEST_BIN="$SCRIPT_DIR/ntk_tests"

# Clean option
if [[ "$1" == "--clean" ]]; then
    echo "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    rm -f "$MAIN_BIN" "$TEST_BIN"
    echo "✅ Clean complete."
    exit 0
fi

# Create build dirs
mkdir -p "$BUILD_DIR/obj" "$BUILD_DIR/test_obj"

# Compiler and flags
CXX=g++
CXXFLAGS="-g -O0 -std=c++23 -fPIC"
INCLUDES="-I$INCLUDE_DIR -I$TEST_DIR"
CFLAGS=$(pkg-config --cflags Qt5Widgets Qt5Multimedia Qt5MultimediaWidgets || echo "")
LIBS=$(pkg-config --libs Qt5Widgets Qt5Multimedia Qt5MultimediaWidgets || echo "")

# Compile .cpp to .o if changed
compile_objects() {
    local src_dir="$1"
    local obj_dir="$2"
    local -n out_array=$3

    while IFS= read -r -d '' cpp_file; do
        rel_path="${cpp_file#$SCRIPT_DIR/../}"
        safe_name="${rel_path//\//_}"
        obj_file="$obj_dir/${safe_name%.cpp}.o"
        
        if [[ ! -f "$obj_file" || "$cpp_file" -nt "$obj_file" ]]; then
            echo "Compiling $cpp_file -> $obj_file"
            $CXX $CXXFLAGS $INCLUDES $CFLAGS -c "$cpp_file" -o "$obj_file"
        fi
        out_array+=("$obj_file")
    done < <(find "$src_dir" -name '*.cpp' -print0)
}

# Compile source and test objects
SRC_OBJS=()
TEST_OBJS=()
compile_objects "$SRC_DIR" "$BUILD_DIR/obj" SRC_OBJS
compile_objects "$TEST_DIR" "$BUILD_DIR/test_obj" TEST_OBJS

# Compile main.cpp
MAIN_CPP="$SCRIPT_DIR/main.cpp"
MAIN_OBJ="$BUILD_DIR/obj/main.o"
if [[ ! -f "$MAIN_OBJ" || "$MAIN_CPP" -nt "$MAIN_OBJ" ]]; then
    echo "Compiling $MAIN_CPP"
    $CXX $CXXFLAGS $INCLUDES -c "$MAIN_CPP" -o "$MAIN_OBJ"
fi

# Link main binary
echo "Linking main binary..."
$CXX $CXXFLAGS "${SRC_OBJS[@]}" "$MAIN_OBJ" \
    $INCLUDES -L"$LIB_DIR" \
    -o "$MAIN_BIN" \
    -lpcap -lssl -lcrypto -lcurl -lz

# Link test binary
echo "Linking test binary..."
$CXX $CXXFLAGS "${SRC_OBJS[@]}" "${TEST_OBJS[@]}" \
    $INCLUDES $CFLAGS -L"$LIB_DIR" \
    -o "$TEST_BIN" \
    -lgtest -lgtest_main -lpcap -lssl -lcrypto $LIBS -lcurl -lz

echo "✅ Build complete. Run ./ntk or ./ntk_tests"
