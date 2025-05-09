Import-Module ".\scripts\windows\setup_googletest.psm1" -Force

$currentRoot = $PSScriptRoot
Setup-GoogleTest -scriptRoot $currentRoot

& g++ -g -O0 -v -std=c++23 main.cpp ../src/ipv4.cpp -I"..\include" -I"D:\Include" -L"D:\Lib\x64" -o shark.exe -lwpcap -lws2_32
& g++ -g -O0 -v -std=c++23 ../tests/test_ipv4_header_extraction.cpp ../src/ipv4.cpp -o shark_tests.exe -I"..\include" -L"..\lib" -I"D:\Include" -L"D:\Lib\x64" -lgtest -lgtest_main -lwpcap -lws2_32