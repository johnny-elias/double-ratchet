#!/usr/bin/env bash
set -e

# 1) compile
g++ -std=c++17 -g \
    -Iinclude -Iinclude-shared \
    src/drivers/crypto_driver.cxx \
    demo/demo_keys.cpp \
    -lcryptopp -o demo_keys

# 2) run
./demo_keys
