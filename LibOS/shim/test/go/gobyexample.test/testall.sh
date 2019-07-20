#! /usr/bin/env bash
# Test 64 / 72 Gobyexample apps via their return code only.
# Relies on correct return code by Graphene
set -e
set -u
set -v
echo 'atomic-counters' >> progress
SGX=1 ./pal_loader atomic-counters
echo 'arrays' >> progress
SGX=1 ./pal_loader arrays
echo 'base64-encoding' >> progress
SGX=1 ./pal_loader base64-encoding
echo 'channel-buffering' >> progress
SGX=1 ./pal_loader channel-buffering
echo 'channel-directions' >> progress
SGX=1 ./pal_loader channel-directions
echo 'channels' >> progress
SGX=1 ./pal_loader channels
echo 'channel-synchronization' >> progress
SGX=1 ./pal_loader channel-synchronization
echo 'closing-channels' >> progress
SGX=1 ./pal_loader closing-channels
echo 'closures' >> progress
SGX=1 ./pal_loader closures
echo 'collection-functions' >> progress
SGX=1 ./pal_loader collection-functions
echo 'command-line-flags' >> progress
SGX=1 ./pal_loader command-line-flags
echo 'constants' >> progress
SGX=1 ./pal_loader constants
echo 'defer' >> progress
SGX=1 ./pal_loader defer
echo 'directories' >> progress
SGX=1 ./pal_loader directories
echo 'environment-variables' >> progress
SGX=1 ./pal_loader environment-variables
echo 'epoch' >> progress
SGX=1 ./pal_loader epoch
echo 'errors' >> progress
SGX=1 ./pal_loader errors
echo 'execing-processes' >> progress
SGX=1 ./pal_loader execing-processes
echo 'file-paths' >> progress
SGX=1 ./pal_loader file-paths
echo 'for' >> progress
SGX=1 ./pal_loader for
echo 'functions' >> progress
SGX=1 ./pal_loader functions
echo 'hello-world' >> progress
SGX=1 ./pal_loader hello-world
echo 'http-clients' >> progress
SGX=1 ./pal_loader http-clients
echo 'if-else' >> progress
SGX=1 ./pal_loader if-else
echo 'interfaces' >> progress
SGX=1 ./pal_loader interfaces
echo 'json' >> progress
SGX=1 ./pal_loader json
echo 'maps' >> progress
SGX=1 ./pal_loader maps
echo 'methods' >> progress
SGX=1 ./pal_loader methods
echo 'multiple-return-values' >> progress
SGX=1 ./pal_loader multiple-return-values
echo 'mutexes' >> progress
SGX=1 ./pal_loader mutexes
echo 'non-blocking-channel-operations' >> progress
SGX=1 ./pal_loader non-blocking-channel-operations
echo 'number-parsing' >> progress
SGX=1 ./pal_loader number-parsing
echo 'pointers' >> progress
SGX=1 ./pal_loader pointers
echo 'random-numbers' >> progress
SGX=1 ./pal_loader random-numbers
echo 'range' >> progress
SGX=1 ./pal_loader range
echo 'range-over-channels' >> progress
SGX=1 ./pal_loader range-over-channels
echo 'rate-limiting' >> progress
SGX=1 ./pal_loader rate-limiting
echo 'recursion' >> progress
SGX=1 ./pal_loader recursion
echo 'regular-expressions' >> progress
SGX=1 ./pal_loader regular-expressions
echo 'select' >> progress
SGX=1 ./pal_loader select
echo 'sha1-hashes' >> progress
SGX=1 ./pal_loader sha1-hashes
echo 'slices' >> progress
SGX=1 ./pal_loader slices
echo 'sorting-by-functions' >> progress
SGX=1 ./pal_loader sorting-by-functions
echo 'sorting' >> progress
SGX=1 ./pal_loader sorting
echo 'spawning-processes' >> progress
SGX=1 ./pal_loader spawning-processes
echo 'stateful-goroutines' >> progress
SGX=1 ./pal_loader stateful-goroutines
echo 'string-formatting' >> progress
SGX=1 ./pal_loader string-formatting
echo 'string-functions' >> progress
SGX=1 ./pal_loader string-functions
echo 'structs' >> progress
SGX=1 ./pal_loader structs
echo 'switch' >> progress
SGX=1 ./pal_loader switch
echo 'temporary-files-and-directories' >> progress
SGX=1 ./pal_loader temporary-files-and-directories
echo 'tickers' >> progress
SGX=1 ./pal_loader tickers
echo 'time-formatting-parsing' >> progress
SGX=1 ./pal_loader time-formatting-parsing
echo 'time' >> progress
SGX=1 ./pal_loader time
echo 'timeouts' >> progress
SGX=1 ./pal_loader timeouts
echo 'timers' >> progress
SGX=1 ./pal_loader timers
echo 'url-parsing' >> progress
SGX=1 ./pal_loader url-parsing
echo 'values' >> progress
SGX=1 ./pal_loader values
echo 'variables' >> progress
SGX=1 ./pal_loader variables
echo 'variadic-functions' >> progress
SGX=1 ./pal_loader variadic-functions
echo 'waitgroups' >> progress
SGX=1 ./pal_loader waitgroups
echo 'worker-pools' >> progress
SGX=1 ./pal_loader worker-pools
echo 'writing-files' >> progress
SGX=1 ./pal_loader writing-files
