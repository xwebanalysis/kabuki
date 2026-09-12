#!/usr/bin/env sh
# Wrapper so `npm test -- --run` (Vitest convention) works with the Angular CLI.
# `--run` is accepted and ignored: the Angular unit-test builder runs once when
# watch mode is disabled. Any other arguments are forwarded unchanged.
set -e

args=""
for arg in "$@"; do
    if [ "$arg" = "--run" ]; then
        continue
    fi
    args="$args $arg"
done

# shellcheck disable=SC2086
exec ng test --watch=false $args
