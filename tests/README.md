# Repository tests

This directory contains cross-package regressions and acceptance fixtures.
Package-local checks remain beside the package they exercise.
Tests use synthetic or disposable state unless their output states otherwise.
A passing source test does not establish installed or live behavior.
Run every test that names a changed file, then the relevant aggregate check.
