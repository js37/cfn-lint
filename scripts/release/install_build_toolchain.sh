#!/usr/bin/env bash
#
# Install the PyPI release build toolchain with hash verification.
#
# 1. Install pip-tools, setuptools, build, wheel and twine at the exact
#    versions declared in requirements/release-build.in.
# 2. Compile that input into requirements/release-build.lock with
#    pip-compile --generate-hashes.
# 3. Re-install the lockfile with --require-hashes so pip aborts the
#    release build if any distribution's content hash does not match
#    what pip-tools just resolved against the index.
# 4. Install the project itself with --no-build-isolation to reuse the
#    hash-verified setuptools/wheel instead of fetching an unpinned
#    PEP 517 environment from PyPI.
#
# Call from the release workflows in place of the old unpinned
# "pip install --upgrade setuptools build wheel twine; pip install -e ."
# sequence; the Dockerfile also benefits from the same policy.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python -m pip install --upgrade --no-cache-dir -r requirements/release-build.in
pip-compile --generate-hashes --allow-unsafe --quiet --output-file requirements/release-build.lock requirements/release-build.in
python -m pip install --no-cache-dir --require-hashes -r requirements/release-build.lock
python -m pip install --no-cache-dir --no-build-isolation -e .
