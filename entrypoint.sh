#!/bin/bash
set -e

echo "::group::LeftSize Cloud Cost Optimization Scanner"
echo "Starting LeftSize scan..."
echo "Cloud Provider: ${LEFTSIZE_CLOUD_PROVIDER}"
echo "Verbose: ${LEFTSIZE_VERBOSE}"
echo "::endgroup::"

# Run the Python scanner (set -e: test the exit code directly)
if python3 /action/run.py; then
    echo "✅ LeftSize scan completed successfully"
else
    EXIT_CODE=$?
    echo "❌ LeftSize scan failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi
