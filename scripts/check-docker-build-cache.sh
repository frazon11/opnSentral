#!/bin/sh
set -eu

workflow=".github/workflows/docker-publish.yml"
dockerfile="Dockerfile"

grep -Fq 'cache-from: type=gha,scope=opnsentral-docker' "$workflow"
grep -Fq 'cache-to: type=gha,mode=max,scope=opnsentral-docker' "$workflow"
grep -Fq 'no-cache: ${{' "$workflow"
grep -Fq 'inputs.clean_build' "$workflow"
grep -Fq 'clean_build:' "$workflow"

if grep -Fq 'no-cache: true' "$workflow"; then
    echo "Permanent no-cache Docker builds must not be enabled." >&2
    exit 1
fi

package_line=$(grep -n '^COPY webssh/package.json ' "$dockerfile" | cut -d: -f1)
install_line=$(grep -n 'npm install --omit=dev --omit=optional' "$dockerfile" | cut -d: -f1)
webssh_line=$(grep -n '^COPY webssh/ ' "$dockerfile" | cut -d: -f1)

test -n "$package_line"
test -n "$install_line"
test -n "$webssh_line"
test "$package_line" -lt "$install_line"
test "$install_line" -lt "$webssh_line"

echo "Docker build cache checks passed."
