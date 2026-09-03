#!/bin/bash

# Regenerates the wire client from the PINNED spec in spec/openapi.yaml.
#
# The output is committed, like the Go and Java SDKs and unlike the Node one:
# a NuGet package is built from source by CI and by anyone who clones this
# repo, and neither should need a code generator on PATH.
#
# NSwag is installed into a scratch tool path at a pinned version, so the
# machine's global tool list is left alone and two runs a year apart produce
# the same client.

set -euo pipefail

cd "$(dirname "$0")/.."

NSWAG_VERSION="${NSWAG_VERSION:-14.6.1}"
TOOLS="${TOOLS:-/tmp/vpndetection-nswag-${NSWAG_VERSION}}"
OUT="src/VPNDetection/Generated/Api.cs"

export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

if [ ! -x "${TOOLS}/nswag" ] ; then
    echo "==> installing NSwag ${NSWAG_VERSION} into ${TOOLS}"
    dotnet tool install NSwag.ConsoleCore --version "$NSWAG_VERSION" --tool-path "$TOOLS"
fi

echo "==> generating ${OUT}"
mkdir -p "$(dirname "$OUT")"

# Settings that matter, in the order they bite:
#   generateOptionalPropertiesAsNullable  the absent-versus-false contract. Without it every
#                                         tier-gated flag lands as a plain `bool` defaulting to
#                                         false, and the SDK's single most important semantic is
#                                         gone before a line of our own code runs.
#   clientClassAccessModifier             the wire client is an implementation detail.
#   dateType:System.DateOnly              `format: date` is a calendar day, not an instant.
#   arrayType:IReadOnlyList               a response collection a caller cannot mutate.
"${TOOLS}/nswag" openapi2csclient \
    /input:spec/openapi.yaml \
    /output:"$OUT" \
    /namespace:VPNDetection \
    /className:WireClient \
    /clientClassAccessModifier:internal \
    /generateClientInterfaces:false \
    /exceptionClass:WireException \
    /jsonLibrary:SystemTextJson \
    /generateOptionalPropertiesAsNullable:true \
    /generateNullableReferenceTypes:true \
    /generateDataAnnotations:false \
    /generateJsonMethods:false \
    /operationGenerationMode:SingleClientFromOperationId \
    /dateType:System.DateOnly \
    /arrayType:System.Collections.Generic.IReadOnlyList \
    /arrayInstanceType:System.Collections.Generic.List \
    /arrayBaseType:System.Collections.Generic.List \
    /responseArrayType:System.Collections.Generic.IReadOnlyList \
    /newLineBehavior:LF

echo "==> normalizing names"
python3 scripts/normalize_generated.py "$OUT"

echo "==> done. Review the diff, then commit spec/ and ${OUT} together."
