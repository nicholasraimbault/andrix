#!/usr/bin/env bash
# Red until apex_artifact.sh extracts andrix-hello from a verified built APEX.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
elf=${ANDRIX_PROOF_ELF:-"$root/out/apex-artifact/payload/bin/andrix-hello"}
exec "$root/scripts/proof/host_elf.sh" "$elf"
