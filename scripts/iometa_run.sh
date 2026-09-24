#!/bin/bash
set -euo pipefail
KERNEL="$1"
OUT="$2"
/tmp/iometa/iometa -A "${KERNEL}" > "${OUT}" || true
if [[ ! -s "${OUT}" ]]; then
  /tmp/iometa/iometa "${KERNEL}" > "${OUT}" || true
fi
wc -l "${OUT}"
