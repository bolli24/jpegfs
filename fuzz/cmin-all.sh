#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if (($# > 0)) && [[ "$1" == "-h" || "$1" == "--help" ]]; then
	echo "Usage: $(basename "$0") [cargo-fuzz-cmin-options...]" >&2
	echo "Runs 'cargo fuzz cmin' for every fuzz target listed in $SCRIPT_DIR." >&2
	exit 0
fi

mapfile -t targets < <(
	cd "$SCRIPT_DIR"
	cargo fuzz list
)

if ((${#targets[@]} == 0)); then
	echo "No fuzz targets found in $SCRIPT_DIR" >&2
	exit 1
fi

for target in "${targets[@]}"; do
	echo "==> cargo fuzz cmin $target"
	(
		cd "$SCRIPT_DIR"
		cargo fuzz cmin "$@" "$target"
	)
done
