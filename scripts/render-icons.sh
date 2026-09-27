#!/usr/bin/env bash
# Regenerates assets/icons/*.png (72 px and @2x 144 px) from the glyphs in
# src/render/glyphs.rs. Needs ImageMagick 7 (`magick`).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --quiet write_icon_sources -- --ignored
for svg in assets/icons/source/*.svg; do
	name=$(basename "$svg" .svg)
	magick -background none -density 384 "$svg" -resize 72x72 "assets/icons/$name.png"
	magick -background none -density 384 "$svg" -resize 144x144 "assets/icons/$name@2x.png"
done
echo "rendered $(ls assets/icons/*.png | wc -l) icons"
