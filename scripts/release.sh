#!/usr/bin/env bash
# Bump version (major|minor|patch), tag, and push. Triggers GitHub Actions release.
set -e
case "$1" in major|minor|patch) ;; *) echo "usage: just release major|minor|patch"; exit 1 ;; esac
bump="$1"
current=$(git describe --tags --abbrev=0 2>/dev/null || true)
current=${current:-v0.0.0}
current=${current#v}
read -r major minor patch <<< "${current//./ }"
major=${major:-0} minor=${minor:-0} patch=${patch:-0}
case "$bump" in
  major) new="$((major+1)).0.0" ;;
  minor) new="${major}.$((minor+1)).0" ;;
  patch) new="${major}.${minor}.$((patch+1))" ;;
esac
echo "Releasing v${new} (was ${current})"
git tag -a "v${new}" -m "Release v${new}"
git push origin "v${new}"
