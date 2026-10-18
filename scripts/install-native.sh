#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
version=$(cat "$root/native-version.txt")
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid native version' >&2; exit 1; }
prefix=${1:-"$root/.native"}
source="$root/.native-src-$version"
if [[ ! -e "$source" ]]; then git clone --depth 1 --branch "$version" https://github.com/licensebox/c.git "$source"; fi
[[ "$(git -C "$source" remote get-url origin)" == 'https://github.com/licensebox/c.git' ]] || { echo 'Unexpected native source remote' >&2; exit 1; }
[[ "$(git -C "$source" rev-parse HEAD)" == "$(git -C "$source" rev-parse "$version^{commit}")" ]] || { echo 'Native checkout is not at the pinned release' >&2; exit 1; }
git -C "$source" diff --quiet
cmake -S "$source" -B "$root/.native-build-$version" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_LIBDIR=lib
cmake --build "$root/.native-build-$version" -j 2
cmake --install "$root/.native-build-$version" --prefix "$prefix"
printf 'Installed native core in %s/lib\n' "$prefix"
