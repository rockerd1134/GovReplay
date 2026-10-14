#!/bin/sh
set -eu

lock_file="foundry-deps.lock"

if [ ! -f "$lock_file" ]; then
  echo "Missing $lock_file" >&2
  exit 1
fi

while read -r name repo ref target; do
  # Accept a copied Windows lock file as well as the LF-normalized Git version.
  target=$(printf '%s' "${target:-}" | tr -d '\r')
  case "$name" in
    ""|\#*) continue ;;
  esac

  if [ -z "${repo:-}" ] || [ -z "${ref:-}" ] || [ -z "${target:-}" ]; then
    echo "Invalid dependency line in $lock_file: $name $repo $ref $target" >&2
    exit 1
  fi

  if [ -d "$target/.git" ]; then
    echo "Updating $name at $target to $ref"
    dependency_dir=$(cd "$target" && pwd -P)
    # Docker bind mounts may report a different owner; trust only this declared dependency.
    # The pinned image's Git requires this setting in a global config, not -c.
    safe_config=$(mktemp)
    trap 'rm -f "$safe_config"' EXIT
    git config --file "$safe_config" --add safe.directory "$dependency_dir"
    GIT_CONFIG_GLOBAL="$safe_config" git -C "$target" fetch --depth 1 origin "refs/tags/$ref:refs/tags/$ref"
    GIT_CONFIG_GLOBAL="$safe_config" git -C "$target" checkout --detach "$ref"
    rm -f "$safe_config"
    trap - EXIT
  elif [ -e "$target" ]; then
    echo "Dependency target exists but is not a git checkout: $target" >&2
    exit 1
  else
    echo "Installing $name@$ref into $target"
    git clone --depth 1 --branch "$ref" "$repo" "$target"
  fi
done < "$lock_file"
