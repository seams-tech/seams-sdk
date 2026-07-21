#!/usr/bin/env bash

set -euo pipefail

target="${1:-staging}"
repository="${SEAMS_GITHUB_REPOSITORY:-seams-tech/seams-sdk}"

case "$target" in
  staging | production) ;;
  *)
    printf 'Usage: %s [staging|production]\n' "$0" >&2
    exit 2
    ;;
esac

for command_name in gh pnpm tee; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required command is unavailable: %s\n' "$command_name" >&2
    exit 1
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
values_file="$HOME/.seams/${target}-deployment.env"
backup_dir="$HOME/.seams/backups"
backup_file="$backup_dir/${target}-$(date +%Y%m%d-%H%M%S).txt"

if [[ ! -f "$values_file" ]]; then
  printf 'Deployment values file is missing: %s\n' "$values_file" >&2
  exit 1
fi

cd "$repo_root"
gh auth status

chmod 600 "$values_file"
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
umask 077

printf '\nWARNING: This will rotate the %s GitHub Environment variables and secrets in %s.\n' \
  "$target" \
  "$repository" >&2
printf 'Existing GitHub values will be overwritten and cannot be read back from GitHub.\n' >&2
printf 'Wallets created with the current deployment identities may stop working.\n' >&2
printf 'Back up the current generation before continuing.\n' >&2
printf 'The new secret manifest will be printed and saved to %s.\n\n' "$backup_file" >&2

if [[ ! -t 0 ]]; then
  printf 'Rotation requires an interactive terminal confirmation.\n' >&2
  exit 1
fi

read -r -p "Continue with ${target} rotation? Type Y or confirm: " confirmation
case "$confirmation" in
  y | Y | yes | Yes | YES | confirm | Confirm | CONFIRM) ;;
  *)
    printf 'Rotation cancelled. No GitHub values were changed.\n' >&2
    exit 0
    ;;
esac

printf '\nRotation confirmed. Uploading the new %s generation.\n\n' "$target" >&2

pnpm --silent router:deploy:env-keygen -- \
  --env "$target" \
  --values-file "$values_file" \
  --apply \
  --rotate \
  --repo "$repository" \
  | tee "$backup_file"

chmod 600 "$backup_file"
printf '\nDeployment manifest backup: %s\n' "$backup_file" >&2
