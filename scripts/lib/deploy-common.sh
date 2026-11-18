#!/usr/bin/env bash
# Shared helpers for production deploy scripts (git pull + safe execution).

deploy_log() {
  printf '[deploy] %s\n' "$*"
}

deploy_die() {
  deploy_log "ERROR: $*"
  exit 1
}

deploy_run() {
  if [[ "${DEPLOY_DRY_RUN:-0}" == "1" ]]; then
    deploy_log "DRY-RUN: $*"
    return 0
  fi
  eval "$@"
}

deploy_parse_args() {
  DEPLOY_NO_PULL=0
  DEPLOY_DRY_RUN=0
  DEPLOY_NO_BUILD=0
  DEPLOY_NO_MIGRATE=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-pull) DEPLOY_NO_PULL=1 ;;
      --dry-run) DEPLOY_DRY_RUN=1 ;;
      --no-build) DEPLOY_NO_BUILD=1 ;;
      --no-migrate) DEPLOY_NO_MIGRATE=1 ;;
      -h|--help)
        cat <<'EOF'
Usage: ./deploy.sh [options]

Options:
  --no-pull     Skip git fetch/pull
  --no-build    Skip docker compose build / make build
  --no-migrate  Skip database migrations (admin-panel only)
  --dry-run     Print commands without executing
  -h, --help    Show this help

Environment:
  DEPLOY_BRANCH   Git branch to deploy (default: current branch or main)
  GIT_REMOTE      Git remote name (default: origin)
EOF
        exit 0
        ;;
      *)
        deploy_die "Unknown option: $1 (use --help)"
        ;;
    esac
    shift
  done
}

deploy_require_git() {
  local dir="$1"
  [[ -d "${dir}/.git" ]] || deploy_die "Not a git repository: ${dir}"
}

deploy_git_pull() {
  local dir="$1"
  local branch="${DEPLOY_BRANCH:-}"
  local remote="${GIT_REMOTE:-origin}"

  deploy_require_git "$dir"
  cd "$dir"

  if [[ -z "$branch" ]]; then
    branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
      branch="main"
    fi
  fi

  deploy_log "Repository: $(basename "$dir")"
  deploy_log "Remote: ${remote}, branch: ${branch}"

  if [[ "${DEPLOY_NO_PULL:-0}" == "1" ]]; then
    deploy_log "Skipping git pull (--no-pull)"
    return 0
  fi

  if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    deploy_log "Local changes detected — stashing before pull"
    deploy_run "git stash push -u -m 'deploy-$(date +%Y%m%d-%H%M%S)'"
  fi

  deploy_run "git fetch '${remote}' --prune"
  deploy_run "git checkout '${branch}'"
  deploy_run "git pull '${remote}' '${branch}'"

  local sha
  sha="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  deploy_log "Now at commit ${sha}"
}

deploy_require_docker() {
  command -v docker >/dev/null 2>&1 || deploy_die "docker is not installed"
  docker compose version >/dev/null 2>&1 || deploy_die "docker compose v2 is required"
}

deploy_compose() {
  local dir="$1"
  local compose_file="$2"
  shift 2

  deploy_require_docker
  (
    cd "$dir"
    if [[ "${DEPLOY_NO_BUILD:-0}" == "1" ]]; then
      deploy_run "docker compose -f '${compose_file}' up -d $*"
    else
      deploy_run "docker compose -f '${compose_file}' up -d --build $*"
    fi
  )
}

deploy_compose_exec() {
  local dir="$1"
  local compose_file="$2"
  local service="$3"
  shift 3

  (
    cd "$dir"
    if [[ "${DEPLOY_DRY_RUN:-0}" == "1" ]]; then
      deploy_log "DRY-RUN: docker compose -f ${compose_file} exec -T ${service} $*"
    else
      docker compose -f "${compose_file}" exec -T "${service}" "$@"
    fi
  )
}

deploy_wait_http() {
  local url="$1"
  local label="${2:-service}"
  local attempts="${3:-30}"

  deploy_log "Waiting for ${label} (${url})"
  for i in $(seq 1 "$attempts"); do
    if curl -sf --max-time 5 "${url}" >/dev/null 2>&1; then
      deploy_log "${label} is healthy"
      return 0
    fi
    sleep 2
  done

  deploy_die "${label} did not respond at ${url}"
}

deploy_wait_compose_healthy() {
  local dir="$1"
  local compose_file="$2"
  local service="$3"
  local attempts="${4:-60}"

  deploy_log "Waiting for container ${service} to become healthy"
  for i in $(seq 1 "$attempts"); do
    if (
      cd "$dir"
      docker compose -f "${compose_file}" ps "${service}" 2>/dev/null | grep -q '(healthy)'
    ); then
      deploy_log "${service} is healthy"
      return 0
    fi
    sleep 2
  done

  deploy_die "Container ${service} did not become healthy in time"
}

# ---- Secret generation (first deploy) --------------------------------------

deploy_rand_hex() {
  local bytes="${1:-32}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${bytes}"
    return 0
  fi
  head -c "${bytes}" /dev/urandom | xxd -p -c 256 | tr -d '\n'
}

deploy_rand_password() {
  local len="${1:-28}"
  local out=""
  while [[ ${#out} -lt ${len} ]]; do
    out+="$(deploy_rand_hex 24)"
  done
  printf '%s' "${out:0:${len}}"
}

deploy_rand_api_key() {
  deploy_rand_hex 32
}

deploy_rand_app_key() {
  if command -v openssl >/dev/null 2>&1; then
    printf 'base64:%s' "$(openssl rand -base64 32 | tr -d '\n')"
    return 0
  fi
  printf 'base64:%s' "$(deploy_rand_hex 32 | xxd -r -p 2>/dev/null | base64 | tr -d '\n')"
}

deploy_env_get() {
  local file="$1"
  local key="$2"
  [[ -f "${file}" ]] || { printf ''; return 0; }
  grep -m1 "^${key}=" "${file}" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true
}

deploy_env_set() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  touch "${file}"
  if grep -qE "^${key}=" "${file}" 2>/dev/null; then
    tmp="$(mktemp)"
    awk -v k="${key}" -v v="${value}" 'BEGIN{FS=OFS="="} $1==k{$0=k"="v} {print}' "${file}" >"${tmp}"
    mv "${tmp}" "${file}"
  else
    printf '%s=%s\n' "${key}" "${value}" >>"${file}"
  fi
}

# True if value looks like a shipped example / empty placeholder.
deploy_is_placeholder_secret() {
  local v="${1:-}"
  case "${v}" in
    ''|secret|waf|changeme|null|NULL|'""'|dev-node-key-change-me|CHANGE_ME|changeme-*|Wl6nfhb654nt58%n3vfB8f4bgigfh)
      return 0
      ;;
  esac
  return 1
}

# First-deploy gate: marker missing OR force flag.
deploy_is_first_secrets() {
  local dir="${1:-.}"
  [[ "${DEPLOY_FORCE_NEW_SECRETS:-0}" == "1" ]] && return 0
  [[ ! -f "${dir}/.secrets-initialized" ]]
}

deploy_mark_secrets_initialized() {
  local dir="${1:-.}"
  date -u +%Y-%m-%dT%H:%M:%SZ >"${dir}/.secrets-initialized"
  chmod 600 "${dir}/.secrets-initialized" 2>/dev/null || true
}

