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
