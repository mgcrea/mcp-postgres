#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# release.sh — Replicate the Bitbucket Pipeline release step locally.
#
# Builds the Docker image with the same tags and build-args as CI, then
# pushes to Harbor.
#
# Usage:
#   ./scripts/release.sh              # build & push
#   ./scripts/release.sh --dry-run    # build only, show what would be pushed
#
# Required env vars (or set them in .env):
#   HARBOR_REGISTRY, HARBOR_PROJECT, HARBOR_USERNAME, HARBOR_PASSWORD
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

# Source .env if present
if [[ -f "${PROJECT_DIR}/.env" ]]; then
    echo -e "${CYAN}Loading .env file${NC}"
    set -a
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.env"
    set +a
fi

# Validate required env vars
missing=()
for var in HARBOR_REGISTRY HARBOR_PROJECT HARBOR_USERNAME HARBOR_PASSWORD; do
    if [[ -z "${!var:-}" ]]; then
        missing+=("$var")
    fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}Error: missing required environment variables: ${missing[*]}${NC}" >&2
    echo "Set them in your environment or in ${PROJECT_DIR}/.env" >&2
    exit 1
fi

# Git metadata (replaces Bitbucket built-in variables)
GIT_COMMIT="$(git -C "${PROJECT_DIR}" rev-parse HEAD)"
GIT_COMMIT_SHORT="${GIT_COMMIT:0:8}"
GIT_BRANCH="$(git -C "${PROJECT_DIR}" rev-parse --abbrev-ref HEAD)"
GIT_COMMIT_TIME="$(git -C "${PROJECT_DIR}" log -1 --format=%ct)"
REPO_SLUG="$(basename "${PROJECT_DIR}")"

# Image coordinates
DOCKER_IMAGE="${HARBOR_REGISTRY}/${HARBOR_PROJECT}/${REPO_SLUG}"
DOCKER_UNIQUE_TAG="${GIT_BRANCH}-${GIT_COMMIT_SHORT}"
DOCKER_SHORT_TAG="${GIT_BRANCH}"

echo -e "${CYAN}=== Release Info ===${NC}"
echo -e "  Image:      ${DOCKER_IMAGE}"
echo -e "  Branch:     ${GIT_BRANCH}"
echo -e "  Commit:     ${GIT_COMMIT_SHORT}"
echo -e "  Unique tag: ${DOCKER_UNIQUE_TAG}"
echo -e "  Short tag:  ${DOCKER_SHORT_TAG}"
if [[ "${GIT_BRANCH}" == "main" ]]; then
    echo -e "  Latest:     ${GREEN}yes${NC}"
fi
if $DRY_RUN; then
    echo -e "  Mode:       ${YELLOW}DRY RUN${NC}"
fi
echo ""

# Docker login
if ! $DRY_RUN; then
    echo -e "${CYAN}Logging in to Harbor...${NC}"
    echo -n "${HARBOR_PASSWORD}" | docker login --username "${HARBOR_USERNAME}" --password-stdin "${HARBOR_REGISTRY}"
    echo ""
fi

# Build
echo -e "${CYAN}Building image...${NC}"
docker build --platform linux/amd64 -t "${DOCKER_IMAGE}:${DOCKER_UNIQUE_TAG}" "${PROJECT_DIR}" \
    --build-arg GIT_COMMIT="${GIT_COMMIT}" \
    --build-arg GIT_COMMIT_SHORT="${GIT_COMMIT_SHORT}" \
    --build-arg GIT_COMMIT_TIME="${GIT_COMMIT_TIME}" \
    --build-arg GIT_BRANCH="${GIT_BRANCH}"
echo ""

# Tag
echo -e "${CYAN}Tagging...${NC}"
docker tag "${DOCKER_IMAGE}:${DOCKER_UNIQUE_TAG}" "${DOCKER_IMAGE}:${DOCKER_SHORT_TAG}"
if [[ "${GIT_BRANCH}" == "main" ]]; then
    docker tag "${DOCKER_IMAGE}:${DOCKER_UNIQUE_TAG}" "${DOCKER_IMAGE}:latest"
fi

# Push
tags=("${DOCKER_UNIQUE_TAG}" "${DOCKER_SHORT_TAG}")
if [[ "${GIT_BRANCH}" == "main" ]]; then
    tags+=("latest")
fi

for tag in "${tags[@]}"; do
    if $DRY_RUN; then
        echo -e "  ${YELLOW}[dry-run]${NC} would push ${DOCKER_IMAGE}:${tag}"
    else
        echo -e "  ${CYAN}Pushing${NC} ${DOCKER_IMAGE}:${tag}"
        docker push "${DOCKER_IMAGE}:${tag}"
    fi
done

echo ""
echo -e "${GREEN}Done!${NC}"
