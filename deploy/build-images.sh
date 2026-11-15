#!/bin/bash
# Build both images from the repo root on the machine that runs Docker.
#   deploy/build-images.sh
# Ship the agent image to other hosts with: docker save lanot-agent:dev | ssh root@HOST docker load
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -f agent/Dockerfile -t lanot-agent:dev .
docker build -f server/Dockerfile -t lanot-server:dev .
