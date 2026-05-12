# SecorizonAI — Containerized single-user image
#
# Author: Laurent Gaffie  <laurent@secorizon.com>
# https://secorizon.com
# twitter.com/secorizon
#
# Two-stage build:
#   1. golang:alpine compiles chat.go into a static-ish binary
#   2. debian:slim provides a minimal runtime + the recon tools the agent
#      reaches for most often (curl, dig, nmap, jq, openssh-client, git, …)
#
# Build with `docker build -t secorizon-ai:latest .` from the package root,
# OR `docker compose build` from inside docker/.

# ─── Stage 1: build ────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY chat.go ./
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o secorizon ./chat.go


# ─── Stage 2: runtime ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://secorizon.com" \
      org.opencontainers.image.description="SecorizonAI — terminal AI agent for security research" \
      org.opencontainers.image.licenses="Apache-2.0 WITH Commons-Clause"

# Tools the agent reaches for most often. Add more with `apt install` at runtime
# or extend this list in your fork. Heavy/aggressive tools (nuclei, sqlmap,
# msfvenom, nikto, wpscan) are intentionally NOT pre-installed — the chat
# shell's safety filter would prompt for confirmation on every use anyway,
# and bundling them grows the image without consent.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl wget \
        dnsutils \
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        nmap \
        jq \
        git \
        openssh-client \
        tcpdump \
        python3 python3-pip \
        less \
    && rm -rf /var/lib/apt/lists/*

# Non-root user — the AI runs as this user, sandboxed from the container's
# system files. mkdir creates the standard runtime layout up front.
RUN useradd -m -s /bin/bash -u 1000 secorizon \
    && mkdir -p /home/secorizon/.secorizon/guides \
                /home/secorizon/engagement \
                /home/secorizon/reports \
    && chown -R secorizon:secorizon /home/secorizon

USER secorizon
WORKDIR /home/secorizon

COPY --from=builder /src/secorizon /usr/local/bin/secorizon

# Default: drop the user straight into the agent. Override with:
#   docker run -it --rm --entrypoint /bin/bash secorizon-ai:latest
ENTRYPOINT ["/usr/local/bin/secorizon"]
