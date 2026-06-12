# Regtest Radiant-Core node for local pyrxd development (`pyrxd regtest`).
#
# Wraps an OFFICIAL Radiant-Core release binary — we do not fork, patch, or
# recompile the node; we fetch the published linux-x64 daemon and verify its
# SHA-256 against the release's signed checksum file. This is the committed,
# reproducible replacement for the previously ad-hoc `radiant-core:*-amd64`
# image that was built outside the repo and that a fresh developer could not
# obtain.
#
# Build (pin to the latest Radiant-Core release):
#     docker build -f docker/regtest.Dockerfile \
#         --build-arg RADIANT_VERSION=v3.1.1 \
#         -t radiant-core:v3.1.1-amd64 .
#
# `pyrxd regtest setup` builds this for you; `pyrxd regtest up` then runs it.
# The container is regtest-only, binds RPC to 127.0.0.1, and is reached solely
# via `docker exec radiant-cli` — never exposed to the network.
#
# Base: ubuntu:22.04 is chosen deliberately — the release binary dynamically
# links Boost 1.74 (22.04's default) and needs GLIBC >= 2.34 (22.04 ships
# 2.35). Debian bullseye's glibc (2.31) is too old; bookworm's Boost (1.81) is
# the wrong soname. Measured with `ldd`/`objdump -T` on the v3.1.x daemon.

FROM ubuntu:22.04

ARG RADIANT_VERSION=v3.1.1
ARG RADIANT_TARBALL=radiant-${RADIANT_VERSION}-linux-x64.tar.gz
ARG RADIANT_BASEURL=https://github.com/Radiant-Core/Radiant-Core/releases/download/${RADIANT_VERSION}

# Runtime shared libraries the daemon links against (measured via ldd).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        libboost-chrono1.74.0 \
        libboost-filesystem1.74.0 \
        libboost-system1.74.0 \
        libboost-thread1.74.0 \
        libdb5.3++ \
        libevent-2.1-7 \
        libevent-pthreads-2.1-7 \
        libminiupnpc17 \
        libsodium23 \
        libssl3 \
        libzmq5 \
    && rm -rf /var/lib/apt/lists/*

# Fetch the official release daemon + cli, verify integrity against the
# release checksum file, install only the two binaries the devnet uses.
RUN set -eux; \
    cd /tmp; \
    wget -q "${RADIANT_BASEURL}/${RADIANT_TARBALL}"; \
    wget -q "${RADIANT_BASEURL}/SHA256SUMS.txt"; \
    grep " ${RADIANT_TARBALL}\$" SHA256SUMS.txt | sha256sum -c -; \
    tar xzf "${RADIANT_TARBALL}"; \
    install -m0755 "radiant-${RADIANT_VERSION}-linux-x64/radiantd" /usr/local/bin/radiantd; \
    install -m0755 "radiant-${RADIANT_VERSION}-linux-x64/radiant-cli" /usr/local/bin/radiant-cli; \
    rm -rf /tmp/*

# Smoke-test that the binary actually runs in this base (catches a missing lib
# at build time rather than at `regtest up`).
RUN radiantd --version

# The devnet driver overrides the entrypoint and passes -regtest flags
# (see pyrxd/devnet.py); this default makes the image runnable standalone too.
ENTRYPOINT ["radiantd"]
CMD ["-regtest", "-server", "-printtoconsole"]
