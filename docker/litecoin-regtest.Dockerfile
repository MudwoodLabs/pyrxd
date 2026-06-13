# Regtest Litecoin Core node for the Bitcoin-family counter-leg tests (Tier 2.3).
#
# Wraps an OFFICIAL Litecoin Core release binary — we do not fork, patch, or
# recompile the node. PROVENANCE NOTE (differs from regtest.Dockerfile): the
# litecoin-project GitHub release carries NO checksum manifest asset, so this
# Dockerfile pins the SHA-256 measured from the official release download on
# 2026-06-12 instead of verifying against a signed SHA256SUMS file. A version
# bump must re-measure and update BOTH args together.
#
# Build:
#     docker build -f docker/litecoin-regtest.Dockerfile \
#         -t litecoin-core:v0.21.5.5-amd64 .
#
# Used by the LTC variants of the BTC-family regtest suites
# (XCHAIN_BTC_FAMILY=ltc / BTC_REGTEST chain knob). Regtest-only; the harness
# reaches RPC via `docker exec litecoin-cli` — never exposed to the network.
#
# The release binary links only the libc family (measured via ldd), so the bare
# ubuntu:22.04 base needs no extra runtime packages.

FROM ubuntu:22.04

ARG LITECOIN_VERSION=0.21.5.5
ARG LITECOIN_SHA256=623410d4f2695a68aa71332ae0672fee19276f41c1c63a531f97e24a50edde14
ARG LITECOIN_TARBALL=litecoin-${LITECOIN_VERSION}-x86_64-linux-gnu.tar.gz
ARG LITECOIN_BASEURL=https://github.com/litecoin-project/litecoin/releases/download/v${LITECOIN_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    cd /tmp; \
    wget -q "${LITECOIN_BASEURL}/${LITECOIN_TARBALL}"; \
    echo "${LITECOIN_SHA256}  ${LITECOIN_TARBALL}" | sha256sum -c -; \
    tar xzf "${LITECOIN_TARBALL}"; \
    install -m0755 "litecoin-${LITECOIN_VERSION}/bin/litecoind" /usr/local/bin/litecoind; \
    install -m0755 "litecoin-${LITECOIN_VERSION}/bin/litecoin-cli" /usr/local/bin/litecoin-cli; \
    rm -rf /tmp/*

# Smoke-test the binary runs in this base.
RUN litecoind --version

# The test harness appends -regtest/-server/... args after the image name,
# which docker passes as CMD to this entrypoint.
ENTRYPOINT ["litecoind"]
CMD ["-regtest", "-server", "-printtoconsole"]
