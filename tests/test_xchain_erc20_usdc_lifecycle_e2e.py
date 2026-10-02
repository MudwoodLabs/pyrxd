"""END-TO-END RXD↔USDC atomic swap on real chains — the first proof the token corridor COMPOSES.

Everything in the ERC-20 corridor has been proven SEPARATELY. `test_erc20_leg_fork_integration.py`
drives `Erc20HtlcLeg` against a forked mainnet — the real USDC proxy, its real blacklist, a real
claim inside the gas budget. The regtest e2e drives a whole swap through the real `SwapCoordinator`
— but with the NATIVE ETH leg, zero ERC-20 references.

Nothing has ever run the two together, and until this file existed, `Erc20HtlcLeg` was constructed
nowhere outside its own tests: the corridor had no production caller at all. Nine adversarial review
rounds found real defects by READING this code. Not one of them could have found a defect that only
appears when the pieces meet.

What is real here:

* **USDC is the real contract** on a mainnet fork — 6 decimals, the real issuer blacklist, the real
  transfer semantics. A mock token is worthless for exactly the two things most likely to be wrong.
* **The Radiant leg is a real covenant** on a radiant-core regtest node, with a real CSV refund.
* **The coordinator is the production one**, driven NEGOTIATED → COMPLETED, plus the refund path.

Moves no real value: anvil is a local fork with public deterministic keys, Radiant is a
self-managed regtest container, and the tokens are conjured ON THE FORK (see `_seed_token`).

THE FORK RUNS UNDER A DEVNET CHAIN ID (31337), not the forked chain's. The taker gate judges the
counter leg by the chain id it signs for, and refuses a regtest Radiant leg beside a chain id that
moves real value — a mainnet id (1, 8453) is exactly that, fork or not. So anvil serves the forked
state under 31337, and the tokens the suite uses are the forked chain's pinned tokens re-pinned to
31337 HERE, test-side (`_on_devnet`): same address, same decimals, same freeze function — the fork
carries the very contract at that address, and `assert_token_matches_chain` still reads its
decimals live. Production's token registry is unchanged.

Run it::

    XCHAIN_ERC20_E2E=1 PYRXD_ETH_FORK_RPC=https://eth.drpc.org \\
        .venv/bin/pytest tests/test_xchain_erc20_usdc_lifecycle_e2e.py -m integration -s

Or against Base, which is the corridor a Base mainnet run would actually take — and the only one
that exercises the `has_blacklist=False` branch of the pre-reveal gate, since Base USDT cannot
freeze and L1 USDT can::

    XCHAIN_ERC20_E2E=1 PYRXD_ETH_FORK_CHAIN_ID=8453 \\
        PYRXD_ETH_FORK_RPC=https://mainnet.base.org \\
        .venv/bin/pytest tests/test_xchain_erc20_usdc_lifecycle_e2e.py -m integration -s

THE ENDPOINT MUST SERVE HISTORICAL STATE — archive reads, on Base in practice. anvil forks at the tip
and keeps reading state AT THE FORK BLOCK for the whole run, so the block it reads falls further
behind the tip as the run goes on: one run (about 10 minutes) is ~50 blocks on Ethereum (12 s blocks)
and ~300 on Base (2 s blocks). A pruned node fails mid-swap with a Fork Error rather than at startup, so it looks
healthy right up until the deploy receipt. Measured 2026-10-01 with ``eth_getCode`` of the pinned USDC:
``eth.drpc.org``, ``eth-mainnet.public.blastapi.io``, ``mainnet.base.org`` and
``base-mainnet.public.blastapi.io`` served state 1024 blocks back (``base.meowrpc.com`` did too, between
rate-limit refusals); ``ethereum-rpc.publicnode.com`` and ``base-rpc.publicnode.com`` refused reads 128
blocks back ("Archive requests require a personal token"). publicnode's Ethereum endpoint passed an
earlier, ~5 minute form of this suite inside that window; it is not on the nightly list, and on Base it
cannot work at all. The nightly lane probes for exactly this before it runs
(``.github/workflows/integration.yml``).

No RPC key is needed — see `test_erc20_leg_fork_integration.py`'s header for why probing endpoints
from Python's ``urllib`` makes it look like one is (they block its user-agent; ``curl`` and anvil pass).

THE POLICY IS THE RUNNER'S REAL-VALUE ONE. Every scenario takes its ``MarginPolicy``, ``t_rxd`` and
``t_btc`` from ``scripts/eth_swap_run.py``'s own ``_args``/``_policy`` on its real token stage: MEASURED,
a 36 s fast tail, a 3600 s ETH stall budget (``_runner_policy``). The happy path and both crash
scenarios use the runner's 24 h default deadline (t_rxd about 2,680 blocks); the refund scenario uses
a 4 h one (about 680) because it must mine t_rxd on regtest to mature the covenant. Regtest Radiant
skips the value-bearing construction checks, so
``test_runners_build_the_coordinator_first.test_the_erc20_lifecycle_e2e_terms_pass_the_mainnet_construction_checks``
runs them, offline, on exactly these inputs.

NOTE: the regtest fixture `docker rm -f`s a FIXED container name, so this cannot run beside another
regtest suite — serialise them.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

from pyrxd.btc_wallet import taproot as bt
from pyrxd.devnet import RegtestNode
from pyrxd.eth_wallet.erc20_leg import Erc20HtlcLeg
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.eth_wallet.tokens import token_for
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.funding_spv import LOCAL_DEVNET_CHAIN_IDS, MEDIAN_TIME_SPAN
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.record_sink import FileFundLock, JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import NetworkError
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20

# The runner inputs every scenario negotiates under (amounts, the measured 36 s fast tail, the 3600 s
# stall floor, the maker-stall window) and the two deadlines: ONE copy, shared with the offline test
# that runs the MAINNET construction checks on exactly these terms (regtest skips them).
from tests.test_runners_build_the_coordinator_first import (
    ERC20_LIFECYCLE_E2E_DEADLINES_S,
    ERC20_LIFECYCLE_E2E_INPUTS,
)
from tests.test_swap_coordinator import FakeIndexer
from tests.test_xchain_swap_regtest_e2e import (
    _FeeSource,
    _RadiantCliClient,
    _rxd_pay,
    # The ONE canonical counter-leg derivation (scripts/_dust_swap_shared.py), re-exported by the BTC
    # e2e, which puts scripts/ on the path — the same function scripts/eth_swap_run.py calls.
    derive_counter_timelock,
)

pytestmark = pytest.mark.integration

#: Derived, never spelled. `scripts/refresh_radiant_core_vendor.py --check` reads
#: `DEFAULT_RADIANT_VERSION`; a literal here could drift from it and the check would
#: still pass while this lane ran a different node.
_RXD_IMAGE = RegtestNode.IMAGE
#: Which chain to fork. Defaults to Ethereum; set PYRXD_ETH_FORK_CHAIN_ID=8453 with a Base RPC in
#: PYRXD_ETH_FORK_RPC to run the same lifecycle against Base's pinned tokens. That matters because
#: Base USDT is the has_blacklist=False branch of the pre-reveal gate — a different path from L1
#: USDT, and the one a Base mainnet run actually takes.
_FORK_CHAIN_ID = int(os.environ.get("PYRXD_ETH_FORK_CHAIN_ID", "1"))
#: The chain id anvil serves the fork under, and every leg signs for: a local development chain,
#: which the taker gate reads as moving no value (see the module docstring).
_DEVNET_CHAIN_ID = 31337
assert _DEVNET_CHAIN_ID in LOCAL_DEVNET_CHAIN_IDS


def _on_devnet(token):
    """The forked chain's pinned *token*, pinned to :data:`_DEVNET_CHAIN_ID` instead — test-side."""
    return dataclasses.replace(token, chain_id=_DEVNET_CHAIN_ID)


_USDC = _on_devnet(token_for("USDC", _FORK_CHAIN_ID))
#: Both are run against the REAL mainnet contracts on a fork, because the USDT delta is runtime
#: behaviour a fake cannot prove: Tether's `transfer` returns NO bool (it is not ERC-20 compliant),
#: and its freeze predicate is `isBlackListed`, not `isBlacklisted`. Unit tests pin the name; only
#: the real bytecode proves the leg survives the missing return value.
_TOKENS = {"USDC": _USDC, "USDT": _on_devnet(token_for("USDT", _FORK_CHAIN_ID))}

#: Function selectors used only to seed the fork with tokens. See `_seed_token`.
_SEL_L2_BRIDGE = "0xae1f6aaf"  # l2Bridge()
_SEL_MASTER_MINTER = "0x35d99f35"  # masterMinter()
_SEL_CONFIGURE_MINTER = "0x4e44d956"  # configureMinter(address,uint256)
_SEL_MINT = "0x40c10f19"  # mint(address,uint256)
_SEL_TRANSFER = "0xa9059cbb"  # transfer(address,uint256)
#: A large L1 holder to impersonate, for the one token that can be seeded no other way (see
#: `_seed_token`) — avoids deriving the balances storage slot, whose packed layout is exactly the
#: sort of detail a test should not encode.
_WHALE = "0x28C6c06298d514Db089934071355E5743bf21d60"
#: Anvil's deterministic PUBLIC dev keys. Local fork only; no real value.
_KEY_TAKER = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
_ADDR_TAKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
_ADDR_MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
#: 12.345678 USDC. Non-round on purpose: a 6-vs-18 decimal bug cannot hide in a round number.
_AMOUNT = 12_345_678
_RXD_CARRIER = 100_000


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _rpc(url: str, method: str, params=None):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        body = json.loads(r.read())
    # Raise on a JSON-RPC `error` rather than handing it back. `_getter_address` depends on it —
    # it tells "this contract has no such function" from a reverted eth_call — and every anvil_*
    # cheat discards its result, so a mistyped method would otherwise pass for a working one.
    #
    # MEASURED 2026-08-25, and it is precisely the limit of this check: anvil does NOT report a
    # reverted `eth_sendTransaction` as an error. It mines the transaction and returns a hash; the
    # revert appears only in the receipt. A failed seeding send is therefore invisible HERE, which
    # is why `_seed_token` reads the balance back rather than trusting the send.
    if "error" in body:
        raise RuntimeError(f"{method} failed: {body['error']}")
    return body


def _mine(url: str, n: int = 1) -> None:
    for _ in range(n):
        _rpc(url, "evm_mine")


def _now(url: str) -> int:
    return int(_rpc(url, "eth_getBlockByNumber", ["latest", False])["result"]["timestamp"], 16)


def _word(value) -> str:
    """One 32-byte ABI word from an int, or from an address as its low 20 bytes."""
    return hex(int(value, 16) if isinstance(value, str) else int(value))[2:].rjust(64, "0")


def _send_as(url: str, sender: str, to: str, data: str) -> None:
    """Send `data` to `to` as `sender`, impersonating it and funding its gas first."""
    _rpc(url, "anvil_impersonateAccount", [sender])
    _rpc(url, "anvil_setBalance", [sender, hex(10**18)])
    # No return value is inspected: Tether's `transfer` returns nothing at all, so there is nothing
    # to inspect. A revert arrives as a JSON-RPC error instead, and `_rpc` raises on those.
    _rpc(url, "eth_sendTransaction", [{"from": sender, "to": to, "data": data}])


def _getter_address(url: str, contract: str, selector: str) -> str | None:
    """A zero-argument address getter's value, or None if this contract has no such function."""
    try:
        word = _rpc(url, "eth_call", [{"to": contract, "data": selector}, "latest"])["result"]
    except RuntimeError:
        return None
    if len(word) < 66:  # a fallback function answering with empty data is not an address
        return None
    return "0x" + word[-40:] if int(word, 16) else None


def _seed_token(url: str, token, holder: str, amount: int) -> None:
    """Give `holder` at least `amount` of `token` on the fork, and PROVE it landed.

    WHICH mechanism works is a property of the token, not of the chain, so this probes the token
    instead of branching on a chain id. Measured against Base mainnet on 2026-08-25: the bridged
    USDT at 0xfde4C96c… mints for the L2 standard bridge, while native Circle USDC at 0x833589fC…
    answers that same caller `FiatToken: caller is not a minter`. A chain-keyed seeder is therefore
    wrong for one of the two tokens this fixture parametrises over — and wrong silently.

    The closing balance read is the load-bearing line, and nothing else does its job: anvil mines a
    reverting send and returns a hash for it (see `_rpc`), so the wrong seeder reports success and
    moves nothing. Verified by planting exactly that — an L2-bridge mint against native USDC, the
    shape the previous revision of this fixture used — and watching the send pass while the balance
    stayed 0. Seeding runs before any assertion, so without this line the shortfall would resurface
    inside the swap as a transfer that moved less than it should have.
    """
    bridge = _getter_address(url, token.address, _SEL_L2_BRIDGE)
    master_minter = _getter_address(url, token.address, _SEL_MASTER_MINTER)
    if bridge is not None:
        _send_as(url, bridge, token.address, _SEL_MINT + _word(holder) + _word(amount))
    elif master_minter is not None:
        # A FiatToken — every native Circle USDC. The masterMinter cannot mint, only appoint, so it
        # appoints itself; that keeps the whole path to a single impersonated account.
        _send_as(url, master_minter, token.address, _SEL_CONFIGURE_MINTER + _word(master_minter) + _word(amount))
        _send_as(url, master_minter, token.address, _SEL_MINT + _word(holder) + _word(amount))
    else:
        # Tether on L1 is neither: no masterMinter, and `issue` credits only the owner. Impersonating
        # a pinned large holder is what is left.
        _send_as(url, _WHALE, token.address, _SEL_TRANSFER + _word(holder) + _word(amount))
    got = _usdc_balance(url, holder, token)
    assert got >= amount, (
        f"seeding {token.symbol} on chain {token.chain_id} left {got} base units, wanted {amount}: "
        "the swap would fail later for a reason that has nothing to do with the swap"
    )


@pytest.fixture(scope="module", params=sorted(_TOKENS))
def env(request, tmp_path_factory):
    """A Radiant regtest node + an anvil fork of mainnet, with the taker holding real USDC."""
    fork_rpc = os.environ.get("PYRXD_ETH_FORK_RPC", "")
    if not os.environ.get("XCHAIN_ERC20_E2E"):
        pytest.skip("XCHAIN_ERC20_E2E not set (opt-in for the RXD↔USDC lifecycle e2e)")
    if not fork_rpc:
        pytest.skip("PYRXD_ETH_FORK_RPC not set — needs a mainnet endpoint to fork (no key required)")
    for tool in ("docker", "anvil"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not available")
    if subprocess.run(["docker", "image", "inspect", _RXD_IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_RXD_IMAGE} image not available")

    from tests.test_xchain_eth_swap_regtest_e2e import _RxdNode

    node = _RxdNode()
    node.start()
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    # `--slots-in-an-epoch 1` so the `finalized` checkpoint tracks latest-2. Without a consensus
    # layer anvil pins it at 0, the ETH-claim finality verdict is never FINAL, and the reorg gate
    # never returns SAFE — the swap would stall for a reason that has nothing to do with the code.
    anvil = subprocess.Popen(
        [
            "anvil",
            "--fork-url",
            fork_rpc,
            "--port",
            str(port),
            "--chain-id",
            str(_DEVNET_CHAIN_ID),
            "--slots-in-an-epoch",
            "1",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(160):
            try:
                _rpc(url, "eth_chainId")
                break
            except Exception:
                time.sleep(0.25)
        else:  # pragma: no cover
            pytest.fail("anvil fork did not become ready")
        node.clock = lambda: _now(url)  # one clock for both chains; see _RxdNode.rxd_mine
        # The anvil dev addresses carry EIP-7702 delegation designators on a mainnet fork; they are
        # deliberately left in place, because the token leg's ERC-20 sweep calls the token and never
        # the recipient, so it must work WITH them present (#478).
        for who in (_ADDR_TAKER, _ADDR_MAKER):
            _rpc(url, "anvil_setBalance", [who, hex(10**19)])
        token = _TOKENS[request.param]
        # Guard the PARAMETRIZATION itself, at the only place it can collapse. Asserting the
        # token inside a test compares the record against the same variable that produced it —
        # self-consistent whatever the fixture yielded, so it cannot notice both runs quietly
        # exercising one token. Verified by planting exactly that collapse here.
        assert token.symbol == request.param, (
            f"fixture param {request.param!r} yielded {token.symbol!r}: the suite would run one "
            "token twice and read as coverage for two"
        )
        _seed_token(url, token, _ADDR_TAKER, _AMOUNT * 10)
        yield node, url, tmp_path_factory.mktemp("erc20e2e"), token
    finally:
        anvil.terminate()
        try:
            anvil.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            anvil.kill()
        node.stop()


def _swap_dir(root: pathlib.Path, scenario: str) -> pathlib.Path:
    """One record directory PER SWAP, as the runner keeps one ``--keys-out`` per run.

    The scenarios share one module-scoped fixture, and they all wrote ``<tmp>/swap.swaprec.json``.
    ``JsonFileRecordSink`` refuses to overwrite a record that belongs to a different swap (#504 item
    3): it may be the only durable trace of a contract that still holds value. So the second
    scenario was refused at its first persist — correctly. Each swap gets its own path instead.
    """
    d = root / scenario
    d.mkdir()
    return d


class _RecordingEthLeg:
    """Captures the maker's claim tx hash on the way past.

    `maker_claims_btc` discards it — the record has no field for it — so the taker cannot be handed
    the transaction it must scrape `p` from. That is a real gap, filed separately; here the wrapper
    stands in for whatever the operator would otherwise have to recover by hand.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.claim_tx_hash: str | None = None

    async def claim(self, locator, preimage):
        self.claim_tx_hash = await self._inner.claim(locator, preimage)
        return self.claim_tx_hash

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _InMemSeen:
    """Single-process H-freshness. The coordinator refuses a value-bearing swap on a non-durable
    store unless told to accept it, which this run does consciously: one process, one shot, a fresh
    H each time."""

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def has_seen(self, h: bytes) -> bool:
        return bytes(h) in self._seen

    def reserve(self, h: bytes) -> bool:
        if bytes(h) in self._seen:
            return False
        self._seen.add(bytes(h))
        return True

    def mark_seen(self, h: bytes) -> None:
        self._seen.add(bytes(h))


def _runner_policy(token, *, deadline: str = "default", t_rxd_blocks: int = 0, remaining_s: int | None = None):
    """``(args, policy)`` from ``scripts/eth_swap_run.py`` ITSELF, on its real-value token stage.

    The runner's own argument parser and its own ``_policy``: a real token counter leg on a
    value-bearing chain (``--counter-asset usdc|usdt --eth-chain-id 1|8453``) builds a MEASURED,
    ``require_measured`` policy, refuses without the measured fast tail and a stall budget of at
    least 3600 s, and DERIVES ``t_rxd`` from its 24 h default deadline at that fast tail plus the taker
    gate's modelled reserve. That is the policy and the ``t_rxd`` a real RXD<->USDC swap gets on
    current main — about 2,680 blocks, where dividing by the nominal 300 s gives about an eighth of
    it. Everything production-shaped is the runner's; the inputs are ``ERC20_LIFECYCLE_E2E_INPUTS``
    (a measured fast tail, the runner-mandated stall floor, this suite's amounts) and a deadline
    from ``ERC20_LIFECYCLE_E2E_DEADLINES_S``.

    ``t_rxd_blocks`` and ``remaining_s`` are the runner's RESUME path: a resume reuses the recorded
    ``t_rxd`` and judges the bounds against what is left of the deadline (``run_sepolia_dust``).
    """
    from tests.test_value_bearing_runners_pass_the_fast_tail import _load

    mod = _load("eth_swap_run")
    argv = [
        "eth_swap_run.py",
        "--stage",
        "dry-run",
        "--counter-asset",
        token.symbol.lower(),
        "--eth-chain-id",
        str(_FORK_CHAIN_ID),
        *ERC20_LIFECYCLE_E2E_INPUTS,
        "--eth-timeout-s",
        str(ERC20_LIFECYCLE_E2E_DEADLINES_S[deadline]),
        "--t-rxd-blocks",
        str(t_rxd_blocks),
        "--keys-out",
        "unused-by-the-parser.json",
    ]
    saved = sys.argv
    try:
        sys.argv = argv  # `_args()` parses sys.argv; restored before anything else runs
        args = mod._args()
    finally:
        sys.argv = saved
    assert mod._token_leg_is_real(args), "this must be the runner's REAL-VALUE token stage"
    policy = mod._policy(args, remaining_s=remaining_s)
    assert policy.is_measured and policy.require_measured, "the real-value stage builds a MEASURED policy"
    # The shared inputs must be what this suite's assertions assume, or the offline construction test
    # vouches for terms this suite does not run.
    assert (args.token_amount, args.rxd_photons) == (_AMOUNT, _RXD_CARRIER)
    return args, policy


def _derive_terms_timelocks(url, token, deadline: str) -> tuple[bt.Timelock, bt.Timelock, int]:
    """``(t_btc, t_rxd, eth_timeout_unix_s)`` for a fresh swap, the way ``run_sepolia_dust`` gets them.

    The deadline is the runner's ``resolve_eth_timeout`` over its own default duration, on anvil's
    clock (the clock both chains here share). ``t_rxd`` is the one ``_policy`` derived, and ``t_btc``
    is ``derive_counter_timelock`` over the runner's inputs with the gate reserve it computed, as
    ``_build_terms_and_covenant`` does.

    The pre-#482 fixture typed ``t_rxd`` (8 or 60 blocks) and ``t_btc = t_rxd + 40``: the ordering
    ``NegotiatedTerms`` refuses, and a Radiant refund opening hours before its deadline.
    """
    from tests.test_value_bearing_runners_pass_the_fast_tail import _load

    args, _policy = _runner_policy(token, deadline=deadline)
    eth_timeout = _load("eth_swap_run").resolve_eth_timeout(
        None, now_unix_s=_now(url), eth_timeout_s=args.eth_timeout_s
    )
    t_rxd = bt.Timelock(int(args.t_rxd_blocks), bt.TimeUnit.BLOCKS)
    t_btc = bt.Timelock(
        derive_counter_timelock(
            t_rxd_blocks=t_rxd.value,
            margin_blocks=args.margin_blocks,
            rxd_block_interval_s=args.rxd_block_interval_s,
            btc_block_interval_s=args.btc_block_interval_s,
            elapsed_reserve_blocks=int(args.gate_reserve_blocks),
        ),
        bt.TimeUnit.BLOCKS,
    )
    return t_btc, t_rxd, eth_timeout


def _build(node, url, workdir, token=None, *, deadline="default", seen=None, reuse=None):
    """Covenant + BOTH real legs + the production coordinator, wired for RXD↔USDC.

    The policy and timelocks are the runner's real-value ones (``_runner_policy``), never typed.

    ``reuse`` carries a previous build's key material, timelocks and deadline so a RESTARTED process
    rebuilds byte-identical terms. Generating fresh keys — or re-deriving ``t_rxd`` at a later
    ``now`` — would produce a different covenant script, and the resume would then verify against a
    covenant nobody funded: a test artefact that looks exactly like the failure it is meant to
    detect. The runner does the same on ``--resume``: ``t_rxd`` and the deadline come from the
    recovery file, never from the clock, and the policy is rebuilt against what is left.
    """
    token = token or _USDC
    if reuse is None:
        # A chain that has been producing blocks up to now. The refund scenario warps anvil's clock
        # hours ahead; without fresh blocks the node's last 11 headers — the window the taker gate
        # takes its median time past over — would read as a chain stalled for that long, and the
        # gate counts that as elapsed time, as it must. A live chain does not stall between swaps.
        node.rxd_mine(MEDIAN_TIME_SPAN)
        p_secret = SecretBytes(os.urandom(32))
        taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
        t_btc, t_rxd, eth_timeout = _derive_terms_timelocks(url, token, deadline)
        args, policy = _runner_policy(token, deadline=deadline)
        assert int(args.t_rxd_blocks) == t_rxd.value
    else:
        p_secret, taker_rxd, maker_rxd, t_btc, t_rxd, eth_timeout = reuse
        args, policy = _runner_policy(token, t_rxd_blocks=t_rxd.value, remaining_s=eth_timeout - _now(url))
    h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    cov = build_htlc_covenant_rxd(
        amount=_RXD_CARRIER, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=t_rxd.value
    )

    terms = NegotiatedTerms(
        hashlock=h,
        # Vestigial on an ETH swap — `value_amount` carries the real counter-leg amount — but the
        # record still requires it positive. Matches the native ETH e2e rather than inventing a
        # different convention.
        btc_sats=100_000,
        radiant_amount=_RXD_CARRIER,
        t_btc=t_btc,
        t_rxd=t_rxd,
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        eth_timeout_unix_s=eth_timeout,
        # THE token fields. `value_amount` is 6-decimal USDC base units, NOT wei — the whole reason
        # the record is chain-tagged, and the distinction a mock token cannot exercise.
        value_amount=_AMOUNT,
        token_address=token.address,
    )

    rpc = EthRpc(url, expected_chain_id=_DEVNET_CHAIN_ID)
    artifact = json.loads((pathlib.Path(__file__).parent / "fixtures" / "Erc20Htlc.json").read_text())
    contract_leg = Erc20HtlcLeg(
        token=token,
        rpc=rpc,
        signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY_TAKER)),
        chain_id=_DEVNET_CHAIN_ID,
        artifact=artifact,
    )
    eth_leg = _RecordingEthLeg(
        EthLeg(
            contract_leg=contract_leg,
            network="mainnet",
            claim_to=_ADDR_MAKER,  # the maker claims the USDC
            refund_to=_ADDR_TAKER,  # the taker gets it back on refund
            eth_timeout_unix_s=eth_timeout,
            audit_cleared=True,  # a forked devnet; no real value moves
        )
    )
    rxd_leg = RadiantCovenantLeg(
        network="bcrt",
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        chain_io=RadiantChainIO(_RadiantCliClient(node)),
        fee_source=_FeeSource(node),
        min_confirmations=1,
    )
    keys = str(workdir / "swap")
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth_leg,
        radiant_leg=rxd_leg,
        indexer=FakeIndexer(),
        seen_store=seen if seen is not None else _InMemSeen(),
        persist=JsonFileRecordSink(keys + ".swaprec.json"),
        # The runner's real-token wiring: its maker-stall window, and NO accept_estimated_eth_margins
        # (the runner passes it only for a throwaway token; with a measured policy it would re-disable
        # the two defences the policy switches on).
        config=CoordinatorConfig(
            maker_stall_safety_window_blocks=args.maker_stall_safety_window_blocks,
            margin_policy=policy,
            accept_nondurable_seen=True,  # single-process, fresh-H-per-run
            fund_lock=FileFundLock(keys),
        ),
    )
    coord._token_leg = contract_leg  # the inner Erc20HtlcLeg, for tests that need to break it
    return coord, cov, p_secret, eth_leg, rxd_leg, taker_rxd, maker_rxd


def _usdc_balance(url: str, who: str, token=None) -> int:
    call = {"to": (token or _USDC).address, "data": "0x70a08231" + who[2:].rjust(64, "0")}
    return int(_rpc(url, "eth_call", [call, "latest"])["result"], 16)


async def test_rxd_usdc_swap_runs_end_to_end(env):
    """THE test. NEGOTIATED → COMPLETED with a real USDC HTLC and a real Radiant covenant.

    Every component here has been proven separately and never together. What only this can catch is
    a defect that lives in the seam: the two-transaction fund against a real mempool, the 6-decimal
    amount surviving the record round trip, the chain-tagged locator reaching the claim path, the
    covenant and the token HTLC agreeing about the same preimage.
    """
    node, url, root, token = env
    workdir = _swap_dir(root, "happy")
    coord, cov, p_secret, eth_leg, _rxd_leg, _tk, _mk = _build(node, url, workdir, token)

    maker_before = _usdc_balance(url, _ADDR_MAKER, token)

    # 1. MAKER locks the Radiant asset first, and it is mined. The taker will not fund until it has
    #    read this off the chain — HZ-1, enforced by pre_btc_lock_check step 5.
    _rxd_pay(node, cov.funded_spk, _RXD_CARRIER)  # mines the block that confirms the covenant
    asset_locked_at = _rxd_height(node)
    _bury_the_covenant(node, coord)

    # 2. TAKER funds the USDC counter leg. Two transactions: deploy, then a plain transfer.
    rec = await coord.taker_funds_btc(coord.record.terms, now_unix_s=_now(url))
    assert rec.state is SwapState.BTC_LOCKED
    loc = rec.counterchain_locator
    assert loc is not None
    # Read the tag off the PERSISTED record, not off the locator object. `loc.CHAIN_TAG` is a class
    # attribute, so asserting it only proves the class was imported — a first version of this line
    # did exactly that, and forcing `to_dict` to write "eth" for a token swap left the test GREEN.
    # What matters is the bytes that reach disk, because those are what a later reader decodes.
    on_disk = json.loads((workdir / "swap.swaprec.json").read_text())
    tag = on_disk["counterchain_locator"]["chain"]
    assert tag == "eth-erc20", f"persisted tag is {tag!r} — a reader would take 6-decimal units for wei"
    assert on_disk["counterchain_locator"]["locator"]["amount_wei"] == _AMOUNT
    # The parametrization must actually reach the chain. If the fixture param failed to propagate,
    # BOTH runs would exercise USDC and both would pass — a parametrized suite that silently tests
    # one thing twice is worse than an unparametrized one, because it reads as coverage.
    assert on_disk["counterchain_locator"]["locator"]["token_address"].lower() == token.address.lower(), (
        f"the record names {on_disk['counterchain_locator']['locator']['token_address']}, but this "
        f"run is parametrized for {token.symbol} at {token.address}"
    )
    # USDT's transfer returns NO bool. Reaching this line at all is the proof the leg does not read
    # one — a compliance-assuming implementation reverts here against the real Tether bytecode.
    assert _usdc_balance(url, loc.contract_address, token) == _AMOUNT
    assert loc.amount_wei == _AMOUNT, "the 6-decimal amount did not survive into the locator"
    assert _usdc_balance(url, loc.contract_address, token) == _AMOUNT, "the HTLC does not hold the USDC"

    # 3. MAKER revalidates and the swap is BOTH_LOCKED — once the deploy is FINAL. A measured policy
    #    pins the verify->lock read to the `finalized` checkpoint (a reorg could otherwise re-deploy a
    #    different contract at the same CREATE address), so a real maker waits for finality first.
    _finalize_the_counter_leg(url)
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_now(url))
    assert rec.state is SwapState.BOTH_LOCKED
    # Positive control for the check at the end: the same helper, same outpoint, must report
    # UNSPENT here. Without this, "spent" at the end could be a helper that always says spent —
    # asking the wrong vout, or swallowing an RPC error — and the test would pass either way.
    assert not _covenant_is_spent(node, rec.radiant_covenant_outpoint), (
        "the covenant reads as spent while it is still locked — the check cannot distinguish"
    )

    # 4. MAKER claims the USDC, revealing p on Ethereum.
    rec = await coord.maker_claims_btc(p_secret)
    assert rec.state is SwapState.SECRET_REVEALED
    assert _usdc_balance(url, _ADDR_MAKER, token) - maker_before == _AMOUNT, "the maker was not paid the USDC"
    _mine(url, 4)  # let the claim finalize so the reorg gate can return SAFE

    # 5. TAKER scrapes p from the maker's real claim and takes the Radiant asset.
    claim_tx = eth_leg.claim_tx_hash
    assert claim_tx, "the maker's claim tx hash was not captured — the taker cannot scrape p"
    node.rxd_mine(2)
    rec = await coord.taker_scrape_and_claim_asset(
        claim_tx, now_rxd_height=_rxd_height(node), asset_locked_at_height=asset_locked_at
    )
    assert rec.state is SwapState.COMPLETED, f"the swap did not complete: {rec.state}"

    # COMPLETED is a flag this process set about itself. What settles the swap is the covenant
    # being SPENT, and the refund test checked that while this one — the path that actually moves
    # the asset — did not. A claim that failed to broadcast, or paid the wrong key, would have left
    # every assertion above green.
    node.rxd_mine(1)
    assert _covenant_is_spent(node, rec.radiant_covenant_outpoint), (
        "the swap reports COMPLETED but the Radiant covenant is still unspent — the taker was "
        "never paid, while the maker already has the USDC and p is public"
    )


def _finalize_the_counter_leg(url: str) -> None:
    """Mine until the counter-leg deploy and transfer are under anvil's `finalized` checkpoint.

    The fixture runs anvil with ``--slots-in-an-epoch 1``, so `finalized` is latest-2: three blocks
    put both funding transactions behind it. On a real chain this is the ~13 min the maker waits.
    """
    _mine(url, 3)


def _bury_the_covenant(node, coord) -> None:
    """Mine the maker's covenant (already 1 deep from ``_rxd_pay``) to the burial the policy requires.

    A MEASURED policy refuses to fund the counter leg until the covenant is ``rxd_claim_burial`` deep
    (``pre_btc_lock_check`` step 5: "Wait for it to bury, then retry"), and a real taker waits exactly
    so. The pre-#482 fixture mined a fixed 3 under an estimated policy, which does not enforce it.
    """
    node.rxd_mine(coord.config.margin_policy.rxd_claim_burial.value - 1)


def _covenant_is_spent(node, outpoint: str) -> bool:
    """Is the funded covenant outpoint gone from the UTXO set?

    Splits the vout off the outpoint instead of assuming 0. Hardcoding vout "0" made the answer
    depend on where the funding transaction happened to place the covenant: if it ever landed at
    vout 1, `gettxout(txid, 0)` would be asking about the CHANGE output, and its absence would read
    as "the covenant was spent" — the assertion passing for a reason unrelated to the swap.
    """
    txid, _, vout = outpoint.partition(":")
    return node.rxd("gettxout", txid, vout or "0") in (None, "")


def _rxd_height(node) -> int:
    return int(node.rxd("getblockcount"))


async def test_mutual_refund_returns_the_usdc_and_the_rxd(env):
    """The guaranteed-safe failure, on real chains: neither side suffers a one-sided loss.

    Both legs are funded and NOBODY claims — the maker never reveals `p`. Each leg must come back to
    the party that funded it: the USDC to the taker (the HTLC's immutable refundee), the Radiant
    covenant to the maker via its CSV branch.

    This is the path the happy-path run does not touch at all, and it is the one an operator
    actually needs when a counterparty goes quiet. It also exercises `mutual_refund`'s repair from
    this session: the two refunds are independent, so a failure in one must not skip the other.
    """
    node, url, root, token = env
    workdir = _swap_dir(root, "refund")
    # The 4 h deadline, not the 24 h default: this scenario MINES t_rxd to mature the covenant, about
    # 680 blocks here against about 2,680 (see ERC20_LIFECYCLE_E2E_DEADLINES_S for the measured cost).
    # Same runner policy, fast tail and stall budget.
    coord, cov, _p_secret, _eth_leg, _rxd_leg, _tk, _mk = _build(node, url, workdir, token, deadline="refund")
    terms = coord.record.terms
    policy = coord.config.margin_policy

    taker_before = _usdc_balance(url, _ADDR_TAKER, token)
    maker_before = _usdc_balance(url, _ADDR_MAKER, token)

    # Both legs funded, exactly as the happy path — a stalling maker still has to LOCK; "never locks
    # at all" is refused before any taker value moves.
    _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
    _bury_the_covenant(node, coord)
    rec = await coord.taker_funds_btc(terms, now_unix_s=_now(url))
    assert rec.state is SwapState.BTC_LOCKED
    htlc = rec.counterchain_locator.contract_address
    assert _usdc_balance(url, htlc, token) == _AMOUNT
    _finalize_the_counter_leg(url)  # the measured policy's `finalized` pin, as in the happy path
    rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_now(url))
    assert rec.state is SwapState.BOTH_LOCKED

    # Nobody claims. In the order the #482 ordering produces, on ONE wall clock:
    # 1. The ETH deadline passes, and Radiant mines the blocks that same span holds at the policy's
    #    nominal interval (rounded UP, so the assertion below is only made harder to pass). The
    #    taker's USDC refund is open; the maker's covenant refund is still CLOSED, and the production
    #    leg's own maturity check refuses it before it takes a fee input or broadcasts anything.
    elapsed_s = terms.eth_timeout_unix_s + 1 - _now(url)
    _rpc(url, "evm_setNextBlockTimestamp", [terms.eth_timeout_unix_s + 1])
    _mine(url, 1)
    node.rxd_mine(math.ceil(elapsed_s / policy.rxd_block_interval_s))
    cov_txid = coord.record.radiant_covenant_outpoint.split(":")[0]
    cov_confs = int(node.rxd("getrawtransaction", cov_txid, "true")["confirmations"])
    assert cov_confs < terms.t_rxd.value, "the covenant refund must open LAST"
    with pytest.raises(NetworkError, match="not yet mature"):
        await coord.radiant_leg.refund_asset(coord.record)

    # 2. t_rxd matures last; now mutual_refund unwinds BOTH legs.
    node.rxd_mine(terms.t_rxd.value - cov_confs)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND, f"mutual refund did not complete: {rec.state}"

    # The USDC is back with the TAKER, who funded it — and the maker gained nothing.
    assert _usdc_balance(url, htlc, token) == 0, "the HTLC still holds USDC after the refund"
    # NET ZERO, not +_AMOUNT: `taker_before` is the balance BEFORE funding, so the taker paid the
    # USDC out and got it back. Being made WHOLE is the property — an earlier version of this line
    # expected a gain, which no refund path should ever produce.
    assert _usdc_balance(url, _ADDR_TAKER, token) == taker_before, "the taker was not made whole by the refund"
    assert _usdc_balance(url, _ADDR_MAKER, token) == maker_before, "the maker gained USDC on a refund path"

    # And the Radiant covenant is spent — refunded to the maker via the CSV branch.
    assert _covenant_is_spent(node, coord.record.radiant_covenant_outpoint), "the Radiant covenant was not refunded"


async def test_a_crash_between_deploy_and_transfer_RESUMES_without_double_funding(env):
    """G3, on real chains: the crash the whole durable-handle and resume machinery exists for.

    The ERC-20 fund is TWO transactions. Between them there is a contract on chain whose address
    depends on the deployer's nonce and appears nowhere until the deploy receipt returns. Die there
    and, before this machinery, the only reference to it was an exception string.

    Everything under test here was built in one session and has never executed against a real
    chain: the durable deploy handle, the nonce pin, the fund lock, the seen-store divergence check,
    and the resume entry point. The property that matters is stated as arithmetic — ONE contract,
    holding EXACTLY the negotiated amount, never two and never double.
    """
    node, url, root, token = env
    workdir = _swap_dir(root, "crash_before_push")
    seen = _InMemSeen()
    coord, cov, p_secret, _eth_leg, _rxd, taker_rxd, maker_rxd = _build(node, url, workdir, token, seen=seen)
    terms = coord.record.terms
    reuse = (p_secret, taker_rxd, maker_rxd, terms.t_btc, terms.t_rxd, terms.eth_timeout_unix_s)

    _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
    _bury_the_covenant(node, coord)
    taker_before = _usdc_balance(url, _ADDR_TAKER, token)

    # CRASH: let the deploy land and be persisted, then die before the token push completes.
    real_send = coord._token_leg._sign_and_send
    calls = {"n": 0}

    async def _die_on_the_push(tx, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return await real_send(tx, **kw)  # the deploy really happens
        raise RuntimeError("process died between deploy and transfer")

    coord._token_leg._sign_and_send = _die_on_the_push
    with pytest.raises(Exception):
        await coord.taker_funds_btc(terms, now_unix_s=_now(url))

    # The crash left a DURABLE handle: an address, its deploy tx, and the pinned push nonce.
    assert calls["n"] == 2, (
        f"_sign_and_send ran {calls['n']}x — the crash did not land BETWEEN the deploy and the "
        "push, so this test is not exercising the window it was written for"
    )
    on_disk = json.loads((workdir / "swap.swaprec.json").read_text())
    # .get, not []: a field written as absent and a field written as null are different failures,
    # and the plant that removes it should read as THIS message, not as a KeyError from the test.
    htlc = on_disk.get("pending_counter_contract")
    assert htlc, "the crash left no reference to the deployed contract — it is unrecoverable"
    assert on_disk["pending_counter_deploy_tx"].startswith("0x")
    assert on_disk["pending_push_nonce"] is not None, "no nonce pin: a retry would be ADDITIVE"
    code = _rpc(url, "eth_getCode", [htlc, "latest"])["result"]
    assert code not in ("0x", ""), "no contract at the recorded address"
    assert _usdc_balance(url, htlc, token) == 0, "the push should NOT have landed"

    # RESUME in a fresh coordinator, as a restarted process would — loading the record from disk.
    sink = JsonFileRecordSink(str(workdir / "swap") + ".swaprec.json")
    coord2, cov2, _p2, _leg2, _rxd2, _tk2, _mk2 = _build(node, url, workdir, token, seen=seen, reuse=reuse)
    assert cov2.funded_spk == cov.funded_spk, "the rebuilt covenant is not the funded one"
    rec = await coord2.resume_interrupted_fund(terms, sink=sink, now_unix_s=_now(url))

    assert rec.state is SwapState.BTC_LOCKED, f"the resumed fund did not complete: {rec.state}"
    assert rec.counterchain_locator.contract_address.lower() == htlc.lower(), (
        "the resume DEPLOYED A SECOND CONTRACT instead of completing the recorded one"
    )
    # THE arithmetic: exactly the negotiated amount, in exactly one contract.
    assert _usdc_balance(url, htlc, token) == _AMOUNT, (
        f"the HTLC holds {_usdc_balance(url, htlc, token)}, not {_AMOUNT} — a resume that re-sent the full "
        "amount would leave double, and claim sweeps the whole balance to the counterparty"
    )
    # The other half of the same arithmetic, from the payer's side. The contract balance alone
    # cannot distinguish "funded once" from "funded twice into two contracts" — this can.
    spent = taker_before - _usdc_balance(url, _ADDR_TAKER, token)
    assert spent == _AMOUNT, f"the taker paid {spent}, not {_AMOUNT}: the crash cost them a second HTLC"


async def test_a_crash_AFTER_the_push_broadcast_replaces_rather_than_adds(env):
    """The window the NONCE PIN exists for — and which the crash test above does NOT reach.

    Planting `push_nonce=None` (dropping the pin entirely) leaves the deploy/transfer crash test
    passing, because that crash lands before the broadcast: there is no pending transaction for a
    pin to replace, so the pin is inert and its absence invisible. The dangerous window is the
    other one — the push IS in the mempool, unconfirmed, and the process dies. A resume that picks
    a fresh nonce there does not retry the payment, it makes a SECOND one, and both mine.

    Reproduced by turning anvil's automine off for the push, so the transfer sits pending exactly
    as it would behind a congested basefee.
    """
    node, url, root, token = env
    workdir = _swap_dir(root, "crash_after_push")
    seen = _InMemSeen()
    coord, cov, p_secret, _eth, _rxd, taker_rxd, maker_rxd = _build(node, url, workdir, token, seen=seen)
    terms = coord.record.terms
    reuse = (p_secret, taker_rxd, maker_rxd, terms.t_btc, terms.t_rxd, terms.eth_timeout_unix_s)

    _rxd_pay(node, cov.funded_spk, terms.radiant_amount)
    _bury_the_covenant(node, coord)
    taker_before = _usdc_balance(url, _ADDR_TAKER, token)

    leg = coord._token_leg
    real_send, real_wait = leg._sign_and_send, leg._rpc.wait_receipt
    calls = {"n": 0}

    async def _send(tx, **kw):
        calls["n"] += 1
        if calls["n"] == 2:  # the push: stop mining so it stays pending, then broadcast for real
            _rpc(url, "evm_setAutomine", [False])
        return await real_send(tx, **kw)

    async def _wait(h):
        if calls["n"] >= 2:
            raise RuntimeError("process died waiting for the push receipt")
        return await real_wait(h)

    leg._sign_and_send, leg._rpc.wait_receipt = _send, _wait
    with pytest.raises(Exception):
        await coord.taker_funds_btc(terms, now_unix_s=_now(url))

    pending = _rpc(url, "eth_getBlockByNumber", ["pending", False])["result"]["transactions"]
    assert pending, "the push never reached the mempool — this is the earlier crash, not this one"
    on_disk = json.loads((workdir / "swap.swaprec.json").read_text())
    pinned = on_disk.get("pending_push_nonce")
    assert pinned is not None, "no durable nonce pin: the resume cannot replace its own pending push"

    coord2, _c2, _p2, _l2, _r2, _t2, _m2 = _build(node, url, workdir, token, seen=seen, reuse=reuse)
    sink = JsonFileRecordSink(str(workdir / "swap") + ".swaprec.json")

    # WHILE THE PUSH IS PENDING the resume REFUSES, and does not reach the pinned re-send at all.
    # This is the behaviour that actually holds, not the replacement the pin's comment describes:
    # the in-flight check (erc20_leg.py) fires first and cannot tell our own pending push from an
    # unrelated transaction. Fail-closed and correct — a resume that guessed here could double-fund
    # — but it means the pin's "replaces rather than adds" property is NOT what protects this case.
    with pytest.raises(NetworkError, match="still in flight"):
        await coord2.resume_interrupted_fund(terms, sink=sink, now_unix_s=_now(url))

    # Let the pending push mine, as the refusal instructs ("Wait for them to mine").
    _rpc(url, "evm_setAutomine", [True])
    _rpc(url, "evm_mine", [])

    # Now the resume completes — and finds nothing left to do, because the push it was going to
    # retry is the one that just landed. THE property, end to end: crash mid-broadcast, resume,
    # and the value is delivered EXACTLY once.
    rec = await coord3_resume(node, url, workdir, token, seen, reuse, terms, sink)
    htlc = on_disk["pending_counter_contract"]
    assert rec.counterchain_locator.contract_address.lower() == htlc.lower()
    assert _usdc_balance(url, htlc, token) == _AMOUNT, f"HTLC holds {_usdc_balance(url, htlc, token)}, not {_AMOUNT}"
    spent = taker_before - _usdc_balance(url, _ADDR_TAKER, token)
    assert spent == _AMOUNT, f"the taker paid {spent}, not {_AMOUNT}: the crashed push and the resume BOTH delivered"


async def coord3_resume(node, url, workdir, token, seen, reuse, terms, sink):
    """A third process, resuming after the pending push settled."""
    coord3, _c, _p, _l, _r, _t, _m = _build(node, url, workdir, token, seen=seen, reuse=reuse)
    return await coord3.resume_interrupted_fund(terms, sink=sink, now_unix_s=_now(url))
