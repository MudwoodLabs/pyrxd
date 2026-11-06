"""The playground's lessons. Plain data; the page renders every string as text, never HTML.

Each lesson's ``code`` runs as written in ``tests/web/test_playground_lessons.py``, under
CPython and again with coincurve and OpenSSL's ``pbkdf2_hmac`` removed (the Pyodide
shape). A lesson whose code stops working fails the build, not a visitor.

``try_it`` is the edit that breaks the lesson on purpose, so a visitor sees a real error.
The test applies it too and checks the error is the one the text promises.
"""

from __future__ import annotations

_IMPORTS_TX = """from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from playground import sandbox
"""

LESSONS: list[dict] = [
    {
        "id": "wallet",
        "title": "Make a wallet",
        "meta": "Offline · 2 min",
        "file": "wallet.py",
        "heading": "Make a wallet",
        "intro": (
            "Every Radiant address comes from a private key, and wallets derive their keys from a "
            "12-word recovery phrase. Radiant's coin type is 512, so the first address lives at "
            "m/44'/512'/0'/0/0, the path Photonic and other wallets use."
        ),
        "steps": [
            "Press Run to make a phrase and derive its first address.",
            "Run it again: a new phrase gives a new address.",
            "Nothing here touches a network. Never paste a real recovery phrase into a web page, this one included.",
        ],
        "code": """from pyrxd.hd import mnemonic_from_entropy, bip44_derive_xprv_from_mnemonic

phrase = mnemonic_from_entropy()
print("recovery phrase:", phrase)

xprv = bip44_derive_xprv_from_mnemonic(phrase, path="m/44'/512'/0'/0/0")
print("first address:  ", xprv.address())
""",
        "try_it": {
            "text": "Change the path to m/44'/512'/0'/0/1 to get the second address from the same phrase.",
            "find": "0'/0/0",
            "replace": "0'/0/1",
            "expect": None,
        },
    },
    {
        "id": "send",
        "title": "Send RXD",
        "meta": "Sandbox · 5 min",
        "file": "send.py",
        "heading": "Send RXD, and pay the fee",
        "intro": (
            "A transaction spends earlier outputs (inputs) and creates new ones (outputs). Whatever "
            "the outputs leave unclaimed is the fee. Radiant relays a transaction only if the fee is "
            "at least 0.1 RXD per kB, which is 10,000 photons per byte (1 RXD = 100,000,000 photons)."
        ),
        "steps": [
            "The faucet pays your sandbox wallet 10 RXD in a new block.",
            "The code spends that coin: 2.5 RXD to a friend, the rest back to you as change, minus FEE.",
            "Press Run, then open the Transaction tab to see both outputs and the checks it passed.",
        ],
        "code": _IMPORTS_TX
        + """
me = sandbox.wallet
coin = sandbox.faucet(rxd=10)          # 1,000,000,000 photons

PAY = 250_000_000                      # 2.5 RXD
FEE = 3_000_000                        # about 226 bytes x 10,000 photons, with room

tx = Transaction(
    tx_inputs=[TransactionInput(
        source_transaction=coin.tx,
        source_output_index=coin.vout,
        unlocking_script_template=P2PKH().unlock(me.key),
    )],
    tx_outputs=[
        TransactionOutput(P2PKH().lock(sandbox.friend.address), PAY),
        TransactionOutput(P2PKH().lock(me.address), coin.value - PAY - FEE),
    ],
)
tx.sign()
print("txid:", sandbox.broadcast(tx))
print("friend now has", sandbox.balance(sandbox.friend) / 1e8, "RXD")
""",
        "try_it": {
            "text": "Set FEE = 1_000 and run it. The sandbox refuses it and says what the floor is.",
            "find": "FEE = 3_000_000",
            "replace": "FEE = 1_000",
            "expect": "fee",
        },
    },
    {
        "id": "nft",
        "title": "Mint your first Glyph",
        "meta": "Sandbox · 5 min",
        "file": "mint_nft.py",
        "heading": "Mint your first Glyph NFT",
        "intro": (
            "A Glyph is a token that lives in an ordinary Radiant output. Minting takes two "
            "transactions. The commit locks a hash of your token's data. The reveal spends the "
            "commit, publishes the data, and creates the output that holds the token."
        ),
        "steps": [
            "Change the name on the metadata line if you like.",
            "Press Run. GlyphMinter builds, signs and sends both transactions, the same code path as on mainnet.",
            "Open the Transaction tab. The orange output holds your token.",
        ],
        "code": """from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from playground import sandbox

sandbox.faucet(rxd=10)
minter = sandbox.minter()   # GlyphMinter(sandbox.client, sandbox.wallet, sandbox.store)

metadata = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="my-first-glyph",
    description="Minted in the Radiant Playground",
)

pending = await minter.commit_nft(metadata)
print("commit:", pending.commit_txid)
result = await minter.reveal_nft(pending)
print("reveal:", result.reveal_txid)
print("genesis ref:", f"{result.ref.txid}:{result.ref.vout}")
""",
        "try_it": {
            "text": "Change GlyphProtocol.NFT to GlyphProtocol.FT. pyrxd refuses before the commit is sent: commit_nft needs the NFT protocol.",
            "find": "protocol=[GlyphProtocol.NFT]",
            "replace": "protocol=[GlyphProtocol.FT]",
            "expect": "ValidationError",
        },
    },
    {
        "id": "send-nft",
        "title": "Send the NFT",
        "meta": "Sandbox · 4 min",
        "file": "send_nft.py",
        "heading": "Send the NFT to a friend",
        "intro": (
            "Moving an NFT means spending the output that holds its ref and creating a new output "
            "that pushes the same ref with OP_PUSHINPUTREFSINGLETON. Radiant's rules let a ref move "
            "only from an input that held it, and a singleton into one output only."
        ),
        "steps": [
            "The code mints an NFT, then asks build_nft_transfer for a transfer to your friend.",
            "The fee comes from a separate plain-RXD input; the NFT's own output carries only dust.",
            "Press Run, then compare the input and output scripts in the Transaction tab.",
        ],
        "code": """from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import MIN_FEE_RATE
from pyrxd.glyph.transfer import build_nft_transfer
from playground import sandbox

sandbox.faucet(rxd=10)
minted = await sandbox.minter().mint_nft(
    GlyphMetadata(protocol=[GlyphProtocol.NFT], name="gift")
)

build = await build_nft_transfer(
    sandbox.wallet, minted.ref, sandbox.friend.pkh,
    client=sandbox.client, fee_rate=MIN_FEE_RATE,
)
print("transfer:", sandbox.broadcast(build.tx))
""",
        "try_it": {
            "text": "Set fee_rate=1_000. The mint still goes through; pyrxd then refuses the transfer before signing it, because that is below the 10,000 photons per byte floor.",
            "find": "fee_rate=MIN_FEE_RATE",
            "replace": "fee_rate=1_000",
            "expect": "ValidationError",
        },
    },
    {
        "id": "ft",
        "title": "Make a fungible token",
        "meta": "Sandbox · 6 min",
        "file": "token.py",
        "heading": "Deploy and send a fungible token",
        "intro": (
            "A Glyph FT is counted in photons: 1 token unit is 1 photon of the output's value. Its "
            "script ends in a covenant that stops a transaction creating units out of nothing. The "
            "Transaction tab marks the covenant's opcodes in blue."
        ),
        "steps": [
            "Deploy 10,000 PLAY, all to your wallet.",
            "Send 2,500 to your friend; the rest comes back as token change.",
            "Check both balances in the Chain & wallet tab.",
        ],
        "code": """from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import MIN_FEE_RATE
from pyrxd.glyph.transfer import build_ft_transfer
from playground import sandbox

sandbox.faucet(rxd=10)
token = await sandbox.minter().deploy_ft(
    GlyphMetadata(protocol=[GlyphProtocol.FT], name="Playground token", ticker="PLAY"),
    supply=10_000,
)
print("token ref:", f"{token.ref.txid}:{token.ref.vout}")

sandbox.faucet(rxd=1)   # a plain coin to pay the transfer's fee
build = await build_ft_transfer(
    sandbox.wallet, token.ref, 2_500, sandbox.friend.pkh,
    client=sandbox.client, fee_rate=MIN_FEE_RATE,
)
print("sent 2,500 PLAY:", sandbox.broadcast(build.tx))
""",
        "try_it": {
            "text": "Ask to send 20_000 units, more than exist. The deploy still goes through; pyrxd then refuses the transfer before signing it.",
            "find": "token.ref, 2_500,",
            "replace": "token.ref, 20_000,",
            "expect": "InsufficientFundsError",
        },
    },
    {
        "id": "rules",
        "title": "Break the ref rules",
        "meta": "Sandbox · 6 min",
        "file": "copy_nft.py",
        "heading": "Try to copy an NFT",
        "intro": (
            "pyrxd's builders refuse bad transactions before signing them, so here you build one by "
            "hand. The code moves an NFT into one new output, which is allowed. The edit below copies "
            "it into two, which the ref rules forbid."
        ),
        "steps": [
            "Run it as written: the NFT moves to your friend.",
            "Apply the edit under Try it, which adds a second output with the same singleton ref.",
            "Run again and read the refusal. Then look at what the Transaction tab says about refs.",
        ],
        "code": _IMPORTS_TX
        + """from pyrxd.glyph import GlyphMetadata, GlyphProtocol
from pyrxd.glyph.script import build_nft_locking_script
from pyrxd.script.script import Script

sandbox.faucet(rxd=10)
nft = await sandbox.minter().mint_nft(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="one-of-one"))
held = next(c for c in sandbox.coins() if (c.txid, c.vout) == (nft.reveal_txid, 0))  # the reveal puts the token on output 0
fee_coin = sandbox.faucet(rxd=1)

to_friend = build_nft_locking_script(sandbox.friend.pkh, nft.ref)
outputs = [TransactionOutput(Script(to_friend), held.value)]
copies = 0
for _ in range(copies):
    outputs.append(TransactionOutput(Script(build_nft_locking_script(sandbox.wallet.pkh, nft.ref)), held.value))

FEE = 5_000_000
outputs.append(TransactionOutput(P2PKH().lock(sandbox.wallet.address), fee_coin.value - FEE - copies * held.value))
tx = Transaction(
    tx_inputs=[
        TransactionInput(source_transaction=held.tx, source_output_index=held.vout,
                         unlocking_script_template=P2PKH().unlock(sandbox.wallet.key)),
        TransactionInput(source_transaction=fee_coin.tx, source_output_index=fee_coin.vout,
                         unlocking_script_template=P2PKH().unlock(sandbox.wallet.key)),
    ],
    tx_outputs=outputs,
)
tx.sign()
print("moved:", sandbox.broadcast(tx))
""",
        "try_it": {
            "text": "Set copies = 1 and run. The sandbox refuses: a singleton ref may be in one output only.",
            "find": "copies = 0",
            "replace": "copies = 1",
            "expect": "refs",
        },
    },
]

SCRATCH = {
    "id": "scratch",
    "title": "Scratch",
    "meta": "Your own code",
    "file": "scratch.py",
    "heading": "Scratch",
    "intro": (
        "A blank page on the same sandbox chain. `from playground import sandbox` gives you a funded "
        "wallet (sandbox.faucet), a friend, a client for pyrxd's builders, and sandbox.broadcast. "
        "Top-level await works."
    ),
    "steps": [],
    "code": """from playground import sandbox

coin = sandbox.faucet(rxd=1)
print("you have", sandbox.balance() / 1e8, "RXD at", sandbox.wallet.address)
""",
    "try_it": None,
}


def lesson_list() -> list[dict]:
    return [*LESSONS, SCRATCH]
