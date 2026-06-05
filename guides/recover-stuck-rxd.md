# Recovering RXD that's stuck in a wallet

**Your coins are almost certainly safe.** If a block explorer shows a balance on
your address but your wallet shows **zero** after you restore your seed phrase,
the money is not lost — your wallet is just looking at the wrong address. This
guide walks you through finding it and moving it somewhere safe, step by step,
in plain language.

---

## ⚠️ Read this first — stay safe

Recovering stuck coins makes you a target for scammers. Before anything else:

- **Never type or paste your seed phrase (your 12 or 24 words) into a website,
  a "recovery service," a chat, or hand it to a person.** No legitimate tool or
  helper ever needs your seed. Anyone who asks for it is trying to steal from you.
- **Only run the official software** described below, **on your own computer.**
- Your seed phrase **is** your money. Treat it like cash.

If you keep that one rule, the rest of this is safe and straightforward.

---

## Why this happens (in plain English)

Your seed phrase doesn't unlock *one* address — it can generate a whole tree of
them. Think of one key that fits many doors. Different wallets (and even
different versions of the *same* wallet) sometimes pick a **different door** to
show you.

So your coins are sitting safely behind one door, but your wallet is standing in
front of a different, empty one. We just need to find the right door, then move
the coins to a wallet you control.

---

## What you'll need

- **A computer** — Windows, Mac, or Linux. (Sorry, this part can't be done on a
  phone. If you only have a phone, borrow or use a computer — and **never** put
  your seed into a phone app you're not sure about.)
- **Your seed phrase** (the 12 or 24 words).
- About 15 minutes.

---

## Step 1 — Install the recovery tool (`pyrxd`)

`pyrxd` is a free, open-source Radiant toolkit. Install it once.

### On Windows

1. **Install Python.** Go to <https://www.python.org/downloads/> and click the
   big "Download Python" button. Run the installer.
   - **Important:** on the first screen, tick the box that says
     **"Add Python to PATH"** before clicking Install. (If you miss it, just
     run the installer again.)
2. **Open a terminal.** Press the Windows key, type `cmd`, and open
   **Command Prompt**.
3. **Install pyrxd.** Type this and press Enter:
   ```
   pip install pyrxd
   ```
   Wait for it to finish (a page of text will scroll by — that's normal).

### On Mac or Linux

Open the **Terminal** app and run:
```
pip3 install pyrxd
```
(Most Macs and Linux machines already have Python. If `pip3` isn't found,
install Python from <https://www.python.org/downloads/> first.)

> **Check it worked:** type `pyrxd --help` and press Enter. If you see a list of
> commands, you're ready. If it says "command not found," close and reopen the
> terminal, or re-run the Python installer with "Add Python to PATH" ticked.

The official package lives at <https://pypi.org/project/pyrxd/> and the source
code is public at <https://github.com/MudwoodLabs/pyrxd>. Don't install anything
that *claims* to be pyrxd from anywhere else.

---

## Step 2 — Find your coins

In the terminal, run:

```
pyrxd wallet recover --scan
```

It will ask:

```
Mnemonic (input hidden):
```

Type or paste your seed phrase and press Enter.

> **You won't see the words appear as you type — that's on purpose**, so nobody
> looking at your screen can read them. It's working even though nothing shows.
> (On Windows Command Prompt, right-click to paste.)

The tool checks the likely addresses and tells you where your coins are. A
successful result looks like this:

```
Found funds. Recover with the wallet that derives the matching path:

  0.10000000 RXD  m/44'/0'/0'/0/0
      coin type 0 — legacy
      1CB9FyqzQiyjUw9gXyYmjHNUxjG8gQScYh

Total confirmed   0.10000000 RXD
```

The important part is the **coin type** (here, `0`) — note it down. You'll use
it in the next step. (If yours says `512`, use `512`.)

> **If it says "No on-chain history found":** double-check your seed words and
> their order, and confirm on a block explorer that the balance is really on an
> address. If the explorer shows it but the scan doesn't, the coins may be on an
> unusual path — see "Still stuck?" at the bottom.

---

## Step 3 — Move your coins to safety

First, you need a **destination** — a receive address from a wallet you control
and trust. The easiest options:

- Create a fresh wallet in a current Radiant wallet app and copy its **receive
  address**, or
- Use your **deposit address** from an exchange you use.

A Radiant address starts with `1` and looks like
`1FzegoRZEXAPKztjVSkiX9VfK7s2ecwMGM`.

Then run this, replacing the coin type with what Step 2 told you, and the
address with your destination:

```
pyrxd wallet sweep --coin-type 0 --to YOUR_DESTINATION_ADDRESS
```

Enter your seed at the hidden prompt again. The tool shows you exactly what it's
about to do and asks you to confirm:

```
  Sweep:
    from path:   m/44'/0'/0'
    inputs:      1 UTXO(s)
    total found: 0.10000000 RXD
    network fee: 0.01920000 RXD
    you receive: 0.08080000 RXD
    to address:  1FzegoRZEXAPKztjVSkiX9VfK7s2ecwMGM

Broadcast this sweep? [y/N]:
```

**Check the "to address" line carefully** — that's where your coins are going.
If it's correct, type `y` and press Enter. You'll get a transaction ID:

```
Swept 0.08080000 RXD to 1FzegoRZEXAPKztjVSkiX9VfK7s2ecwMGM
Transaction: f4a6af5f1b2055cb3d7e0af4ae5447c263972d2eb4c053fd7cb89a8c81754254
```

That's it — your coins are on their way to your new wallet. You can paste the
transaction ID into a block explorer to watch it confirm.

> A small **network fee** is taken out (paid to miners, not to anyone else) —
> that's normal for any blockchain transaction. If your balance is *very* small
> (smaller than the fee), the tool will refuse rather than waste it.

---

## Good to know

- This tool is **read-only until you confirm.** Step 2 only *looks*; nothing
  moves until you type `y` in Step 3.
- Your seed never leaves your computer. The tool only sends ordinary public
  addresses to the network to check balances — never your words.
- If your coins turn out to be on the *common* path, the current
  [Photonic Wallet](https://github.com/Radiant-Core/Photonic-Wallet)'s "Recover"
  screen can also restore them without a computer (tick "Use legacy derivation
  path" if it shows empty). The tool above is the thorough fallback that also
  handles the less-common paths a phone wallet can't reach.

---

## Still stuck?

If Step 2 finds nothing even though the explorer shows your balance:

1. Re-check every seed word and the order — one wrong word changes everything.
2. Widen the search:
   ```
   pyrxd wallet recover --scan --coin-types 0,512 --accounts 0,1,2,3
   ```
3. Confirm the funded address on an explorer and check whether it matches any
   address the scan derived. If it matches none, your old wallet may have used
   an unusual setup — ask for help in a **trusted** Radiant community channel,
   and remember: **never share your seed phrase, even with someone helping you.**

---

*This guide and the `pyrxd` tool are open source. Verify the tool at
<https://github.com/MudwoodLabs/pyrxd> and <https://pypi.org/project/pyrxd/>
before installing.*
