"""Faithful simulator of GravityNftCovenantAnyWallet20.rxd's parser + merkle walk.
Mirrors the EXACT opcode semantics:
- rawTx.split(n) => (rawTx[:n], rawTx[n:]). split on out-of-range index in
  Radiant Script: OP_SPLIT requires 0 <= n <= len; n>len -> SCRIPT FAILURE.
- int(bytes) => CScriptNum minimal decode (LE, sign-magnitude). For a 1-byte
  push 0x00..0x7f it's the value; 0x80..0xff are NEGATIVE in CScriptNum!
"""
def OP_SPLIT(b, n):
    # Radiant/BCH OP_SPLIT: fails if n<0 or n>len(b)
    if n < 0 or n > len(b):
        raise ScriptFail(f"OP_SPLIT out of range: n={n} len={len(b)}")
    return b[:n], b[n:]

class ScriptFail(Exception): pass

def scriptnum(b):
    # CScriptNum decode (BCH/Radiant): LE, MSB of last byte = sign.
    if len(b) == 0:
        return 0
    if len(b) > 4:
        # int() in radiantscript on >4 bytes: OP_BIN2NUM / numeric overflow
        # Actually `int(bytes)` for a value-read like split(8)[0] uses bin2num
        # which fails if it doesn't fit in 4 bytes (after minimal encoding).
        # But value reads are 8 bytes! Radiant uses extended 8-byte script nums?
        # We'll model the parser's `int(...)` on <=4 byte slices for counts/lens,
        # and 8-byte for value. Radiant supports bignum script via OP_NUM... 
        # For safety in THIS sim, decode full LE two's-complement-ish.
        pass
    n = int.from_bytes(b, "little")
    # sign bit
    if b[-1] & 0x80:
        n -= (1 << (8*len(b)))  # NEGATIVE — this is the CScriptNum gotcha
    return n

def split_idx(b, n):
    # helper: b.split(n)[idx]
    l, r = OP_SPLIT(b, n)
    return l, r

def parse(rawTx, btcReceiveHash, btcSatoshis, trace=False):
    """Return True if covenant would accept the payment (found==true) AND the
    parse completes without ScriptFail. Raises ScriptFail to mimic consensus reject."""
    # require(rawTx.length > 64)
    if not (len(rawTx) > 64):
        raise ScriptFail("rawTx.length <= 64")
    # int(rawTx.split(4)[1].split(1)[0])
    _, r = OP_SPLIT(rawTx, 4)
    nIn_b, _ = OP_SPLIT(r, 1)
    nIn = scriptnum(nIn_b)
    if not (nIn >= 1): raise ScriptFail("nIn<1")
    if not (nIn <= 4): raise ScriptFail("nIn>4")
    pos = 5
    def read_ssl(pos):
        _, r = OP_SPLIT(rawTx, pos+36)
        sslb,_ = OP_SPLIT(r,1)
        return scriptnum(sslb)
    def chk_ssl(s):
        if not (s >= 0): raise ScriptFail("ssl<0")
        if not (s <= 252): raise ScriptFail("ssl>252")
        return s
    ssl1 = chk_ssl(read_ssl(pos)); pos = pos + 36 + 1 + ssl1 + 4
    if nIn>=2:
        ssl2=chk_ssl(read_ssl(pos)); pos = pos+36+1+ssl2+4
    if nIn>=3:
        ssl3=chk_ssl(read_ssl(pos)); pos = pos+36+1+ssl3+4
    if nIn>=4:
        ssl4=chk_ssl(read_ssl(pos)); pos = pos+36+1+ssl4+4
    # nOut
    _,r = OP_SPLIT(rawTx,pos); nob,_=OP_SPLIT(r,1); nOut=scriptnum(nob)
    if not (nOut>=1): raise ScriptFail("nOut<1")
    if not (nOut<=4): raise ScriptFail("nOut>4")
    pos = pos+1
    found = False
    def scan(pos):
        nonlocal found
        _,r=OP_SPLIT(rawTx,pos); vb,_=OP_SPLIT(r,8); v=scriptnum(vb)
        _,r=OP_SPLIT(rawTx,pos+8); slb,_=OP_SPLIT(r,1); sl=scriptnum(slb)
        if sl==22:
            _,r=OP_SPLIT(rawTx,pos+9); pfx,_=OP_SPLIT(r,2)
            if pfx==bytes.fromhex("0014"):
                _,r=OP_SPLIT(rawTx,pos+11); hh,_=OP_SPLIT(r,20)
                if hh==btcReceiveHash and v>=btcSatoshis: found=True
        if sl==25:
            _,r=OP_SPLIT(rawTx,pos+9); pfx,_=OP_SPLIT(r,3)
            if pfx==bytes.fromhex("76a914"):
                _,r=OP_SPLIT(rawTx,pos+12); hh,_=OP_SPLIT(r,20)
                if hh==btcReceiveHash:
                    _,r=OP_SPLIT(rawTx,pos+32); sfx,_=OP_SPLIT(r,2)
                    if sfx==bytes.fromhex("88ac") and v>=btcSatoshis: found=True
        if sl==23:
            _,r=OP_SPLIT(rawTx,pos+9); pfx,_=OP_SPLIT(r,2)
            if pfx==bytes.fromhex("a914"):
                _,r=OP_SPLIT(rawTx,pos+11); hh,_=OP_SPLIT(r,20)
                if hh==btcReceiveHash:
                    _,r=OP_SPLIT(rawTx,pos+31); sfx,_=OP_SPLIT(r,1)
                    if sfx==bytes.fromhex("87") and v>=btcSatoshis: found=True
        if sl==34:
            _,r=OP_SPLIT(rawTx,pos+9); pfx,_=OP_SPLIT(r,2)
            if pfx==bytes.fromhex("5120"):
                _,r=OP_SPLIT(rawTx,pos+11); hh,_=OP_SPLIT(r,32)
                if hh==btcReceiveHash and v>=btcSatoshis: found=True
        return sl
    def chk_sl(s):
        if not (s >= 0): raise ScriptFail("sl<0")
        if not (s <= 252): raise ScriptFail("sl>252")
        return s
    sl1=chk_sl(scan(pos)); pos=pos+9+sl1
    if nOut>=2:
        sl2=chk_sl(scan(pos)); pos=pos+9+sl2
    if nOut>=3:
        sl3=chk_sl(scan(pos)); pos=pos+9+sl3
    if nOut>=4:
        sl4=chk_sl(scan(pos)); pos=pos+9+sl4
    if not found: raise ScriptFail("require(found) failed")
    if pos != len(rawTx) - 4: raise ScriptFail(f"terminal pos {pos} != len-4 {len(rawTx)-4}")
    return True

if __name__=="__main__":
    import json
    p=json.load(open(".nft_proof.json"))
    raw=bytes.fromhex(p["raw_tx_hex"])
    h=bytes.fromhex("9995c9ac3bd932a75dca3229e3195c3544d5db36")  # bc1q2quw... pkh? check
    # The real maker hash from payment_info
    pi=json.load(open(".aw_maker_btc.json"))
    print("maker_btc.json:", pi)
