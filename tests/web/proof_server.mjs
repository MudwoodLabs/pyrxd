// The three requests a block proof makes, answered from a table — shared by every harness that
// drives a page's block proof (`proveMarkBlock` in shared.js), so each serves them one way.
//
// Contract: answerProof(proof, method, params) -> {result} | {error: {code?, message}} | null
//   `proof`: {"merkle": reply, "coinbase": reply, "headers": {height: hex},
//             "headers_reply"?: reply, "hang"?: [method, ...]}
//   `merkle` answers `blockchain.transaction.get_merkle`, `coinbase` answers
//   `blockchain.transaction.id_from_pos`; either may be `{"error": {...}}` to refuse. A
//   `blockchain.block.headers [start, count]` request is answered from `headers` the way ElectrumX
//   answers it — the consecutive headers it has from `start`, at most `count` — unless
//   `headers_reply` is given, which is sent verbatim for every range. `null` means "not a proof
//   request": the caller answers it (or refuses it) itself. A method listed in `hang` gets
//   `{hang: true}` — the caller never answers it, so the page's own timeout ends the wait.

export function answerProof(proof, method, params) {
  if (!proof) return null;
  const known = [
    "blockchain.transaction.get_merkle",
    "blockchain.transaction.id_from_pos",
    "blockchain.block.headers",
  ];
  if (!known.includes(method)) return null;
  if (Array.isArray(proof.hang) && proof.hang.includes(method)) return { hang: true };
  const reply = (value) => {
    if (value === undefined) return { error: { code: -32601, message: `unknown method ${method}` } };
    if (value && typeof value === "object" && value.error) return { error: value.error };
    return { result: value };
  };
  if (method === "blockchain.transaction.get_merkle") return reply(proof.merkle);
  if (method === "blockchain.transaction.id_from_pos") return reply(proof.coinbase);
  if (proof.headers_reply !== undefined) return reply(proof.headers_reply);
  const [start, count] = params;
  let hex = "";
  let served = 0;
  for (let h = start; served < count && Object.prototype.hasOwnProperty.call(proof.headers || {}, String(h)); h += 1) {
    hex += proof.headers[String(h)];
    served += 1;
  }
  return { result: { count: served, hex, max: 2016 } };
}
