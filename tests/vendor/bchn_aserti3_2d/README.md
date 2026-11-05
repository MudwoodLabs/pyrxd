# Bitcoin Cash Node aserti3-2d test vectors

Verbatim copies of `test_vectors/aserti3-2d/run01` to `run11` from
[bitcoin-cash-node/bchn-sw/qa-assets](https://gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets) at
commit `1e153d75cdaaa21ca3988977e946a538c74751a2`, under that repository's MIT license
(`LICENSE`, copied from the same commit). `run12` (10,000 rows) is left out for size.

They are test fixtures, never imported. `tests/test_asert_difficulty_rule.py` checks
`pyrxd.spv.asert.calculate_asert` against every row: Radiant's `CalculateASERT`
(`tests/vendor/radiant_core/pow.cpp`) is this algorithm with the spacing, half-life and anchor
passed in, and these vectors fix BCH's (600 s, two days). Each run's header gives the anchor;
each row is `iteration height time nBits`, the nBits required of the block after one at `height`
with timestamp `time`.

Do not hand-edit. To refresh, fetch the same paths at a new commit and update the commit above.
