# Surviving mutants — value-moving modules

```{toctree}
:maxdepth: 1

fee
wallet
hdwallet
glyph
mint
swap
coordinator
network
```

Each file here lists the mutants that **survived** a cosmic-ray run: the suite executed that
mutated line and no assertion failed. They are the raw output of
[`scripts/mutation_survivors.py`](https://github.com/MudwoodLabs/pyrxd/blob/main/scripts/mutation_survivors.py),
one row per mutant — file, line, enclosing definition, mutation operator, and the exact source
change.

This is a **worklist, not a defect list.** A survivor means one of two things and the difference
is a judgement call a human has to make:

- *Nothing tests this.* The branch runs, the behaviour changed, and the suite did not notice. These
  are the ones worth a test. When you write one, put it in `tests/test_mutation_hardening.py` and
  name the mutant class it kills, the way the existing entries there do.
- *Nothing **can** test this.* The mutant is equivalent — it does not change behaviour. The classes
  that dominate in this codebase are catalogued in
  [`../../how-to/mutation-testing.md`](../../how-to/mutation-testing.md#reading-the-score--survivors-are-not-all-bugs):
  type annotations (`bytes | None` → `bytes - None`, never evaluated under
  `from __future__ import annotations`), error-message f-strings, and interpreter-detail rewrites
  such as `==` → `is` on interned values.

## Reading a row

| Column | Meaning |
|---|---|
| Line | 1-based line in the module, at the commit named below |
| Definition | the enclosing function or method — `(module level)` when there is none |
| Operator | the cosmic-ray operator, with its `core/` prefix stripped |
| Original / Mutant | the single source line before and after the mutation |
| (last) | `annot` marks a BitOr-family rewrite of a **type annotation** — `X \| None` becoming `X + None`. These cannot be killed: `from __future__ import annotations` makes annotations strings that are never evaluated. **Start with the unmarked rows.** They are flagged rather than dropped so the file stays a complete record if the heuristic is ever wrong. |

A row is triaged by answering one question: **if this mutant shipped, what would go wrong, and why
did no test see it?** If the answer is "nothing would go wrong", it is equivalent — say so in the
commit that removes it from the worklist. If the answer is anything else, it needs a test.

## Provenance

Produced 2026-08-12 from a full sweep of all seven value groups — **8 171 mutants, 5 049 killed,
3 122 survived (61%)** — against the module sources at commit `3115028`, which are byte-identical to
those at `724fe92`. Per-module rates and wall times are in
[`../../how-to/mutation-testing.md`](../../how-to/mutation-testing.md).

These lists are **generated**, and they go stale the moment the source or the tests move. Line
numbers are only meaningful at the commit above.

Regenerate them with:

```bash
MUTATION_SESSION_DIR=.mutation-sessions task mutate <group>
python scripts/mutation_survivors.py out.md .mutation-sessions/*.sqlite
```

The weekly [`Mutation (scheduled)`](https://github.com/MudwoodLabs/pyrxd/blob/main/.github/workflows/mutation.yml)
workflow produces the same files as build artifacts, so the current picture is always one workflow
run away even when the copies here have aged.
