# Reference

Normative specifications and precise, lookup-oriented material. Reference pages
state *what is true* and cite the source that makes it true; they are not
tutorials, and they assume you already know why you are here.

For the narrative versions of the same material, see
[Concepts](../concepts/index.md); for step-by-step instructions, see
[Tutorials](../tutorials/index.md) and [How-to guides](../how-to/index.md).

```{toctree}
:maxdepth: 1

glyph-token-protocol-spec
```

## Machine-readable companions

Cross-implementation test vectors live outside the docs tree, in
[`conformance/`](https://github.com/MudwoodLabs/pyrxd/blob/main/conformance/README.md).
Each suite is plain JSON with a schema id, a `params` block, and the expected
bytes, so an independent implementation can differential-test against the same
canonical artifacts rather than against pyrxd's running code.
