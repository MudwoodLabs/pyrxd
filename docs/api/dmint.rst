pyrxd.glyph.dmint — dMint permissionless PoW issuance
=====================================================

.. automodule:: pyrxd.glyph.dmint

The subpackage layers as ``types ← builders ← chain ← miner`` (a one-way
dependency graph). Every public symbol is re-exported at the
``pyrxd.glyph.dmint`` path via PEP 562 lazy ``__getattr__``; the reference
below documents each symbol at its defining submodule.

Types & parameters
------------------

.. automodule:: pyrxd.glyph.dmint.types
   :members:
   :show-inheritance:

Covenant & transaction builders
-------------------------------

.. automodule:: pyrxd.glyph.dmint.builders
   :members:
   :show-inheritance:

Contract & chain state
----------------------

.. automodule:: pyrxd.glyph.dmint.chain
   :members:
   :show-inheritance:

Proof-of-work miner
-------------------

.. automodule:: pyrxd.glyph.dmint.miner
   :members:
   :show-inheritance:
