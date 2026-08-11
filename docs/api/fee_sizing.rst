pyrxd.fee_sizing — What fee a signed transaction must pay
=========================================================

The single implementation of the trial/final fee-sizing rule used by every
builder that signs twice. Distinct from :doc:`fee_models`, which models a
transaction's size from its *shape* for ``Transaction.fee()``; this module
works from the **measured serialized length of an already-signed transaction**
and is what stands between a build and a ``min relay fee not met`` rejection
that Radiant cannot fee-bump.

.. automodule:: pyrxd.fee_sizing
   :members:
   :show-inheritance:
