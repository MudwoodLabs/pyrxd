pyrxd.eth_wallet — Ethereum counter-leg
=======================================

The ETH side of a cross-chain swap. The chain-neutral coordinator and the ``EthLeg``
orchestrator live in :doc:`gravity`; the durable ``EthHtlcLocator`` and ``recover_secret`` are
re-exported on the package and documented under :doc:`pyrxd`.

EVM chain registry
------------------

.. automodule:: pyrxd.eth_wallet.chains
   :members:
   :show-inheritance:

JSON-RPC client
---------------

.. automodule:: pyrxd.eth_wallet.rpc
   :members:
   :show-inheritance:

HTLC contract leg
-----------------

.. automodule:: pyrxd.eth_wallet.htlc_leg
   :members:
   :show-inheritance:
