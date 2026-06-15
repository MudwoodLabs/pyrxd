pyrxd.agent — sign-on-behalf signing daemon
===========================================

The optional ``pyrxd agent`` daemon holds an unlocked wallet for a bounded window and signs
transactions on request — with a per-spend confirmation on its own controlling terminal and
prevout-authenticity checks — so the key is removed from the short-lived CLI process and a
same-uid caller can only *request* a signature, never take the key.

.. automodule:: pyrxd.agent
   :members:
   :show-inheritance:
