"""Application services: the only code allowed to write to the database.

All writes go through :func:`portregistry.services.db.write_transaction`, which
serializes writers inside the daemon and keeps transactions short. Discovery
results are always collected *before* a transaction is opened.
"""
