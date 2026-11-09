"""Single-writer discipline for SQLite inside the daemon."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from django.db import transaction

#: Serializes all write transactions in the daemon process. SQLite allows one
#: writer at a time; serializing in-process avoids busy-retry storms.
write_lock = threading.RLock()


@contextmanager
def write_transaction() -> Iterator[None]:
    """Short write transaction. Never perform OS or Docker queries inside it."""
    with write_lock, transaction.atomic():
        yield
