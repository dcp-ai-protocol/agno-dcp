"""Storage backends for agno-dcp.

The :class:`BaseStorage` abstract class defines the persistence
contract that every concrete backend must satisfy. Two backends ship
with the library:

* :class:`SQLiteStorage`: file-backed sqlite, no extra dependencies,
  suitable for development and local testing.
* :class:`PostgresStorage`: Postgres via SQLAlchemy 2.0 async, suitable
  for production. Requires the ``[postgres]`` extra
  (``pip install agno-dcp[postgres]``).
"""

from agno_dcp.storage.base import BaseStorage
from agno_dcp.storage.sqlite import SQLiteStorage

__all__ = ["BaseStorage", "PostgresStorage", "SQLiteStorage"]


def __getattr__(name: str) -> object:
    """Lazy import of optional backends.

    ``PostgresStorage`` is only available when the ``[postgres]`` extra
    is installed. Importing it lazily lets the package load on systems
    without psycopg.
    """
    if name == "PostgresStorage":
        from agno_dcp.storage.postgres import PostgresStorage

        return PostgresStorage
    raise AttributeError(f"module 'agno_dcp.storage' has no attribute {name!r}")
