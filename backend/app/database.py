import os
import time

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker

DB_DRIVER = os.getenv("DB_DRIVER", "sqlite").strip().lower()
DB_PATH = os.getenv("DB_PATH", "./kabuki.db")

if DB_DRIVER in ("sqlite", "sqlite3"):
    DATABASE_URL = f"sqlite:///{DB_PATH}"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA busy_timeout = 5000")
        cursor.close()

elif DB_DRIVER in ("postgresql", "postgres"):
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASS = os.getenv("DB_PASS", "postgres")
    DB_HOST = os.getenv("DB_HOST", "db")
    DB_NAME = os.getenv("DB_NAME", "kabuki")

    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"

    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

else:
    raise ValueError(f"Unsupported DB_DRIVER '{DB_DRIVER}' (use 'sqlite' or 'postgresql').")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

IS_SQLITE = DB_DRIVER in ("sqlite", "sqlite3")


def ping() -> bool:
    """Return True when the database answers a trivial query."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def wait_for_db(max_retries: int = 30, retry_delay: float = 1.5):
    if IS_SQLITE:
        return

    last_error = None

    for _ in range(max_retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:
            last_error = exc
            time.sleep(retry_delay)

    if last_error:
        raise last_error


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
