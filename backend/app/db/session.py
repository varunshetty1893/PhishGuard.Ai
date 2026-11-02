from typing import Any, Dict
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

engine_kwargs: Dict[str, Any] = {}

if settings.IS_POSTGRES:
    # Neon Serverless PostgreSQL optimizations
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 300,
        "connect_args": {"sslmode": "require"} if "sslmode" not in settings.DATABASE_URL else {}
    })
else:
    # SQLite configuration for local dev & testing with WAL mode & busy timeout
    engine_kwargs.update({
        "connect_args": {"check_same_thread": False, "timeout": 15}
    })

engine = create_engine(
    settings.DATABASE_URL,
    **engine_kwargs
)

if not settings.IS_POSTGRES:
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Initializes tables for all registered models with automatic schema migration."""
    Base.metadata.create_all(bind=engine)

    # In case scan_history already existed before user_id was introduced
    try:
        insp = inspect(engine)
        if "scan_history" in insp.get_table_names():
            columns = [c["name"] for c in insp.get_columns("scan_history")]
            if "user_id" not in columns:
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_history_user_id ON scan_history(user_id)"))
    except Exception:
        # Table migration logged or handled gracefully
        pass


def get_db():
    """Dependency that yields a managed SQLAlchemy database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
