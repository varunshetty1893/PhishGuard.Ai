from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

# SQLite configuration with thread-safety for multi-threaded FastAPI dev server
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    from app.models import scan  # ensure models are imported
    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency that yields a managed SQLAlchemy database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
