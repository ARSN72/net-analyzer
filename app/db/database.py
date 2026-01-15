from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite database configuration
DATABASE_URL = "sqlite:///scanner.db"

# check_same_thread=False allows usage with FastAPI's async-to-sync bridging
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
