import aiosqlite
import logging
from pathlib import Path
from config import settings

logger = logging.getLogger(__name__)


async def get_db():
    """Get database connection"""
    db = await aiosqlite.connect(settings.DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    """Initialize database schema"""
    schema_file = Path(__file__).parent / "schema.sql"

    db = await get_db()
    try:
        if schema_file.exists():
            with open(schema_file, 'r') as f:
                schema = f.read()
                await db.executescript(schema)
                await db.commit()
            logger.info("Database schema initialized")
        else:
            logger.warning(f"Schema file not found: {schema_file}")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise
    finally:
        await db.close()
