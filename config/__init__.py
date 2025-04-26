from config.database import get_db
from config.settings import MONGO_URI

db = get_db()

__all__ = ["MONGO_URI","db"]


