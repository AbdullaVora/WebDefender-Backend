import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

# Load environment variables from .env file
load_dotenv()

# Retrieve credentials from environment variables
username = os.getenv("MONGO_USER", "webDefender")  # Default value as fallback
password = os.getenv("MONGO_PASS", "defend@00")
db_name = os.getenv("MONGO_DB", "users")

# Encode password
encoded_password = quote_plus(password)

# Construct the MongoDB URI
MONGO_URI = f"mongodb+srv://{username}:{encoded_password}@cluster0.e0qoq.mongodb.net/{db_name}"