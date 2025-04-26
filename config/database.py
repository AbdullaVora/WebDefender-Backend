# from pymongo import AsyncMongoClient
# from config.settings import MONGO_URI

# def connect_to_mongo():
#     try:
#         client = AsyncMongoClient(MONGO_URI, serverSelectionTimeoutMS=60000)
#         db = client.get_database()
#         print(f"Successfully connected to MongoDB: {db.name}")  # Print confirmation
#         return db
#     except Exception as e:
#         print(f"MongoDB Connection Error: {e}")  # Print error if connection fails
#         return None

# # Run the connection when database.py is imported
# db = connect_to_mongo()

# from motor.motor_asyncio import AsyncIOMotorClient
# from config.settings import MONGO_URI

# async def connect_to_mongo():
#     try:
#         client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=60000)
#         db = client.get_database()
#         print(f"Successfully connected to MongoDB: {db.name}")  # Print confirmation
#         return db
#     except Exception as e:
#         print(f"MongoDB Connection Error: {e}")  # Print error if connection fails
#         return None

# # Example of using async function
# import asyncio
# db = asyncio.run(connect_to_mongo())
# config/database.py
from motor.motor_asyncio import AsyncIOMotorClient
from config.settings import MONGO_URI

db = None

async def connect_to_mongo():
    global db
    try:
        client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=60000)
        db = client.get_database()
        print(f"✅ Connected to MongoDB: {db.name}")
    except Exception as e:
        print(f"❌ MongoDB connection error: {e}")

def get_db():
    global db
    if db is None:
        raise Exception("Database not initialized. Please wait for startup.")
    return db
