from fastapi import FastAPI, Form, HTTPException , Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os , traceback
from dotenv import load_dotenv
from bson import ObjectId
from datetime import datetime
from pymongo import MongoClient
from pydantic import BaseModel
from typing import List
from collections import defaultdict
from passlib.context import CryptContext

# Load environment variables
load_dotenv()

app = FastAPI()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow frontend origin
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# MongoDB Connection
MONGO_URL = os.getenv("MONGO_URL", "mongodb+srv://nidhishshastri1234:admin123@cluster0.yvsxj.mongodb.net/customerdb")
client = AsyncIOMotorClient(MONGO_URL)
db = client["customerdb"]
gift_collection = db["gift"]
customer_collection = db["customers"]
gift_report_collection = db["gift_report"]
users_collection = db["users"]

# Helper function to convert MongoDB documents to JSON serializable format
def convert_mongo_document(doc):
    """Convert MongoDB document to JSON serializable format"""
    doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
    return doc

# API to add a new gift
@app.post("/api/gifts/in")
async def add_gift(
    item_name: str = Form(...),
    points_needed: int = Form(...),
    number_of_items: int = Form(...),
    date_of_arrival: str = Form(...)
):
    try:
        # Convert date_of_arrival to proper date format
        formatted_date = datetime.strptime(date_of_arrival, "%Y-%m-%d").date()

        new_gift = {
            "item_name": item_name,
            "points_needed": points_needed,
            "number_of_items": number_of_items,
            "date_of_arrival": formatted_date.isoformat()  # Store in ISO format
        }

        result = await gift_collection.insert_one(new_gift)
        return {"message": "Gift added successfully!", "gift_id": str(result.inserted_id)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# API to fetch all gifts in stock (including old ones)
@app.get("/api/gifts/stock")
async def get_gift_stock():
    try:
        gifts_cursor = gift_collection.find().sort("date_of_arrival", -1)  # Sort by date_of_arrival (newest first)
        gifts = await gifts_cursor.to_list(length=None)  # Fetch ALL documents
        if not gifts:
            return {"message": "No gifts found in database."}
        return [convert_mongo_document(gift) for gift in gifts]  # Convert and return JSON serializable data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving gifts: {str(e)}")

# API to fetch all gifts and check eligibility for a specific customer
@app.get("/api/gifts/eligibility")
async def check_gift_eligibility(customerId: str = Query(..., description="Customer ID is required")):
    try:
        # Get customer details
        customer = await customer_collection.find_one({"customerId": customerId})
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")

        customer_points = customer.get("points", 0)  # Get customer points

        # Fetch all available gifts
        gifts_cursor = gift_collection.find()
        gifts = await gifts_cursor.to_list(length=None)

        # Process gift eligibility
        result = []
        for gift in gifts:
            gift_data = convert_mongo_document(gift)

            # Ensure "points_needed" exists, or set default
            points_needed = gift.get("points_needed", 0)  # Use .get() to avoid KeyError
            gift_data["points_needed"] = points_needed  # Ensure field exists in response

            # Determine eligibility status
            # gift_data["status"] = "Buy" if customer_points >= pointsneeded else "Not Eligible"
            if customer_points >= gift["points_needed"]:
                gift_data["status"] = "Buy"
            else:
                gift_data["status"] = "Not Eligible"


            result.append(gift_data)

        return result  # Return all gifts with eligibility status

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
# API to purchase a gift
@app.post("/api/gifts/buy")
async def buy_gift(
    customerId: str = Form(...),
    giftId: str = Form(...),
    quantity: int = Form(...)
):
    try:
        # Fetch customer details
        customer = await customer_collection.find_one({"customerId": customerId})
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        customer_points = customer.get("points", 0)  

        # Fetch gift details
        gift = await gift_collection.find_one({"_id": ObjectId(giftId)})
        if not gift:
            raise HTTPException(status_code=404, detail="Gift not found")

        gift_points_needed = gift.get("points_needed", 0)  
        available_stock = gift.get("number_of_items", 0)

        # Check if enough stock is available
        if available_stock < quantity:
            raise HTTPException(status_code=400, detail="Not enough stock available")

        # Check if the customer has enough points
        total_points_needed = gift_points_needed * quantity
        if customer_points < total_points_needed:
            raise HTTPException(status_code=400, detail="Not enough points to buy this gift")

        # Deduct points from customer
        new_customer_points = customer_points - total_points_needed
        await customer_collection.update_one(
            {"customerId": customerId},
            {"$set": {"points": new_customer_points}}
        )

        # Deduct stock from gift collection
        new_stock = available_stock - quantity
        await gift_collection.update_one(
            {"_id": ObjectId(giftId)},
            {"$set": {"number_of_items": new_stock}}
        )

        # Store purchase details in the gift report collection
        purchase_report = {
            "customerId": customerId,
            "customerName": customer.get("customerName", "Unknown"),
            "giftName": gift.get("item_name", "Unknown"),
            "quantity": quantity,
            "pointsSpent": total_points_needed,
            "purchaseTime": datetime.now().isoformat()
        }

        await gift_report_collection.insert_one(purchase_report)

        return {"message": "Gift purchased successfully!", "remaining_points": new_customer_points, "remaining_stock": new_stock}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# Display customer reports
@app.get("/api/reports/customer")
async def get_customer_reports():
    try:
        # ✅ Fetch all customer data
        customers = await customer_collection.find({}, {"_id": 0}).to_list(length=None)
        if not customers:
            return {"message": "No customers found"}  # Handle empty case

        # ✅ Fetch only relevant fields from gift_report
        gift_reports = await gift_report_collection.find({}, {"_id": 0, "customerId": 1, "quantity": 1, "pointsSpent": 1}).to_list(length=None)
        
        # ✅ Aggregate gift data per customer using defaultdict
        gift_data = defaultdict(lambda: {"gifts_redeemed": 0, "points_consumed": 0})

        for gift in gift_reports:
            cust_id = str(gift.get("customerId"))  # Convert to string for consistency
            if cust_id:
                gift_data[cust_id]["gifts_redeemed"] += gift.get("quantity", 0)
                gift_data[cust_id]["points_consumed"] += gift.get("pointsSpent", 0)

        # ✅ Merge customer data with aggregated gift data
        final_report = []
        for customer in customers:
            cust_id = str(customer.get("customerId"))  # Ensure type consistency
            customer["gifts_redeemed"] = gift_data[cust_id]["gifts_redeemed"]
            customer["points_consumed"] = gift_data[cust_id]["points_consumed"]
            final_report.append(customer)

        return final_report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server Error: {str(e)}")

@app.get("/api/reports/redemption")
async def get_gift_redemption_report():
    try:
        # Fetch all customer data
        customers = await customer_collection.find({}, {"_id": 0, "customerId": 1, "customerName": 1, "mobileNumber": 1}).to_list(length=None)

        # Fetch all gift redemption reports
        gift_reports = await gift_report_collection.find({}, {"_id": 0}).to_list(length=None)

        # Fetch all gift items and handle missing fields safely
        gifts = await gift_collection.find({}, {"_id": 0, "item_name": 1, "number_of_items": 1}).to_list(length=None)
        gift_stock = {gift.get("item_name", "Unknown"): gift.get("number_of_items", 0) for gift in gifts}

        # Create a report by merging customer and gift redemption data
        report = []
        for record in gift_reports:
            customer = next((c for c in customers if c["customerId"] == record["customerId"]), None)
            if customer:
                item_name = record.get("giftName", "Unknown")  # Handle missing 'giftName' field
                report.append({
                    "Customer Name": customer["customerName"],
                    "Customer ID": customer["customerId"],
                    "Phone Number": customer["mobileNumber"],
                    "Item Name": item_name,
                    "No. of Items Redeemed": record.get("quantity", 0),
                    "Points Consumed": record.get("pointsSpent", 0),
                    "Date of Redemption": record.get("purchaseTime", "N/A"),
                    "No. of Items Remaining": gift_stock.get(item_name, 0)  # Handle missing stock
                })

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching redemption report: {str(e)}")

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Allowed Roles
ALLOWED_ROLES = {"manager", "employee", "admin"}

class UserCreate(BaseModel):
    username: str  # Role-based username (manager, employee, admin)
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

async def get_user(username: str):
    """Fetch user from MongoDB by username."""
    return await users_collection.find_one({"username": username})

@app.post("/register/")
async def register(user: UserCreate):
    """Register a new user (only if not already registered)."""
    if user.username not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role. Choose from manager, employee, or admin.")

    existing_user = await get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered.")

    hashed_password = pwd_context.hash(user.password)
    new_user = {"username": user.username, "password": hashed_password}

    await users_collection.insert_one(new_user)
    return {"message": "User registered successfully!"}

@app.post("/login/")
async def login(user: UserLogin):
    """Verify user login."""
    existing_user = await get_user(user.username)
    if not existing_user:
        raise HTTPException(status_code=400, detail="User not found. Please register first.")

    if not pwd_context.verify(user.password, existing_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid password.")

    return {"message": f"Login successful for {user.username}!"}

