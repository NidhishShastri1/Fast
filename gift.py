
from fastapi import FastAPI, Form, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from bson import ObjectId
from datetime import datetime, timedelta
from pymongo import MongoClient
from pydantic import BaseModel , EmailStr
from typing import List
from collections import defaultdict
from passlib.context import CryptContext
from jose import JWTError, jwt 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Load environment variables
load_dotenv()

app = FastAPI()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow frontend origin
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

SECRET_KEY = "a3f1d2e4c6b8a7d9e0f1c2b3d4a5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Models
class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    phone: str
    role: str

class UserProfile(BaseModel):
    username: str
    email: str
    phone: str
    role: str

# Helper Functions
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Register API
@app.post("/register")
async def register(user: UserCreate):
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    hashed_password = hash_password(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    await users_collection.insert_one(user_dict)
    return {"message": "User registered successfully"}

# Login API
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Profile API
@app.get("/profile", response_model=UserProfile)
async def profile(user: dict = Depends(get_current_user)):
    return {
        "username": user["username"],
        "email": user["email"],
        "phone": user["phone"],
        "role": user["role"]
    }
#api to update profile
@app.get("/api/profile/{username}")
async def get_user_profile(username: str):
    try:
        user = await users_collection.find_one({"username": username}, {"_id": 0, "email": 1, "phone": 1, "firstname": 1})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return user  # Return fetched details
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user profile: {str(e)}")

@app.post("/api/profile/update")
async def update_profile(
    username: str = Form(...),
    firstname: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    lastname: str = Form(...),
    address: str = Form(...),
    designation: str = Form(...)
):
    try:
        # Check if user exists
        user = await users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Create the complete employee profile
        employee_data = {
            "username": username,
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "phone": phone,
            "address": address,
            "designation": designation,
            "created_at": datetime.now().isoformat()
        }

        # Store in employees collection
        await db["employees"].insert_one(employee_data)

        return {"message": "Profile updated successfully!", "employee_data": employee_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating profile: {str(e)}")
