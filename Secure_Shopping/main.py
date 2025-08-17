from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import hashlib
import json
import os
from typing import List, Dict

app = FastAPI()
security = HTTPBasic()

# Data files
PRODUCTS_FILE = "products.json"
CARTS_FILE = "carts.json"
USERS_FILE = "users.json"

class User(BaseModel):
    username: str
    password: str  
    role: str 

class Product(BaseModel):
    id: int
    name: str
    price: float
    description: str = ""

class CartItem(BaseModel):
    product_id: int
    quantity: int

def save_data(data, filename):
    try:
        with open(filename, "w") as f:
            json.dump(data, f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving data: {str(e)}")

def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return json.load(f)
        return {} if "users" in filename else []
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading data: {str(e)}")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Authentication
def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    users = load_data(USERS_FILE)
    username = credentials.username
    
    if username not in users:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    hashed_password = hash_password(credentials.password)
    if hashed_password != users[username]["password"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return users[username]

def admin_required(user: Dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user

if not os.path.exists(USERS_FILE):
    save_data({
        "kodecamp": {
            "password": hash_password("kodecamp@123"),
            "role": "admin"
        }
    }, USERS_FILE)

if not os.path.exists(PRODUCTS_FILE):
    save_data([], PRODUCTS_FILE)

if not os.path.exists(CARTS_FILE):
    save_data({}, CARTS_FILE)

# API Endpoints
@app.post("/register/")
async def register(user: User):
    users = load_data(USERS_FILE)
    
    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    users[user.username] = {
        "password": hash_password(user.password),
        "role": user.role
    }
    
    save_data(users, USERS_FILE)
    return {"message": "User registered successfully"}

@app.post("/admin/add_product/")
async def add_product(
    product: Product,
    current_user: Dict = Depends(admin_required)
):
    products = load_data(PRODUCTS_FILE)
    products.append(product.dict())
    save_data(products, PRODUCTS_FILE)
    return {"message": "Product added successfully"}

@app.get("/products/")
async def get_products():
    return load_data(PRODUCTS_FILE)

@app.post("/cart/add/")
async def add_to_cart(
    item: CartItem,
    current_user: Dict = Depends(get_current_user)
):
    carts = load_data(CARTS_FILE)
    username = current_user["username"]
    
    if username not in carts:
        carts[username] = []
    
    products = load_data(PRODUCTS_FILE)
    product_ids = [p["id"] for p in products]
    if item.product_id not in product_ids:
        raise HTTPException(status_code=404, detail="Product not found")
    
    carts[username].append(item.dict())
    save_data(carts, CARTS_FILE)
    return {"message": "Item added to cart"}
