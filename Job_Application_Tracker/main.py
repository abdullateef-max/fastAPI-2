from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List, Dict
import hashlib
import json
import os
from datetime import date

app = FastAPI()
security = HTTPBasic()

# Data files
USERS_FILE = "users.json"
APPLICATIONS_FILE = "applications.json"

class User(BaseModel):
    username: str
    password: str  # Will be hashed

class JobApplication(BaseModel):
    job_title: str
    company: str
    date_applied: date
    status: str = "Applied"

    # Add this method to properly serialize the date
    def dict(self, **kwargs):
        data = super().dict(**kwargs)
        data['date_applied'] = self.date_applied.isoformat()
        return data

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def save_data(data, filename):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, default=str)  # Added default=str to handle dates
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving data: {str(e)}")

def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                data = json.load(f)
                # Convert string dates back to date objects when loading
                if filename == APPLICATIONS_FILE:
                    for user_apps in data.values():
                        for app in user_apps:
                            if 'date_applied' in app and isinstance(app['date_applied'], str):
                                app['date_applied'] = date.fromisoformat(app['date_applied'])
                return data
        return {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading data: {str(e)}")

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
    
    return username

if not os.path.exists(USERS_FILE):
    save_data({
        "kodecamp": {
            "password": hash_password("kodecamp@123")
        }
    }, USERS_FILE)

if not os.path.exists(APPLICATIONS_FILE):
    save_data({}, APPLICATIONS_FILE)

# API Endpoints
@app.post("/register/")
async def register(user: User):
    users = load_data(USERS_FILE)
    
    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    users[user.username] = {
        "password": hash_password(user.password)
    }
    
    save_data(users, USERS_FILE)
    return {"message": "User registered successfully"}

@app.post("/applications/")
async def add_application(
    application: JobApplication,
    username: str = Depends(get_current_user)
):
    applications = load_data(APPLICATIONS_FILE)
    
    if username not in applications:
        applications[username] = []
    
    applications[username].append(application.dict())
    save_data(applications, APPLICATIONS_FILE)
    return {"message": "Application added successfully"}

@app.get("/applications/")
async def get_applications(username: str = Depends(get_current_user)):
    applications = load_data(APPLICATIONS_FILE)
    return applications.get(username, [])