from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import hashlib
import json
import os
from typing import List

app = FastAPI()
security = HTTPBasic()

STUDENT_FILE = "students.json"

class Student(BaseModel):
    username: str
    password: str 
    grades: List[float] = []

def save_students(students: dict):
    try:
        with open(STUDENT_FILE, "w") as f:
            json.dump(students, f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving data: {str(e)}")

def load_students() -> dict:
    try:
        if os.path.exists(STUDENT_FILE):
            with open(STUDENT_FILE, "r") as f:
                return json.load(f)
        return {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading data: {str(e)}")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    students = load_students()
    username = credentials.username
    if username not in students:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    hashed_password = hash_password(credentials.password)
    if hashed_password != students[username]["password"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return username

@app.post("/register/")
async def register(student: Student):
    students = load_students()
    
    if student.username in students:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Hash password before storing
    hashed_password = hash_password(student.password)
    students[student.username] = {
        "password": hashed_password,
        "grades": student.grades
    }
    
    save_students(students)
    return {"message": "Student registered successfully"}

@app.post("/login/")
async def login(credentials: HTTPBasicCredentials = Depends(security)):
    username = get_current_user(credentials)
    return {"message": f"Welcome {username}"}

@app.get("/grades/")
async def get_grades(username: str = Depends(get_current_user)):
    students = load_students()
    return {"username": username, "grades": students[username]["grades"]}