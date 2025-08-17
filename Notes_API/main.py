from datetime import datetime, timedelta
from typing import Dict, List, Optional

import json
import os
import secrets

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from passlib.context import CryptContext
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError


SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

USERS_FILE = "users.json"
NOTES_FILE = "notes.json"

# OAuth2 config; tokenUrl must match your /login route (without leading slash)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Notes API", version="1.0.0")

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=128)

class UserInDB(BaseModel):
    username: str
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class NoteCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1)
    # Optional date; defaults to now if not provided
    date: Optional[datetime] = None

class NoteOut(BaseModel):
    title: str
    content: str
    date: datetime

def save_data(data, filename: str) -> None:
    try:
        with open(filename, "w") as f:
            json.dump(data, f, default=str, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving data: {str(e)}")

def load_data(filename: str):
    try:
        if os.path.exists(filename):
            with open(filename, "r") as f:
                return json.load(f)
        return {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading data: {str(e)}")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str) -> Optional[UserInDB]:
    users = load_data(USERS_FILE)
    data = users.get(username)
    if not data:
        return None
    # Allow migration from old schema ("password") to new ("hashed_password")
    if "hashed_password" not in data and "password" in data:
        data["hashed_password"] = data["password"]
        data.pop("password", None)
        users[username] = data
        save_data(users, USERS_FILE)
    return UserInDB(**data)

def create_access_token(subject: str, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if not username:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired", headers={"WWW-Authenticate": "Bearer"})
    except InvalidTokenError:
        raise credentials_exception

    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

def bootstrap_files() -> None:
    if not os.path.exists(USERS_FILE):
        save_data({
            "admin": {
                "username": "admin",
                "hashed_password": hash_password("admin123")
            }
        }, USERS_FILE)
    else:
        # Optional: migrate any legacy "password" fields to "hashed_password"
        users = load_data(USERS_FILE)
        changed = False
        for u, data in users.items():
            if "hashed_password" not in data and "password" in data:
                data["hashed_password"] = data["password"]
                data.pop("password", None)
                users[u] = data
                changed = True
        if changed:
            save_data(users, USERS_FILE)

    if not os.path.exists(NOTES_FILE):
        save_data({}, NOTES_FILE)

bootstrap_files()


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: RegisterRequest):
    users = load_data(USERS_FILE)

    if user.username in users:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    users[user.username] = {
        "username": user.username,
        "password": hash_password(user.password),
    }
    save_data(users, USERS_FILE)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=user.username)
    return {"access_token": access_token, "token_type": "Bearer"}

@app.get("/me")
async def read_me(current_user: UserInDB = Depends(get_current_user)):
    # Minimal profile endpoint
    return {"username": current_user.username}

@app.post("/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
async def add_note(note: NoteCreate, current_user: UserInDB = Depends(get_current_user)):
    notes = load_data(NOTES_FILE)

    if current_user.username not in notes:
        notes[current_user.username] = []

    # Default date to now if not provided
    note_date = note.date or datetime.utcnow()

    new_note = {
        "title": note.title,
        "content": note.content,
        "date": note_date.isoformat(),
    }
    notes[current_user.username].append(new_note)
    save_data(notes, NOTES_FILE)

    # Return as NoteOut (ensure datetime conversion)
    return NoteOut(title=note.title, content=note.content, date=note_date)

@app.get("/notes", response_model=List[NoteOut])
async def get_notes(current_user: UserInDB = Depends(get_current_user)):
    notes = load_data(NOTES_FILE)
    user_notes = notes.get(current_user.username, [])

    # Ensure proper datetime parsing
    parsed: List[NoteOut] = []
    for n in user_notes:
        d = n.get("date")
        dt = datetime.fromisoformat(d) if isinstance(d, str) else (d or datetime.utcnow())
        parsed.append(NoteOut(title=n["title"], content=n["content"], date=dt))
    return parsed
