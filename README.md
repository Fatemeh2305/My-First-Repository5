modern_fastapi_pro/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── db.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   ├── routes.py
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── login.html
│       ├── register.html
│       ├── contact.html
│       └── admin.html
│
├── requirements.txt
├── Dockerfile
└── README.mds


────────────────────────────
app/main.py
────────────────────────────
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.db import create_db_and_tables
from app.routes import router

app = FastAPI(title="ModernFastAPIPro", version="1.0.0")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(router)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


────────────────────────────
app/db.py
────────────────────────────
from sqlmodel import SQLModel, create_engine, Session
from typing import Generator

DATABASE_URL = "sqlite:///./app.db"
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


────────────────────────────
app/models.py
────────────────────────────
from typing import Optional
from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, max_length=150, unique=True)
    hashed_password: str

class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str
    message: str


────────────────────────────
app/schemas.py
────────────────────────────
from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MessageCreate(BaseModel):
    name: str
    email: EmailStr
    message: str

class MessageRead(BaseModel):
    id: int
    name: str
    email: str
    message: str


────────────────────────────
app/auth.py
────────────────────────────
from datetime import datetime, timedelta
from typing import Optional
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, Request
from sqlmodel import Session, select
from app.models import User
from app.db import get_session

SECRET_KEY = "change_this_to_a_long_random_secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = {"sub": subject}
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_username_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    return decode_token(token)

def authenticate_user(db: Session, username: str, password: str) -> Optional[str]:
    statement = select(User).where(User.username == username)
    user = db.exec(statement).first()
    if user and verify_password(password, user.hashed_password):
        return create_access_token(subject=username)
    return None


────────────────────────────
app/routes.py
────────────────────────────
from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from app.db import get_session
from app.models import User, Message
from app.schemas import MessageCreate, MessageRead, Token
from app.auth import hash_password, authenticate_user, create_access_token, get_current_username_from_cookie

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = get_current_username_from_cookie(request)
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

@router.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register_post(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_session)):
    if len(username) < 3 or len(password) < 6:
        return templates.TemplateResponse("register.html", {"request": Request, "error": "Invalid input"})
    statement = select(User).where(User.username == username)
    if db.exec(statement).first():
        return templates.TemplateResponse("register.html", {"request": Request, "error": "Username already taken"})
    user = User(username=username, hashed_password=hash_password(password))
    db.add(user)
    db.commit()
    return RedirectResponse("/login", status_code=303)

@router.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_session)):
    token = authenticate_user(db, username, password)
    if not token:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(key="access_token", value=token, httponly=True, samesite="lax")
    return resp

@router.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie("access_token")
    return resp

@router.get("/contact", response_class=HTMLResponse)
def contact_get(request: Request):
    user = get_current_username_from_cookie(request)
    return templates.TemplateResponse("contact.html", {"request": request, "user": user})

@router.post("/contact")
def contact_post(name: str = Form(...), email: str = Form(...), message: str = Form(...), db: Session = Depends(get_session)):
    msg = Message(name=name, email=email, message=message)
    db.add(msg)
    db.commit()
    return RedirectResponse("/contact", status_code=303)

@router.get("/admin", response_class=HTMLResponse)
def admin(request: Request, db: Session = Depends(get_session)):
    username = get_current_username_from_cookie(request)
    if not username:
        return RedirectResponse("/login", status_code=303)
    statement = select(Message).order_by(Message.id.desc())
    msgs = db.exec(statement).all()
    return templates.TemplateResponse("admin.html", {"request": request, "user": username, "messages": msgs})


────────────────────────────
Templates
────────────────────────────

base.html
---------------------------------
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ title or "ModernFastAPIPro" }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="/">ModernFastAPIPro</a>
    <div>
      <a class="nav-link d-inline text-white" href="/">Home</a>
      <a class="nav-link d-inline text-white" href="/contact">Contact</a>
      {% if user %}
        <a class="nav-link d-inline text-warning" href="/admin">Admin</a>
        <a class="nav-link d-inline text-danger" href="/logout">Logout</a>
      {% else %}
        <a class="nav-link d-inline text-info" href="/login">Login</a>
        <a class="nav-link d-inline text-success" href="/register">Register</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container mt-4">
  {% block content %}{% endblock %}
</div>
</body>
</html>

index.html
---------------------------------
{% extends "base.html" %}
{% block content %}
<h1 class="mb-3">Welcome to ModernFastAPIPro</h1>
<p class="lead">FastAPI + SQLModel + JWT auth — production-ready starter.</p>
{% endblock %}

register.html
---------------------------------
{% extends "base.html" %}
{% block content %}
<h2>Register</h2>
<form method="post">
  <div class="mb-3"><label>Username</label><input class="form-control" name="username" required></div>
  <div class="mb-3"><label>Password</label><input type="password" class="form-control" name="password" required></div>
  <button class="btn btn-primary">Register</button>
</form>
{% if error %}<div class="mt-3 alert alert-danger">{{ error }}</div>{% endif %}
{% endblock %}

login.html
---------------------------------
{% extends "base.html" %}
{% block content %}
<h2>Login</h2>
<form method="post">
  <div class="mb-3"><label>Username</label><input class="form-control" name="username" required></div>
  <div class="mb-3"><label>Password</label><input type="password" class="form-control" name="password" required></div>
  <button class="btn btn-success">Login</button>
</form>
{% if error %}<div class="mt-3 alert alert-danger">{{ error }}</div>{% endif %}
{% endblock %}

contact.html
---------------------------------
{% extends "base.html" %}
{% block content %}
<h2>Contact</h2>
<form method="post">
  <div class="mb-3"><label>Name</label><input class="form-control" name="name" required></div>
  <div class="mb-3"><label>Email</label><input type="email" class="form-control" name="email" required></div>
  <div class="mb-3"><label>Message</label><textarea class="form-control" name="message" rows="4" required></textarea></div>
  <button class="btn btn-primary">Send</button>
</form>
{% endblock %}

admin.html
---------------------------------
{% extends "base.html" %}
{% block content %}
<h2>Admin Dashboard</h2>
{% if messages %}
  <table class="table table-striped">
    <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Message</th></tr></thead>
    <tbody>
      {% for m in messages %}
      <tr><td>{{ m.id }}</td><td>{{ m.name }}</td><td>{{ m.email }}</td><td>{{ m.message }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
{% else %}
  <p>No messages yet.</p>
{% endif %}
{% endblock %}


────────────────────────────
requirements.txt
────────────────────────────
fastapi
uvicorn[standard]
sqlmodel
jinja2
passlib[bcrypt]
pyjwt


────────────────────────────
Dockerfile
────────────────────────────
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


────────────────────────────
README.md
────────────────────────────
# ModernFastAPIPro

Starter project: FastAPI + SQLModel + JWT auth + Jinja2 templates + Docker.

## Run locally
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
