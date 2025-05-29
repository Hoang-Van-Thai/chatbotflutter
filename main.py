
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import bcrypt
from urllib.parse import quote_plus
import google.generativeai as genai
import logging
import jwt
from fastapi.security import OAuth2PasswordBearer
import os
import smtplib
from email.mime.text import MIMEText
import random
import string
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

username = quote_plus(os.getenv("MONGO_USER"))
password = quote_plus(os.getenv("MONGO_PASSWORD"))

client = MongoClient(f"mongodb+srv://{username}:{password}@cluster0.hbzcx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["chatbotDB"]
users_collection = db["users"]
chat_history_collection = db["chat_history"]
otp_collection = db["otp_codes"]

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("models/gemini-1.5-flash")


SECRET_KEY = os.getenv("SECRET_KEY")

ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login/")

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Model cho Users
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "user"

class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    role: str | None = None

# Model cho Login
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Model cho OTP Verification
class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

# Model cho Chat History
class ChatHistoryCreate(BaseModel):
    userID: str
    message: str
    is_from_user: bool

class ChatHistoryUpdate(BaseModel):
    message: str | None = None
    is_from_user: bool | None = None

# Model cho Chat Request
class ChatRequest(BaseModel):
    userID: str
    message: str

# Hàm tạo OTP
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Hàm gửi email OTP
def send_otp_email(email: str, otp: str):
    try:
        msg = MIMEText(f"Your OTP code is: {otp}. It expires in 10 minutes.")
        msg['Subject'] = 'Your OTP for Registration'
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = email

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"OTP sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send OTP email")

# Hàm hash password
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Hàm kiểm tra password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Hàm tạo token JWT
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Hàm xác thực token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# API Gửi OTP cho đăng ký
@app.post("/register/send-otp/")
async def send_otp(user: UserCreate):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    otp = generate_otp()
    otp_data = {
        "email": user.email,
        "otp": otp,
        "password": hash_password(user.password),
        "role": user.role,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(minutes=10)
    }
    otp_collection.insert_one(otp_data)
    send_otp_email(user.email, otp)
    return {"message": "OTP sent to your email"}

# API Xác thực OTP và hoàn tất đăng ký
@app.post("/register/verify-otp/")
async def verify_otp(otp_verify: OTPVerify):
    otp_doc = otp_collection.find_one({"email": otp_verify.email, "otp": otp_verify.otp})
    if not otp_doc:
        raise HTTPException(status_code=400, detail="Invalid OTP or email")
    
    if datetime.utcnow() > otp_doc["expires_at"]:
        otp_collection.delete_one({"_id": otp_doc["_id"]})
        raise HTTPException(status_code=400, detail="OTP has expired")
    
    user_data = {
        "email": otp_doc["email"],
        "password": otp_doc["password"],
        "role": otp_doc["role"],
        "createdAt": datetime.utcnow()
    }
    result = users_collection.insert_one(user_data)
    otp_collection.delete_one({"_id": otp_doc["_id"]})
    return {"id": str(result.inserted_id), "email": user_data["email"], "role": user_data["role"], "message": "User registered successfully"}

# API Đăng nhập (Login)
@app.post("/login/")
async def login_user(user: UserLogin):
    db_user = users_collection.find_one({"email": user.email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token({"sub": str(db_user["_id"])})
    return {
        "id": str(db_user["_id"]),
        "email": db_user["email"],
        "role": db_user["role"],
        "access_token": access_token,
        "message": "Login successful"
    }

# API Đăng xuất (Logout)
@app.post("/logout/")
async def logout_user(token: str = Depends(oauth2_scheme)):
    return {"message": "Logout successful"}

# API cho Users
@app.put("/users/{user_id}")
async def update_user(user_id: str, user: UserUpdate, current_user: dict = Depends(get_current_user)):
    if str(current_user["_id"]) != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user")
    update_data = {}
    if user.email:
        if user.email != current_user["email"]:
            if users_collection.find_one({"email": user.email}):
                raise HTTPException(status_code=400, detail="Email already exists")
        update_data["email"] = user.email
    if user.password:
        update_data["password"] = hash_password(user.password)
    if user.role:
        update_data["role"] = user.role

    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    result = users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User updated successfully"}

@app.delete("/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    if str(current_user["_id"]) != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this user")
    result = users_collection.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}

# API cho Chat History
@app.post("/chat_history/")
async def create_chat_history(chat: ChatHistoryCreate, current_user: dict = Depends(get_current_user)):
    if str(current_user["_id"]) != chat.userID:
        raise HTTPException(status_code=403, detail="Not authorized to create chat history for this user")
    if not users_collection.find_one({"_id": ObjectId(chat.userID)}):
        raise HTTPException(status_code=404, detail="User not found")
    
    chat_data = {
        "userID": ObjectId(chat.userID),
        "message": chat.message,
        "is_from_user": chat.is_from_user,
        "timestamp": datetime.utcnow()
    }
    result = chat_history_collection.insert_one(chat_data)
    return {"id": str(result.inserted_id), "message": chat.message}

@app.put("/chat_history/{chat_id}")
async def update_chat_history(chat_id: str, chat: ChatHistoryUpdate, current_user: dict = Depends(get_current_user)):
    chat_doc = chat_history_collection.find_one({"_id": ObjectId(chat_id)})
    if not chat_doc or str(chat_doc["userID"]) != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to update this chat history")
    update_data = {}
    if chat.message:
        update_data["message"] = chat.message
    if chat.is_from_user is not None:
        update_data["is_from_user"] = chat.is_from_user

    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    result = chat_history_collection.update_one(
        {"_id": ObjectId(chat_id)},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Chat history not found")
    return {"message": "Chat history updated successfully"}

@app.delete("/chat_history/{chat_id}")
async def delete_chat_history(chat_id: str, current_user: dict = Depends(get_current_user)):
    chat_doc = chat_history_collection.find_one({"_id": ObjectId(chat_id)})
    if not chat_doc or str(chat_doc["userID"]) != str(current_user["_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to delete this chat history")
    result = chat_history_collection.delete_one({"_id": ObjectId(chat_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Chat history not found")
    return {"message": "Chat history deleted successfully"}

# API Lấy lịch sử chat theo user
@app.get("/chat_history/{user_id}")
async def get_chat_history(user_id: str, current_user: dict = Depends(get_current_user)):
    if str(current_user["_id"]) != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this chat history")
    chat_history = list(chat_history_collection.find({"userID": ObjectId(user_id)}))
    return [{"id": str(ch["_id"]), "message": ch["message"], "is_from_user": ch["is_from_user"], "timestamp": ch["timestamp"]} for ch in chat_history]

# API Chatbot
@app.post("/chat/")
async def chat_with_bot(chat_request: ChatRequest, current_user: dict = Depends(get_current_user)):
    if str(current_user["_id"]) != chat_request.userID:
        raise HTTPException(status_code=403, detail="Not authorized to chat for this user")
    if not users_collection.find_one({"_id": ObjectId(chat_request.userID)}):
        raise HTTPException(status_code=404, detail="User not found")

    try:
        response = model.generate_content(chat_request.message)
        bot_reply = response.text
    except Exception as e:
        logger.error(f"Gemini API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error with Gemini API: {str(e)}")

    user_chat_data = {
        "userID": ObjectId(chat_request.userID),
        "message": chat_request.message,
        "is_from_user": True,
        "timestamp": datetime.utcnow()
    }
    user_result = chat_history_collection.insert_one(user_chat_data)

    bot_chat_data = {
        "userID": ObjectId(chat_request.userID),
        "message": bot_reply,
        "is_from_user": False,
        "timestamp": datetime.utcnow()
    }
    bot_result = chat_history_collection.insert_one(bot_chat_data)

    return {
        "user_message_id": str(user_result.inserted_id),
        "bot_reply_id": str(bot_result.inserted_id),
        "user_message": chat_request.message,
        "bot_reply": bot_reply
    }

# Chạy server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)