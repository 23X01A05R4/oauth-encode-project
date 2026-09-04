# 🔐 Auth + Encode/Decode Project

A full stack web application with user authentication, Google OAuth, and Base64 encode/decode functionality. Built and deployed end-to-end.
 
## 🌐 Live Demo

| Layer | URL |
|---|---|
| Frontend | https://oauth-encode-project.vercel.app |
| Backend API | https://oauth-encode-project.onrender.com/docs |

## 🚀 Features

- ✅ Signup / Login with email and password
- ✅ Login with Google (OAuth 2.0)
- ✅ JWT-based authentication (24hr expiry)
- ✅ Password hashing with bcrypt
- ✅ Base64 Encode and Decode
- ✅ Per-user history saved in database
- ✅ Delete individual or all history
- ✅ Fully deployed on cloud

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, FastAPI |
| Database | MySQL (Railway) |
| Auth | JWT, bcrypt |
| OAuth | Google OAuth 2.0 |
| Deployment | Vercel + Render + Railway |

## 📁 Project Structure
```
project/
├── backend/
│   ├── main.py          # FastAPI backend
│   ├── requirements.txt # Dependencies
│   └── .env             # Environment variables (not uploaded)
├── index.html           # Frontend
├── .gitignore
└── README.md
```

## ⚙️ Local Setup

### 1. Clone the repo
```bash
git clone https://github.com/23X01A05R4/oauth-encode-project.git
cd oauth-encode-project
```

### 2. Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 3. Create `.env` file inside `backend/`
```
SECRET_KEY=your_secret_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
DB_PASSWORD=your_mysql_password
MYSQLHOST=localhost
MYSQLUSER=root
MYSQLPASSWORD=your_mysql_password
MYSQLPORT=3306
MYSQLDATABASE=encode_project
```

### 4. Run backend
```bash
cd backend
python -m uvicorn main:app --reload
```

### 5. Run frontend
Open `index.html` with VS Code Live Server

## 📌 API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | /signup | Register new user | ❌ |
| POST | /login | Login with email/password | ❌ |
| GET | /dashboard | Get logged-in user info | ✅ |
| GET | /auth/google | Google OAuth login | ❌ |
| GET | /auth/google/callback | Google OAuth callback | ❌ |
| POST | /encode | Encode text to Base64 | ✅ |
| POST | /decode | Decode Base64 to text | ✅ |
| GET | /history | Get user history | ✅ |
| DELETE | /history/{id} | Delete one record | ✅ |
| DELETE | /history | Delete all records | ✅ |

## ☁️ Deployment

| Service | Platform | Purpose |
|---|---|---|
| Frontend | Vercel | HTML/CSS/JS hosting |
| Backend | Render | FastAPI server |
| Database | Railway | MySQL database |

## 🔒 Security
- Passwords hashed using bcrypt
- JWT tokens expire in 24 hours
- Credentials stored in `.env` (not pushed to GitHub)
- Google OAuth 2.0 for secure third-party login

## 👨‍💻 Developer
**Mahesh** — B.Tech CSE Student  
Narsimha Reddy Engineering College, Hyderabad
