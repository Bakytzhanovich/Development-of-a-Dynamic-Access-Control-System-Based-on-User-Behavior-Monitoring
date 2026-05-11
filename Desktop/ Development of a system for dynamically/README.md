# Dynamic Access Control System

A web application that monitors user behavior (keystroke dynamics, mouse movement, and session metadata) to dynamically grant, restrict, or block access.

## Features

- **Behavioral Monitoring**: Tracks keystroke dynamics (dwell time, flight time) and mouse movement patterns
- **Risk Engine**: Calculates risk scores based on behavioral deviations from user baseline
- **Dynamic Access Control**: Automatically grants, restricts, or blocks access based on risk assessment
- **JWT Authentication**: Secure token-based authentication
- **Real-time Analysis**: Continuous monitoring and analysis of user behavior

## Tech Stack

- **Backend**: Python (FastAPI)
- **Frontend**: HTML, Tailwind CSS, Vanilla JavaScript
- **Database**: SQLite with SQLAlchemy
- **Authentication**: JWT (JSON Web Tokens)

## Project Structure

```
.
├── main.py              # FastAPI server and API routes
├── auth.py              # JWT-based authentication logic
├── behavior.py          # Risk Engine - behavioral analysis logic
├── models.py            # Database schemas (User, BehavioralProfile, AccessLog)
├── requirements.txt     # Python dependencies
├── templates/           # HTML templates
│   ├── login.html      # Login page
│   ├── dashboard.html  # Main behavioral risk dashboard
│   └── admin_analytics.html # Admin-only security analytics dashboard
└── static/             # Static files
    └── sensor.js       # Behavioral data collection script
```

## Installation

1. **Create and activate a virtual environment**:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Run the application**:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The application will be available at `http://localhost:8000`

## Usage

### Initial Setup

1. The database will be automatically created on first run (`access_control.db`)
2. You'll need to create a user account. You can do this by:
   - Adding a user directly to the database, or
   - Modifying `main.py` to include a registration endpoint

### Demo Credentials

The app auto-seeds demo users on startup:

- admin / admin123
- employee / employee123
- auditor / auditor123

Use admin credentials for security analytics features.

**Note**: In production, implement proper password hashing (e.g., using `bcrypt` or `passlib`).

### How It Works

1. **Login**: User logs in through the login page
2. **Behavioral Baseline**: As the user interacts with the dashboard, the system collects behavioral data:
   - Keystroke dynamics (typing speed, dwell time, flight time)
   - Mouse movement patterns (velocity, linearity)
3. **Risk Assessment**: Every 10 seconds or after 20 keystrokes, the system:
   - Compares current behavior against the user's historical baseline
   - Calculates a risk score based on deviations
4. **Access Control**:
   - **Risk Score < 50**: Access granted
   - **Risk Score 50-70**: Step-up authentication required
   - **Risk Score > 70**: Access denied (403 Forbidden)

## Admin Security Analytics

### Login as Admin

1. Open the login page at http://localhost:8000/login
2. Sign in with admin / admin123

### Open Admin Analytics

1. Use the top navigation button **Admin Analytics** (visible only for admin users), or
2. Open http://localhost:8000/admin/analytics directly

### What the Analytics Page Demonstrates

The admin analytics view is a security operations style dashboard that includes:

- Security overview cards (users, sessions, suspicious activity, trust score)
- Users risk table with role/risk/decision/session state
- Risk trend chart over recent behavioral analysis events
- Security events table from system logs
- User detail panel with baseline vs current behavior deviation
- Admin actions to require step-up auth, lock session, and reset baseline

### Access Control Rules

- ADMIN can access analytics data and actions.
- EMPLOYEE and AUDITOR are redirected away from admin analytics UI.
- Backend analytics APIs are protected with admin-only authorization checks.

### Diploma Topic Relevance

This page supports the diploma objective by demonstrating centralized, real-time, adaptive access governance:

- Continuous behavioral risk monitoring for all users
- Policy decisions tied to role and runtime behavior
- Security event visibility for incident analysis
- Operator-driven response actions (step-up, lock, baseline reset)

## Risk Scoring Algorithm

The risk score is calculated based on:

- **Typing Speed Deviation (>30%)**: +55 points
- **IP Address Change**: +30 points
- **Linear Mouse Movement (Bot-like)**: +80 points

## Simulating Behavior Scenarios

To demonstrate the full chain of the system, a script is provided to simulate different behavioral risk scenarios:

1. Make sure your server is running.
2. In a new terminal, run:
```bash
source .venv/bin/activate
python simulate_behavior.py
```
This script sequentially demonstrates:
- **Normal Behavior**: Regular typing and mouse curves (Score: 0, Access: Full).
- **Suspicious Behavior**: Noticeable typing deviation simulating an imposter (Score: 55, Access: Warning/Step-Up Auth).
- **High-Risk Behavior**: Perfectly linear mouse movements simulating a bot (Score: 80, Access: Denied).

## API Endpoints

- `GET /` - Root endpoint (redirects to login)
- `GET /login` - Login page
- `POST /api/login` - Authenticate user and get JWT token
- `GET /dashboard` - Dashboard page (requires authentication)
- `POST /api/analyze-behavior` - Analyze behavioral data and return risk score
- `GET /api/user-profile` - Get user's behavioral profile
- `GET /admin/analytics` - Admin analytics page
- `GET /api/admin/analytics/summary` - Admin security overview metrics
- `GET /api/admin/analytics/users` - Admin users risk table data
- `GET /api/admin/analytics/risk-trend` - Admin risk trend points
- `GET /api/admin/analytics/events` - Admin security events feed
- `GET /api/admin/analytics/users/{id}` - Admin user detail panel data
- `POST /api/admin/analytics/actions` - Admin response actions on user sessions

## Security Notes

⚠️ **Important**: This is a demonstration project. For production use:

1. **Change the SECRET_KEY** in `auth.py` to a strong, randomly generated key
2. **Implement password hashing** (use `bcrypt` or `passlib`)
3. **Use HTTPS** in production
4. **Add rate limiting** to prevent abuse
5. **Implement proper MFA** for step-up authentication
6. **Add input validation** and sanitization
7. **Use environment variables** for sensitive configuration
8. **Implement proper logging** and monitoring

## Development

### Adding a User (Quick Test)

You can add a test user by running this Python script:

```python
from models import SessionLocal, User
from sqlalchemy.orm import Session

db = SessionLocal()
user = User(username="admin", password="admin123", email="admin@example.com")
db.add(user)
db.commit()
db.close()
```

## License

This project is for educational/demonstration purposes.
