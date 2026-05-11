"""
Seed demo users for the Dynamic Access Control System.
"""

from models import SessionLocal, User
from sqlalchemy.orm import Session

def create_test_user():
    """Create or update diploma demo users with roles."""
    db = SessionLocal()
    
    try:
        users = [
            {"username": "admin", "password": "admin123", "email": "admin@example.com", "role": "admin"},
            {"username": "employee", "password": "employee123", "email": "employee@example.com", "role": "employee"},
            {"username": "auditor", "password": "auditor123", "email": "auditor@example.com", "role": "auditor"},
        ]
        for payload in users:
            existing_user = db.query(User).filter(User.username == payload["username"]).first()
            if existing_user:
                existing_user.password = payload["password"]
                existing_user.email = payload["email"]
                existing_user.role = payload["role"]
            else:
                db.add(User(**payload))
        db.commit()
        print("Demo users are ready:")
        print("- admin / admin123 (admin)")
        print("- employee / employee123 (employee)")
        print("- auditor / auditor123 (auditor)")
        
    except Exception as e:
        print(f"Error creating user: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_test_user()
