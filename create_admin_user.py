"""
Create or update the default admin user with known credentials
"""
from app import app, db, User

ADMIN_USERNAME='admin'
ADMIN_PASSWORD='admin123'
ADMIN_EMAIL='admin@agromol.com'

with app.app_context():
    u = User.query.filter_by(username=ADMIN_USERNAME).first()
    if not u:
        u = User(username=ADMIN_USERNAME, email=ADMIN_EMAIL, role='admin')
        u.set_password(ADMIN_PASSWORD)
        db.session.add(u)
        db.session.commit()
        print("✓ Admin user created")
    else:
        u.email = ADMIN_EMAIL
        u.role = 'admin'
        u.set_password(ADMIN_PASSWORD)
        db.session.commit()
        print("✓ Admin user updated")
    print(f"Username: {ADMIN_USERNAME}\nPassword: {ADMIN_PASSWORD}")
