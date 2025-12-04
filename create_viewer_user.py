"""
Script to create a viewer user for testing the role-based system
Run this script to add a viewer user to the database
"""
from app import app, db, User

with app.app_context():
    # Check if viewer user already exists
    existing_viewer = User.query.filter_by(username='viewer').first()
    
    if existing_viewer:
        print("Viewer user already exists!")
        print(f"Username: {existing_viewer.username}")
        print(f"Email: {existing_viewer.email}")
        print(f"Role: {existing_viewer.role}")
    else:
        # Create viewer user
        viewer = User(
            username='viewer',
            email='viewer@agromol.com',
            role='viewer'
        )
        viewer.set_password('viewer123')
        db.session.add(viewer)
        db.session.commit()
        
        print("✓ Viewer user created successfully!")
        print(f"Username: viewer")
        print(f"Password: viewer123")
        print(f"Email: viewer@agromol.com")
        print(f"Role: viewer")
