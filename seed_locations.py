"""
Seed default locations if none exist
"""
from app import app, db, Location

with app.app_context():
    count = db.session.query(Location).count()
    if count == 0:
        db.session.add(Location(name="KUNJIR WADI"))
        db.session.add(Location(name="KALAMB"))
        db.session.commit()
        print("✓ Seeded default locations: KUNJIRWADI, KALAMB")
    else:
        names = ", ".join([l.name for l in Location.query.order_by(Location.name.asc()).all()])
        print(f"Locations already exist ({count}): {names}")
