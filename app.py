from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import List
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, func, text
from sqlalchemy.orm import relationship
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Configure database URI with sensible defaults for local and Vercel
db_uri = os.getenv("DATABASE_URL")
if not db_uri:
    # On Vercel, the filesystem is read-only except for /tmp; use that for ephemeral SQLite
    if os.getenv("VERCEL") or os.getenv("VERCEL_ENV"):
        db_uri = "sqlite:////tmp/agromol.db"
    else:
        db_uri = "sqlite:///agromol.db"
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["WTF_CSRF_TIME_LIMIT"] = None

# Allow disabling CSRF validation via env var (useful for some hosting setups like Vercel)
_disable_csrf = os.getenv("DISABLE_CSRF", "").lower() in {"1", "true", "yes"}
app.config["WTF_CSRF_ENABLED"] = not _disable_csrf

csrf = CSRFProtect(app)

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# Models
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')  # 'admin' or 'viewer'
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self) -> bool:
        return self.role == 'admin'
    
    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()


class OTPCode(db.Model):
    __tablename__ = "otp_codes"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = relationship("User", backref="otp_codes")


class Item(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    unit = db.Column(db.String(32), nullable=False, default="kg")
    tax_rate = db.Column(db.Numeric(5, 2), nullable=False, default=Decimal("0.00"))
    unit_price = db.Column(db.Numeric(10, 2), nullable=False, default=Decimal("0.00"))
    # current_stock = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000")) # Managed by stock entries
    active = db.Column(db.Boolean, nullable=False, default=True)
    # Category: fresh, processed, frozen, packaging
    category = db.Column(db.String(16), nullable=False, default="fresh")
    # Base quantity captured at creation (weight)
    quantity = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000"))
    hsn_sac = db.Column(db.String(20), nullable=True)

    stock_entries = relationship("StockEntry", back_populates="item", cascade="all, delete-orphan")

    @property
    def current_stock(self) -> Decimal:
        return self.get_stock_by_location("all")

    def get_stock_by_location(self, location: str) -> Decimal:
        """Return stock for this item at a given location or across all locations.

        Stock is always computed from StockEntry records and is independent of unit price.
        We also clamp at zero so it never shows as negative even if deliveries exceed
        recorded incoming stock.
        """
        query = db.session.query(func.sum(StockEntry.change_qty)).filter(StockEntry.item_id == self.id)
        if location != "all":
            query = query.filter(StockEntry.location_id == location)
        total_stock = query.scalar() or Decimal("0.000")
        total_stock = total_stock.quantize(Decimal("0.001"))
        if total_stock < Decimal("0.000"):
            total_stock = Decimal("0.000")
        return total_stock


class StockEntry(db.Model):
    __tablename__ = "stock_entries"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"), nullable=False)
    entry_date = db.Column(db.Date, nullable=False, default=date.today)
    change_qty = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000"))
    note = db.Column(db.String(255))
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=True)

    item = relationship("Item", back_populates="stock_entries")
    location_rel = relationship("Location", back_populates="stock_entries")


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(160), nullable=False)
    customer_address = db.Column(db.String(255), nullable=True)
    # New fields for company details
    company_name = db.Column(db.String(160), nullable=True)
    company_location = db.Column(db.String(160), nullable=True)
    dispatch_location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=True)

    status = db.Column(db.String(20), nullable=False, default="PENDING")  # PENDING, DELIVERED, CANCELLED
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Invoice and tax fields
    invoice_number = db.Column(db.String(40), nullable=True)
    invoice_date = db.Column(db.Date, nullable=True)
    customer_gstin = db.Column(db.String(20), nullable=True)

    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")
    delivery = relationship("Delivery", back_populates="order", uselist=False, cascade="all, delete-orphan")


class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"), nullable=False)

    item_name = db.Column(db.String(120), nullable=False)
    unit = db.Column(db.String(32), nullable=False)

    qty_ordered = db.Column(db.Numeric(12, 3), nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    tax_rate = db.Column(db.Numeric(5, 2), nullable=False)

    # Packet-based ordering metadata (optional)
    packet_weight = db.Column(db.Numeric(12, 3), nullable=True)  # weight per packet in kg (for kg items)
    packet_unit = db.Column(db.String(8), nullable=True)  # 'g' or 'kg' as provided at input (for reference)
    packets_count = db.Column(db.Integer, nullable=True)
    location_id = db.Column(db.Integer, db.ForeignKey("locations.id"), nullable=True)
    hsn_sac = db.Column(db.String(20), nullable=True)

    order = relationship("Order", back_populates="items")
    item = relationship("Item")


class Delivery(db.Model):
    __tablename__ = "deliveries"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), unique=True, nullable=False)
    delivery_date = db.Column(db.Date, nullable=False, default=date.today)

    total_accepted_qty = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000"))
    total_rejected_qty = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000"))
    overall_mismatch_reason = db.Column(db.String(255))

    order = relationship("Order", back_populates="delivery")
    lines = relationship("DeliveryItem", back_populates="delivery", cascade="all, delete-orphan")


class DeliveryItem(db.Model):
    __tablename__ = "delivery_items"

    id = db.Column(db.Integer, primary_key=True)
    delivery_id = db.Column(db.Integer, db.ForeignKey("deliveries.id"), nullable=False)
    order_item_id = db.Column(db.Integer, db.ForeignKey("order_items.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"), nullable=False)

    qty_delivered = db.Column(db.Numeric(12, 3), nullable=False)
    qty_accepted = db.Column(db.Numeric(12, 3), nullable=False)
    qty_rejected = db.Column(db.Numeric(12, 3), nullable=False)

    mismatch_reason = db.Column(db.String(255))

    delivery = relationship("Delivery", back_populates="lines")
    order_item = relationship("OrderItem")
    item = relationship("Item")

    __table_args__ = (
        CheckConstraint("qty_delivered = qty_accepted + qty_rejected", name="ck_qty_match"),
    )


class Location(db.Model):
    __tablename__ = "locations"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    stock_entries = relationship("StockEntry", back_populates="location_rel")


class PackagingMaterial(db.Model):
    __tablename__ = "packaging_materials"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    unit = db.Column(db.String(32), nullable=False, default="pcs") # e.g., pcs, kg, m
    current_stock = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000"))
    active = db.Column(db.Boolean, nullable=False, default=True)

    packaging_stock_entries = relationship("PackagingStockEntry", back_populates="packaging_material", cascade="all, delete-orphan")


class PackagingStockEntry(db.Model):
    __tablename__ = "packaging_stock_entries"

    id = db.Column(db.Integer, primary_key=True)
    packaging_material_id = db.Column(db.Integer, db.ForeignKey("packaging_materials.id"), nullable=False)
    entry_date = db.Column(db.Date, nullable=False, default=date.today)
    change_qty = db.Column(db.Numeric(12, 3), nullable=False, default=Decimal("0.000"))
    note = db.Column(db.String(255))

    packaging_material = relationship("PackagingMaterial", back_populates="packaging_stock_entries")


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def generate_otp() -> str:
    """Generate a 6-digit OTP"""
    return str(secrets.randbelow(900000) + 100000)


def send_otp_email(email: str, otp: str) -> bool:
    """Send OTP via email"""
    try:
        # Email configuration - you should set these as environment variables
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_username = os.getenv("SMTP_USERNAME", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        
        if not smtp_username or not smtp_password:
            print(f"OTP for {email}: {otp}")  # Fallback to console for development
            return True
        
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = email
        msg['Subject'] = "Agromol Login OTP"
        
        body = f"""
        Your login OTP for Agromol is: {otp}
        
        This code will expire in 10 minutes.
        If you didn't request this OTP, please ignore this email.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        text = msg.as_string()
        server.sendmail(smtp_username, email, text)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        print(f"OTP for {email}: {otp}")  # Fallback to console
        return True


def admin_required(f):
    """Decorator to require admin role"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin():
            flash("Access denied. Admin privileges required.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def viewer_or_admin_required(f):
    """Decorator to require viewer or admin role (for viewing data)"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_brand():
    return {
        "brand_name": os.getenv("BRAND_NAME", ""),
        "brand_logo_url": os.getenv("BRAND_LOGO_URL", url_for("static", filename="logo.png")),
    }


@app.template_filter("currency")
def currency_filter(value: Decimal | float | int) -> str:
    try:
        d = Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        d = Decimal("0.00")
    return f"₹{d:.2f}"


def parse_decimal(val: str, default: Decimal = Decimal("0")) -> Decimal:
    try:
        if val is None or val == "":
            return default
        return Decimal(str(val))
    except Exception:
        return default


def get_form_list(base: str) -> list[str]:
    """Return list values for a field, supporting both `name` and `name[]`."""
    values = request.form.getlist(base)
    if values:
        return values
    return request.form.getlist(f"{base}[]")


def ensure_columns():
    """Lightweight migration to add new columns if the DB already exists.
    SQLite supports ADD COLUMN, which is sufficient for our optional fields.
    """
    try:
        # users table may not exist in old DBs
        db.create_all()

        # users table: email, role, created_at, last_login
        cols = db.session.execute(text("PRAGMA table_info(users)")).fetchall()
        existing = {row[1] for row in cols}
        if "email" not in existing:
            db.session.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(120)"))
        if "role" not in existing:
            db.session.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'viewer' NOT NULL"))
        if "created_at" not in existing:
            db.session.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME"))
        if "last_login" not in existing:
            db.session.execute(text("ALTER TABLE users ADD COLUMN last_login DATETIME"))

        # orders: company_name, company_location
        cols = db.session.execute(text("PRAGMA table_info(orders)")).fetchall()
        existing = {row[1] for row in cols}
        if "company_name" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN company_name VARCHAR(160)"))
        if "company_location" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN company_location VARCHAR(160)"))
        if "dispatch_location_id" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN dispatch_location_id INTEGER"))

        # order_items: packet_weight, packet_unit, packets_count
        cols = db.session.execute(text("PRAGMA table_info(order_items)")).fetchall()
        existing = {row[1] for row in cols}
        if "packet_weight" not in existing:
            db.session.execute(text("ALTER TABLE order_items ADD COLUMN packet_weight NUMERIC"))
        if "packet_unit" not in existing:
            db.session.execute(text("ALTER TABLE order_items ADD COLUMN packet_unit VARCHAR(8)"))
        if "packets_count" not in existing:
            db.session.execute(text("ALTER TABLE order_items ADD COLUMN packets_count INTEGER"))
        if "location_id" not in existing:
            db.session.execute(text("ALTER TABLE order_items ADD COLUMN location_id INTEGER"))
        if "hsn_sac" not in existing:
            db.session.execute(text("ALTER TABLE order_items ADD COLUMN hsn_sac VARCHAR(20)"))

        # items: category
        cols = db.session.execute(text("PRAGMA table_info(items)")).fetchall()
        existing = {row[1] for row in cols}
        if "category" not in existing:
            db.session.execute(text("ALTER TABLE items ADD COLUMN category VARCHAR(16) DEFAULT 'fresh' NOT NULL"))
        if "quantity" not in existing:
            db.session.execute(text("ALTER TABLE items ADD COLUMN quantity NUMERIC DEFAULT 0 NOT NULL"))
        if "hsn_sac" not in existing:
            db.session.execute(text("ALTER TABLE items ADD COLUMN hsn_sac VARCHAR(20)"))
        # Remove current_stock column if it exists, as it's now managed by StockEntry
        if "current_stock" in existing:
            # SQLite does not support dropping columns directly if not empty. 
            # A more robust migration would involve: 
            # 1. Renaming the table 
            # 2. Creating a new table without the column 
            # 3. Copying data
            # For simplicity, we'll try to drop, but it might fail on existing data.
            # For development, manually dropping the column or recreating the db might be easier.
            # db.session.execute(text("ALTER TABLE items DROP COLUMN current_stock"))
            pass # Placeholder, manual intervention or full migration needed for production

        # deliveries: overall_mismatch_reason
        cols = db.session.execute(text("PRAGMA table_info(deliveries)")).fetchall()
        existing = {row[1] for row in cols}
        if "overall_mismatch_reason" not in existing:
            db.session.execute(text("ALTER TABLE deliveries ADD COLUMN overall_mismatch_reason VARCHAR(255)"))

        # stock_entries: location_id
        cols = db.session.execute(text("PRAGMA table_info(stock_entries)")).fetchall()
        existing = {row[1] for row in cols}
        if "location_id" not in existing:
            db.session.execute(text("ALTER TABLE stock_entries ADD COLUMN location_id INTEGER"))

        # locations: name
        cols = db.session.execute(text("PRAGMA table_info(locations)")).fetchall()
        existing = {row[1] for row in cols}
        if "name" not in existing:
            db.session.execute(text("ALTER TABLE locations ADD COLUMN name VARCHAR(80) UNIQUE NOT NULL"))

        # orders: invoice_number, invoice_date, customer_gstin
        cols = db.session.execute(text("PRAGMA table_info(orders)")).fetchall()
        existing = {row[1] for row in cols}
        if "invoice_number" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN invoice_number VARCHAR(40)"))
        if "invoice_date" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN invoice_date DATE"))
        if "customer_gstin" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN customer_gstin VARCHAR(20)"))
        if "dispatch_location_id" not in existing:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN dispatch_location_id INTEGER"))

        # packaging_materials: name, unit, current_stock, active
        cols = db.session.execute(text("PRAGMA table_info(packaging_materials)")).fetchall()
        existing = {row[1] for row in cols}
        if "name" not in existing:
            db.session.execute(text("ALTER TABLE packaging_materials ADD COLUMN name VARCHAR(120) UNIQUE NOT NULL"))
        if "unit" not in existing:
            db.session.execute(text("ALTER TABLE packaging_materials ADD COLUMN unit VARCHAR(32) DEFAULT 'pcs' NOT NULL"))
        if "current_stock" not in existing:
            db.session.execute(text("ALTER TABLE packaging_materials ADD COLUMN current_stock NUMERIC DEFAULT 0.000 NOT NULL"))
        if "active" not in existing:
            db.session.execute(text("ALTER TABLE packaging_materials ADD COLUMN active BOOLEAN DEFAULT TRUE NOT NULL"))

        # packaging_stock_entries: packaging_material_id, entry_date, change_qty, note
        cols = db.session.execute(text("PRAGMA table_info(packaging_stock_entries)")).fetchall()
        existing = {row[1] for row in cols}
        if "packaging_material_id" not in existing:
            db.session.execute(text("ALTER TABLE packaging_stock_entries ADD COLUMN packaging_material_id INTEGER NOT NULL"))
        if "entry_date" not in existing:
            db.session.execute(text("ALTER TABLE packaging_stock_entries ADD COLUMN entry_date DATE NOT NULL"))
        if "change_qty" not in existing:
            db.session.execute(text("ALTER TABLE packaging_stock_entries ADD COLUMN change_qty NUMERIC DEFAULT 0.000 NOT NULL"))
        if "note" not in existing:
            db.session.execute(text("ALTER TABLE packaging_stock_entries ADD COLUMN note VARCHAR(255)"))

        # Optionally seed default locations only if explicitly enabled via env var.
        # By default, no locations are created so the user can define their own.
        seed_flag = os.getenv("SEED_DEFAULT_LOCATIONS", "").lower()
        if seed_flag in {"1", "true", "yes"} and db.session.query(Location).count() == 0:
            db.session.add(Location(name="Main Warehouse"))
            db.session.add(Location(name="Secondary Storage"))
            db.session.commit()
    except Exception:
        db.session.rollback()


def seed_admin():
    try:
        if db.session.query(User).count() == 0:
            username = os.getenv("ADMIN_USERNAME", "admin")
            password = os.getenv("ADMIN_PASSWORD", "admin123")
            email = os.getenv("ADMIN_EMAIL", "admin@agromol.com")
            u = User(
                username=username,
                email=email,
                role="admin"
            )
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            print(f"Initial admin user created: username='{username}', password='{password}'")
            print("IMPORTANT: Change the admin password immediately!")
    except Exception:
        db.session.rollback()


@app.before_request
def ensure_db():
    # Create tables on first request; then ensure new columns exist (migration-lite)
    db.create_all()
    try:
        # Only run SQLite-specific lightweight migrations on SQLite
        if db.engine.url.drivername.startswith("sqlite"):
            ensure_columns()
    except Exception:
        # Avoid failing requests in serverless/non-sqlite environments
        db.session.rollback()
    seed_admin()


@app.route("/")
@login_required
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
@csrf.exempt  # CSRF exempt for GET; POST uses token from the form
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            # All users can login directly
            login_user(user)
            user.update_last_login()
            flash("Logged in successfully", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard"))
        
        flash("Invalid credentials", "error")
        return redirect(url_for("login"))
    
    return render_template("login.html")


@app.route("/verify-otp/<int:user_id>", methods=["GET", "POST"])
@csrf.exempt
def verify_otp(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        
        # Find valid OTP
        otp_record = OTPCode.query.filter_by(
            user_id=user_id,
            code=otp_code,
            used=False
        ).filter(OTPCode.expires_at > datetime.utcnow()).first()
        
        if otp_record:
            # Mark OTP as used
            otp_record.used = True
            db.session.commit()
            
            # Login the user
            login_user(user)
            user.update_last_login()
            flash("OTP verified successfully. Logged in.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired OTP", "error")
            return redirect(url_for("verify_otp", user_id=user_id))
    
    return render_template("verify_otp.html", user=user)


@app.route("/register", methods=["GET", "POST"])
@csrf.exempt
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not username or not email or not password:
            flash("All fields are required", "error")
            return redirect(url_for("register"))
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return redirect(url_for("register"))
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "error")
            return redirect(url_for("register"))
        
        # Create new user (default role is 'viewer')
        user = User(
            username=username,
            email=email,
            role='viewer'  # Only admin can create other admins
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash("Registration successful. You can now login.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))


@app.route("/users")
@login_required
@admin_required
def users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=users)


@app.route("/users/new", methods=["GET", "POST"])
@login_required
@admin_required
def user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")
        
        if not username or not email or not password:
            flash("All fields are required", "error")
            return redirect(url_for("user_new"))
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return redirect(url_for("user_new"))
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "error")
            return redirect(url_for("user_new"))
        
        user = User(
            username=username,
            email=email,
            role=role
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash(f"User '{username}' created successfully", "success")
        return redirect(url_for("users_list"))
    
    return render_template("user_new.html")


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == "POST":
        user.username = request.form.get("username", "").strip()
        user.email = request.form.get("email", "").strip()
        user.role = request.form.get("role", "viewer")
        
        password = request.form.get("password", "")
        if password:
            user.set_password(password)
        
        db.session.commit()
        flash(f"User '{user.username}' updated successfully", "success")
        return redirect(url_for("users_list"))
    
    return render_template("user_edit.html", user=user)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash("You cannot delete your own account", "error")
        return redirect(url_for("users_list"))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User '{username}' deleted successfully", "success")
    return redirect(url_for("users_list"))


@app.route("/dashboard")
@login_required
@viewer_or_admin_required
def dashboard():
    # Optional filter by category
    selected_category = request.args.get("category", "all").lower()
    q = Item.query
    if selected_category in {"fresh", "processed", "frozen"}:
        q = q.filter(Item.category == selected_category)
    items = q.order_by(Item.name.asc()).all()

    # Fetch stock for each item by location
    locations = Location.query.order_by(Location.name.asc()).all()
    item_stocks_by_location = {}
    for item in items:
        item_stocks_by_location[item.id] = {loc.id: item.get_stock_by_location(loc.id) for loc in locations}

    # Fetch packaging materials
    packaging_materials = PackagingMaterial.query.filter_by(active=True).order_by(PackagingMaterial.name.asc()).all()

    order_counts = (
        db.session.query(Order.status, func.count(Order.id)).group_by(Order.status).all()
    )
    counts = {status: count for status, count in order_counts}

    today = date.today()
    today_delivery = (
        db.session.query(
            func.coalesce(func.sum(Delivery.total_accepted_qty), 0),
            func.coalesce(func.sum(Delivery.total_rejected_qty), 0),
        )
        .filter(Delivery.delivery_date == today)
        .one()
    )

    today_item_totals = (
        db.session.query(
            Item.name.label("name"),
            func.coalesce(func.sum(DeliveryItem.qty_accepted), 0).label("accepted"),
            func.coalesce(func.sum(DeliveryItem.qty_rejected), 0).label("rejected"),
        )
        .join(DeliveryItem, DeliveryItem.item_id == Item.id)
        .join(Delivery, DeliveryItem.delivery_id == Delivery.id)
        .filter(Delivery.delivery_date == today)
        .group_by(Item.id)
        .order_by(Item.name.asc())
        .all()
    )

    return render_template(
        "dashboard.html",
        items=items,
        counts=counts,
        today=today,
        today_accepted=today_delivery[0],
        today_rejected=today_delivery[1],
        selected_category=selected_category,
        today_item_totals=today_item_totals,
        locations=locations,
        item_stocks_by_location=item_stocks_by_location,
        packaging_materials=packaging_materials,
    )


@app.route("/items", methods=["GET", "POST"])
@login_required
@viewer_or_admin_required
def items_view():
    if request.method == "POST":
        if not current_user.is_admin():
            flash("Only admins can add/edit items", "error")
            return redirect(url_for("items_view"))
        name = request.form.get("name", "").strip()
        unit = request.form.get("unit", "kg").strip().lower() or "kg"
        if unit not in {"kg", "pcs"}:
            unit = "kg"
        tax_rate = parse_decimal(request.form.get("tax_rate"), Decimal("0"))
        unit_price = parse_decimal(request.form.get("unit_price"), Decimal("0"))
        initial_stock = parse_decimal(request.form.get("initial_stock"), Decimal("0"))
        quantity = parse_decimal(request.form.get("quantity"), Decimal("0"))
        category = request.form.get("category", "fresh").strip().lower()
        if category not in {"fresh", "processed", "frozen", "packaging"}:
            category = "fresh"
        hsn_sac = request.form.get("hsn_sac", "").strip()

        if not name:
            flash("Item name is required", "error")
            return redirect(url_for("items_view"))

        existing_item = Item.query.filter_by(name=name).first()
        if existing_item:
            item = existing_item
            # Update existing item's core properties if submitted (e.g., if editing an existing item from this form)
            item.unit = unit
            item.tax_rate = tax_rate
            item.unit_price = unit_price
            item.category = category
            item.hsn_sac = hsn_sac
            flash(f"Item '{name}' already exists. Updating its properties and stock.", "info")
        else:
            item = Item(
            name=name,
            unit=unit,
            tax_rate=tax_rate,
            unit_price=unit_price,
                quantity=quantity, # For new items, this is the initial base quantity
            category=category,
                hsn_sac=hsn_sac, # Set HSN/SAC for new item
        )
        db.session.add(item)
        db.session.flush() # Ensure item.id is available for StockEntry
        flash("New item added.", "success")

        # Calculate total initial stock to be added/updated for the item
        total_initial = (quantity + initial_stock).quantize(Decimal("0.001"))

        # Only create a StockEntry if there's an actual change in stock to be recorded
        if total_initial != 0:
            location_id = int(request.form.get("initial_stock_location_id", 1))
            db.session.add(
                StockEntry(
                    item_id=item.id,
                    entry_date=date.today(),
                    change_qty=total_initial,
                    note="Initial quantity + initial stock",
                    location_id=location_id,
                )
            )
        db.session.commit()
        return redirect(url_for("items_view"))

    items = Item.query.order_by(Item.name.asc()).all()
    locations = Location.query.order_by(Location.name.asc()).all()
    item_stocks_by_location = {}
    for item in items:
        item_stocks_by_location[item.id] = {loc.id: item.get_stock_by_location(loc.id) for loc in locations}
    return render_template("items.html", items=items, locations=locations, item_stocks_by_location=item_stocks_by_location)


@app.route("/items/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def item_edit(item_id: int):
    item = Item.query.get_or_404(item_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        unit = request.form.get("unit", item.unit).strip().lower()
        if unit not in {"kg", "pcs"}:
            unit = item.unit
        tax_rate = parse_decimal(request.form.get("tax_rate"), Decimal("0"))
        unit_price = parse_decimal(request.form.get("unit_price"), Decimal("0"))
        category = request.form.get("category", item.category).strip().lower()
        quantity = parse_decimal(request.form.get("quantity"), item.quantity)
        if category not in {"fresh", "processed", "frozen", "packaging"}:
            category = item.category
        hsn_sac = request.form.get("hsn_sac", "").strip()

        if not name:
            flash("Item name is required", "error")
            return redirect(url_for("item_edit", item_id=item.id))
        # ensure unique name if changed
        # if name != item.name and Item.query.filter_by(name=name).first():
        #     flash("Another item already has this name", "error")
        #     return redirect(url_for("item_edit", item_id=item.id))
        item.name = name
        item.unit = unit
        item.tax_rate = tax_rate
        item.unit_price = unit_price
        item.category = category
        item.hsn_sac = hsn_sac # Update HSN/SAC for existing item
        # Recalculate current stock to reflect new base quantity delta
        try:
            existing_log = Decimal(item.quantity or 0)
        except Exception:
            existing_log = Decimal("0")
        delta = (quantity - existing_log).quantize(Decimal("0.001"))
        if delta != 0:
            # item.current_stock = (Decimal(item.current_stock) + delta).quantize(Decimal("0.001")) # Managed by stock entries
            location_id = int(request.form.get("stock_update_location_id", 1))
            db.session.add(StockEntry(item_id=item.id, entry_date=date.today(), change_qty=delta, note="Quantity edit", location_id=location_id)) # Assuming location_1 for manual updates
        item.quantity = quantity
        db.session.commit()
        flash("Item updated", "success")
        return redirect(url_for("items_view"))
    locations = Location.query.order_by(Location.name.asc()).all()
    return render_template("item_edit.html", item=item, locations=locations)


@app.route("/items/<int:item_id>/delete", methods=["POST"])
@login_required
@admin_required
def item_delete(item_id: int):
    item = Item.query.get_or_404(item_id)
    # prevent delete if used in orders
    if OrderItem.query.filter_by(item_id=item.id).count() > 0:
        flash("Cannot delete item referenced by orders", "error")
        return redirect(url_for("items_view"))
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted", "success")
    return redirect(url_for("items_view"))


@app.route("/stock/update", methods=["GET", "POST"])
@login_required
@viewer_or_admin_required
def stock_update():
    items = Item.query.order_by(Item.name.asc()).all()

    if request.method == "POST":
        if not current_user.is_admin():
            flash("Only admins can update stock", "error")
            return redirect(url_for("stock_update"))
        entry_dt = request.form.get("entry_date")
        try:
            entry_date_parsed = datetime.strptime(entry_dt, "%Y-%m-%d").date() if entry_dt else date.today()
        except Exception:
            entry_date_parsed = date.today()

        any_changes = False
        for item in items:
            delta_str = request.form.get(f"delta_{item.id}")
            delta = parse_decimal(delta_str, Decimal("0"))
            if delta != 0:
                any_changes = True
                # item.current_stock = (Decimal(item.current_stock) + delta).quantize(Decimal("0.001")) # Removed, managed by StockEntry
                db.session.add(
                    StockEntry(
                        item_id=item.id,
                        entry_date=entry_date_parsed,
                        change_qty=delta,
                        note="Manual update",
                        location_id=int(request.form.get("location_id", 1)),
                    )
                )
        if any_changes:
            db.session.commit()
            flash("Stock updated", "success")
        else:
            flash("No changes submitted", "info")
        return redirect(url_for("stock_update"))

    locations = Location.query.order_by(Location.name.asc()).all()
    item_stocks_by_location = {}
    for item in items:
        item_stocks_by_location[item.id] = {loc.id: item.get_stock_by_location(loc.id) for loc in locations}

    return render_template("stock_update.html", items=items, today=date.today(), locations=locations, item_stocks_by_location=item_stocks_by_location)


@app.route("/orders", methods=["GET"])
@login_required
@viewer_or_admin_required
def orders_list():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    status_counts = (
        db.session.query(Order.status, func.count(Order.id)).group_by(Order.status).all()
    )
    counts = {status: count for status, count in status_counts}
    return render_template("orders.html", orders=orders, counts=counts)


@app.route("/orders/new", methods=["GET", "POST"])
@login_required
@admin_required
def order_new():
    items = Item.query.filter_by(active=True).order_by(Item.name.asc()).all()
    locations = Location.query.order_by(Location.name.asc()).all()

    if request.method == "POST":
        customer_name = request.form.get("customer_name", "").strip()
        customer_address = request.form.get("customer_address", "").strip()
        company_name = request.form.get("company_name", "").strip() or None
        company_location = request.form.get("company_location", "").strip() or None
        customer_gstin = request.form.get("customer_gstin", "").strip() or None

        if not customer_name:
            flash("Customer name is required", "error")
            return redirect(url_for("order_new"))

        item_ids = get_form_list("item_id")
        item_names = get_form_list("item_name")
        qtys = get_form_list("qty")
        prices = get_form_list("unit_price")
        taxes = get_form_list("tax_rate")
        packet_weights = get_form_list("packet_weight")
        packet_counts = get_form_list("packets_count")
        location_ids = get_form_list("location_id")
        hsn_sacs = get_form_list("hsn_sac")

        selected_lines: List[tuple] = []
        for i in range(len(item_ids)):
            item_id = item_ids[i]
            qty = parse_decimal(request.form.getlist("qty[]")[i], Decimal("0"))
            packets_count = int(request.form.getlist("packets_count[]")[i] or 0)
            packet_weight = parse_decimal(request.form.getlist("packet_weight[]")[i], Decimal("0"))
            location_id = request.form.getlist("location_id[]")[i]
            unit_price = parse_decimal(request.form.getlist("unit_price[]")[i], Decimal("0"))
            tax_rate = parse_decimal(request.form.getlist("tax_rate[]")[i], Decimal("0"))
            hsn_sac = request.form.getlist("hsn_sac[]")[i].strip()

            # Packet metadata stored on the line
            packet_unit_input = "kg"  # our UI uses kg for per-packet weight
            packets_count_input = packets_count

            # Require a valid item id
            if not item_id:
                continue
            itm = Item.query.get(int(item_id))
            if not itm:
                continue

            effective_qty = Decimal("0")
            stored_packet_weight_kg = None

            # 1) If packets_count and packet_weight are provided, use them
            if packets_count > 0 and packet_weight > 0:
                if itm.unit.lower() == "kg":
                    # packet_weight is already in kg
                    weight_kg = packet_weight
                    effective_qty = (weight_kg * Decimal(packets_count)).quantize(Decimal("0.003"))
                    stored_packet_weight_kg = weight_kg
                else:
                    # For non-kg items (e.g. pieces), quantity is number of packets
                    effective_qty = Decimal(packets_count)
                    stored_packet_weight_kg = None
            # 2) Otherwise, fall back to the raw quantity field
            elif qty > 0:
                effective_qty = qty
            else:
                # Nothing ordered on this line
                continue

            if effective_qty <= 0:
                continue

            selected_lines.append(
                (
                    int(item_id),
                    effective_qty,
                    unit_price,
                    tax_rate,
                    stored_packet_weight_kg,
                    packet_unit_input if stored_packet_weight_kg is not None else None,
                    packets_count_input if packets_count_input > 0 else None,
                    int(location_id) if location_id else None,
                    hsn_sac,
                )
            )

        if not selected_lines:
            flash("Add at least one item with a positive quantity or valid packets", "error")
            return redirect(url_for("order_new"))

        order = Order(
            customer_name=customer_name,
            customer_address=customer_address,
            company_name=company_name,
            company_location=company_location,
            customer_gstin=customer_gstin,
            status="PENDING",
            dispatch_location_id=int(request.form.get("dispatch_location_id")) if request.form.get("dispatch_location_id") else None,
        )
        db.session.add(order)
        db.session.flush()

        for (
            item_id,
            qty,
            price,
            tax,
            packet_weight_kg,
            packet_unit_label,
            packets_count_val,
            location_id,
            hsn_sac,
        ) in selected_lines:
            itm = Item.query.get(item_id)
            if not itm:
                continue
            db.session.add(
                OrderItem(
                    order_id=order.id,
                    item_id=itm.id,
                    item_name=itm.name,
                    unit=itm.unit,
                    qty_ordered=qty,
                    unit_price=price if price > 0 else itm.unit_price,
                    tax_rate=tax if tax >= 0 else itm.tax_rate,
                    packet_weight=packet_weight_kg,
                    packet_unit=packet_unit_label,
                    packets_count=packets_count_val,
                    location_id=location_id,
                    hsn_sac=hsn_sac,
                )
            )

        db.session.commit()
        flash("Order created", "success")
        return redirect(url_for("order_detail", order_id=order.id))

    # Build per-item, per-location available stock map for client-side validation
    item_stocks_by_location: Dict[int, Dict[int, float]] = {}
    for it in items:
        loc_map: Dict[int, float] = {}
        for loc in locations:
            try:
                loc_map[loc.id] = float(it.get_stock_by_location(loc.id))
            except Exception:
                loc_map[loc.id] = 0.0
        item_stocks_by_location[it.id] = loc_map

    return render_template("order_new.html", items=items, locations=locations, item_stocks_by_location=item_stocks_by_location)


@app.route("/orders/<int:order_id>")
@app.route("/orders/<int:order_id>/")  # allow trailing slash
@login_required
@viewer_or_admin_required
def order_detail(order_id: int):
    order = Order.query.get_or_404(order_id)
    return render_template("order_detail.html", order=order)


@app.route("/orders/<int:order_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def order_edit(order_id: int):
    order = Order.query.get_or_404(order_id)
    if order.status != "PENDING":
        flash("Only pending orders can be edited", "error")
        return redirect(url_for("order_detail", order_id=order.id))
    items = Item.query.filter_by(active=True).order_by(Item.name.asc()).all()
    locations = Location.query.order_by(Location.name.asc()).all()
    if request.method == "POST":
        order.customer_name = request.form.get("customer_name", order.customer_name).strip() or order.customer_name
        order.customer_address = request.form.get("customer_address", order.customer_address)
        order.company_name = request.form.get("company_name", order.company_name)
        order.company_location = request.form.get("company_location", order.company_location)
        order.customer_gstin = request.form.get("customer_gstin", order.customer_gstin)
        order.dispatch_location_id = int(request.form.get("dispatch_location_id")) if request.form.get("dispatch_location_id") else None

        item_ids = get_form_list("item_id")
        item_names = get_form_list("item_name")
        qtys = get_form_list("qty")
        prices = get_form_list("unit_price")
        taxes = get_form_list("tax_rate")
        packet_weights = get_form_list("packet_weight")
        packet_counts = get_form_list("packets_count")
        location_ids = get_form_list("location_id")
        hsn_sacs = get_form_list("hsn_sac")

        # remove existing lines and rebuild
        for li in list(order.items):
            db.session.delete(li)
        db.session.flush()

        any_line = False
        for i in range(len(item_ids)):
            item_id = item_ids[i]
            qty = parse_decimal(qtys[i], Decimal("0")) if i < len(qtys) else Decimal("0")
            price = parse_decimal(prices[i], Decimal("0")) if i < len(prices) else Decimal("0")
            tax = parse_decimal(taxes[i], Decimal("0")) if i < len(taxes) else Decimal("0")
            packet_weight_input = parse_decimal(packet_weights[i], Decimal("0")) if i < len(packet_weights) else Decimal("0")
            packet_unit = request.form.getlist("packet_unit[]")[i] if i < len(request.form.getlist("packet_unit[]")) else "kg"
            packets_count_input = int(packet_counts[i]) if i < len(packet_counts) and packet_counts[i].isdigit() else 0
            hsn_sac = hsn_sacs[i].strip() if i < len(hsn_sacs) else ""

            itm = None
            if item_id and (qty > 0 or packets_count_input > 0):
                itm = Item.query.get(int(item_id))
            if not itm:
                continue
            effective_qty = qty
            stored_packet_weight_kg = None
            if packet_weight_input > 0 and packets_count_input > 0:
                if itm.unit.lower() == "kg":
                        weight_kg = packet_weight_input / Decimal("1000") if packet_unit == "g" else packet_weight_input
                        effective_qty = (weight_kg * Decimal(packets_count_input)).quantize(Decimal("0.003"))
                        stored_packet_weight_kg = weight_kg
                else:
                    effective_qty = Decimal(packets_count_input)
                    stored_packet_weight_kg = None
                
            if effective_qty <= 0:
                continue
            any_line = True
            db.session.add(
                OrderItem(
                    order_id=order.id,
                    item_id=itm.id,
                    item_name=itm.name,
                    unit=itm.unit,
                    qty_ordered=effective_qty,
                        unit_price=parse_decimal(prices[i], Decimal("0")) if i < len(prices) else itm.unit_price,
                        tax_rate=parse_decimal(taxes[i], Decimal("0")) if i < len(taxes) else itm.tax_rate,
                    packet_weight=stored_packet_weight_kg,
                        packet_unit=packet_unit if stored_packet_weight_kg is not None else None,
                    packets_count=packets_count_input if packets_count_input > 0 else None,
                        location_id=int(location_ids[i]) if i < len(location_ids) else None,
                        hsn_sac=hsn_sac,
                )
            )
        if not any_line:
            flash("Add at least one item", "error")
            return redirect(url_for("order_edit", order_id=order.id))
        db.session.commit()
        flash("Order updated", "success")
        return redirect(url_for("order_detail", order_id=order.id))
    return render_template("order_edit.html", order=order, items=items, locations=locations)


@app.route("/orders/<int:order_id>/delete", methods=["POST"])
@login_required
@admin_required
def order_delete(order_id: int):
    order = Order.query.get_or_404(order_id)
    if order.status != "PENDING":
        flash("Only pending orders can be deleted", "error")
        return redirect(url_for("order_detail", order_id=order.id))
    db.session.delete(order)
    db.session.commit()
    flash("Order deleted", "success")
    return redirect(url_for("orders_list"))


@app.route("/deliveries/new/<int:order_id>", methods=["GET", "POST"])
@app.route("/deliveries/new/<int:order_id>/", methods=["GET", "POST"])  # allow trailing slash
@login_required
@admin_required
def delivery_new(order_id: int):
    order = Order.query.get_or_404(order_id)
    # Allow editing an existing delivery if it exists, even if status is DELIVERED

    if request.method == "POST":
        overall_reason = (request.form.get("overall_reason", "") or "").strip()
        delivered_list = request.form.getlist("qty_delivered")
        accepted_list = request.form.getlist("qty_accepted")
        rejected_list = request.form.getlist("qty_rejected")
        reason_list = request.form.getlist("reason")
        order_item_ids = request.form.getlist("order_item_id")

        if not order_item_ids:
            flash("No items submitted", "error")
            return redirect(url_for("delivery_new", order_id=order.id))

        # Reuse existing delivery if present to avoid UNIQUE(order_id) violation
        delivery = Delivery.query.filter_by(order_id=order.id).first()
        if delivery is None:
            delivery = Delivery(order_id=order.id, delivery_date=date.today())
            db.session.add(delivery)
            db.session.flush()
        else:
            # Clear existing lines to re-record the delivery
            for li in list(delivery.lines):
                db.session.delete(li)
            delivery.delivery_date = date.today()
            delivery.total_accepted_qty = Decimal("0")
            delivery.total_rejected_qty = Decimal("0")
            delivery.overall_mismatch_reason = None

        total_accepted = Decimal("0")
        total_rejected = Decimal("0")

        any_line_mismatch = False
        for idx, oi_id_str in enumerate(order_item_ids):
            oi = OrderItem.query.get(int(oi_id_str))
            if not oi:
                continue

            qty_delivered = parse_decimal(delivered_list[idx], Decimal("0")) if idx < len(delivered_list) else Decimal("0")
            qty_accepted = parse_decimal(accepted_list[idx], Decimal("0")) if idx < len(accepted_list) else Decimal("0")
            qty_rejected = parse_decimal(rejected_list[idx], Decimal("0")) if idx < len(rejected_list) else Decimal("0")
            reason = reason_list[idx].strip() if idx < len(reason_list) else ""

            # Validation: accepted + rejected must equal delivered
            if (qty_accepted + qty_rejected) != qty_delivered:
                db.session.rollback()
                flash(f"Line for {oi.item_name}: accepted + rejected must equal delivered", "error")
                return redirect(url_for("delivery_new", order_id=order.id))

            # If mismatch between ordered and delivered/accepted, require reason(s)
            if (qty_delivered != oi.qty_ordered) or (qty_accepted != oi.qty_ordered) or qty_rejected > 0:
                any_line_mismatch = True
                if not reason and not overall_reason:
                    db.session.rollback()
                    flash(f"Line for {oi.item_name}: provide reason (line or overall) for mismatch", "error")
                    return redirect(url_for("delivery_new", order_id=order.id))

            db.session.add(
                DeliveryItem(
                    delivery_id=delivery.id,
                    order_item_id=oi.id,
                    item_id=oi.item_id,
                    qty_delivered=qty_delivered,
                    qty_accepted=qty_accepted,
                    qty_rejected=qty_rejected,
                    mismatch_reason=reason or None,
                )
            )

            # Stock reduces only by accepted quantity; rejected considered returned/undelivered
            item = Item.query.get(oi.item_id)
            if item:
                # item.current_stock = (Decimal(item.current_stock) - qty_accepted).quantize(Decimal("0.001")) # Managed by stock entries
                db.session.add(
                    StockEntry(
                        item_id=item.id,
                        entry_date=date.today(),
                        change_qty=-qty_accepted,
                        note=f"Delivery for Order #{order.id}",
                        location_id=1, # Assuming location_1 for deliveries
                    )
                )

            total_accepted += qty_accepted
            total_rejected += qty_rejected

        delivery.total_accepted_qty = total_accepted
        delivery.total_rejected_qty = total_rejected
        if any_line_mismatch and overall_reason:
            delivery.overall_mismatch_reason = overall_reason

        order.status = "DELIVERED"
        db.session.commit()
        flash("Delivery recorded", "success")
        return redirect(url_for("order_detail", order_id=order.id))

    return render_template("delivery_new.html", order=order)


@app.route("/invoice/<int:order_id>")
@app.route("/invoice/<int:order_id>/")  # allow trailing slash
@login_required
@viewer_or_admin_required
def invoice(order_id: int):
    order = Order.query.get_or_404(order_id)
    if order.status != "DELIVERED" or not order.delivery:
        flash("Invoice available only after delivery", "error")
        return redirect(url_for("order_detail", order_id=order.id))

    # Ensure invoice number/date
    if not order.invoice_number:
        today_str = date.today().strftime("%Y%m%d")
        order.invoice_number = f"INV-{today_str}-{order.id:05d}"
    if not order.invoice_date:
        order.invoice_date = date.today()
    db.session.commit()

    # Build invoice lines from accepted quantities
    inv_lines = []
    subtotal = Decimal("0")
    total_tax = Decimal("0")

    # Map order_item_id -> accepted qty
    accepted_map = {li.order_item_id: li.qty_accepted for li in order.delivery.lines}

    for oi in order.items:
        accepted_qty = Decimal(accepted_map.get(oi.id, Decimal("0")))
        if accepted_qty <= 0:
            continue
        line_amount = (accepted_qty * Decimal(oi.unit_price)).quantize(Decimal("0.01"))
        tax_amount = (line_amount * (Decimal(oi.tax_rate) / Decimal("100"))).quantize(Decimal("0.01"))
        inv_lines.append({
            "item_name": oi.item_name,
            "unit": oi.unit,
            "qty": accepted_qty,
            "unit_price": Decimal(oi.unit_price),
            "amount": line_amount,
            "tax_rate": Decimal(oi.tax_rate),
            "tax_amount": tax_amount,
            "total": (line_amount + tax_amount).quantize(Decimal("0.01")),
            "hsn_sac": oi.hsn_sac or "",
        })
        subtotal += line_amount
        total_tax += tax_amount

    grand_total = (subtotal + total_tax).quantize(Decimal("0.01"))

    # Seller details from environment
    seller = {
        "name": os.getenv("COMPANY_NAME", "Agromol Venture Pvt Ltd"),
        "address": os.getenv("COMPANY_ADDRESS", ""),
        "gstin": os.getenv("COMPANY_GSTIN", ""),
        "state": os.getenv("COMPANY_STATE", ""),
    }

    return render_template(
        "invoice.html",
        order=order,
        lines=inv_lines,
        subtotal=subtotal,
        total_tax=total_tax,
        grand_total=grand_total,
        today=date.today(),
        seller=seller,
    )


@app.route("/invoice/<int:order_id>/pdf")
@login_required
@viewer_or_admin_required
def invoice_pdf(order_id: int):
    order = Order.query.get_or_404(order_id)
    # Reuse the same data as HTML invoice
    if order.status != "DELIVERED" or not order.delivery:
        flash("Invoice available only after delivery", "error")
        return redirect(url_for("order_detail", order_id=order.id))

    # Ensure invoice number/date like HTML route
    if not order.invoice_number:
        today_str = date.today().strftime("%Y%m%d")
        order.invoice_number = f"INV-{today_str}-{order.id:05d}"
    if not order.invoice_date:
        order.invoice_date = date.today()
    db.session.commit()

    # Render HTML
    html = render_template("invoice.html", order=order,
                          lines=[{
                              "item_name": oi.item_name,
                              "unit": oi.unit,
                              "qty": oi.delivery.qty_accepted if order.delivery else oi.qty_ordered,
                              "unit_price": Decimal(oi.unit_price),
                              "amount": Decimal(oi.unit_price) * (oi.delivery.qty_accepted if order.delivery else oi.qty_ordered),
                              "tax_rate": Decimal(oi.tax_rate),
                              "tax_amount": (Decimal(oi.unit_price) * (oi.delivery.qty_accepted if order.delivery else oi.qty_ordered)) * (Decimal(oi.tax_rate)/Decimal("100")),
                              "total": (Decimal(oi.unit_price) * (oi.delivery.qty_accepted if order.delivery else oi.qty_ordered)) * (Decimal("1") + (Decimal(oi.tax_rate)/Decimal("100"))),
                              "hsn_sac": oi.hsn_sac or "",
                          } for oi in order.items if (order.delivery and any(li.order_item_id==oi.id and li.qty_accepted>0 for li in order.delivery.lines)) or True],
                          subtotal=Decimal("0"), total_tax=Decimal("0"), grand_total=Decimal("0"), today=date.today(),
                          seller={
                              "name": os.getenv("COMPANY_NAME", "Agromol Venture Pvt Ltd"),
                              "address": os.getenv("COMPANY_ADDRESS", ""),
                              "gstin": os.getenv("COMPANY_GSTIN", ""),
                              "state": os.getenv("COMPANY_STATE", ""),
                          })

    try:
        import pdfkit
        from io import BytesIO
        from flask import send_file
        options = {"enable-local-file-access": ""}
        pdf_bytes = pdfkit.from_string(html, False, options=options)
        buf = BytesIO(pdf_bytes)
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"invoice_{order.id}.pdf", mimetype="application/pdf")
    except Exception as e:
        flash("PDF generation failed. Please ensure wkhtmltopdf and pdfkit are installed.", "error")
        return redirect(url_for("invoice", order_id=order.id))


# Order status updates and live dashboard API
@app.route("/orders/<int:order_id>/status", methods=["GET", "POST"])
@login_required
@admin_required
def order_status_update(order_id: int):
    order = Order.query.get_or_404(order_id)

    # For GET requests, just redirect back to the order detail instead of 404/405
    if request.method == "GET":
        return redirect(url_for("order_detail", order_id=order.id))

    new_status = request.form.get("status", "").upper()
    allowed = {"PENDING", "PROCESSING", "OUT_FOR_DELIVERY", "DELIVERED", "COMPLETED", "CANCELLED"}
    if new_status not in allowed:
        flash("Invalid status", "error")
        return redirect(url_for("order_detail", order_id=order.id))
    order.status = new_status
    db.session.commit()
    flash("Status updated", "success")
    return redirect(url_for("order_detail", order_id=order.id))


@app.route("/api/dashboard")
@login_required
@viewer_or_admin_required
def api_dashboard():
    status_counts = (
        db.session.query(Order.status, func.count(Order.id)).group_by(Order.status).all()
    )
    counts = {status: count for status, count in status_counts}
    recent = (
        Order.query.order_by(Order.created_at.desc()).limit(5).all()
    )
    today = date.today()
    today_accepted, today_rejected = (
        db.session.query(
            func.coalesce(func.sum(Delivery.total_accepted_qty), 0),
            func.coalesce(func.sum(Delivery.total_rejected_qty), 0),
        )
        .filter(Delivery.delivery_date == today)
        .one()
    )
    per_item = (
        db.session.query(
            Item.name.label("name"),
            func.coalesce(func.sum(DeliveryItem.qty_accepted), 0).label("accepted"),
            func.coalesce(func.sum(DeliveryItem.qty_rejected), 0).label("rejected"),
        )
        .join(DeliveryItem, DeliveryItem.item_id == Item.id)
        .join(Delivery, DeliveryItem.delivery_id == Delivery.id)
        .filter(Delivery.delivery_date == today)
        .group_by(Item.id)
        .order_by(Item.name.asc())
        .all()
    )
    # Fetch stock for each item by location for API
    items = Item.query.order_by(Item.name.asc()).all()
    locations = Location.query.order_by(Location.name.asc()).all()
    item_stocks_by_location = {}
    for item in items:
        item_stocks_by_location[item.id] = {loc.id: item.get_stock_by_location(loc.id) for loc in locations}
    item_prices = {item.id: float(item.unit_price) for item in items}
    item_tax_rates = {item.id: float(item.tax_rate) for item in items}

    # Fetch packaging materials for API
    packaging_materials_api = PackagingMaterial.query.filter_by(active=True).order_by(PackagingMaterial.name.asc()).all()

    return jsonify({
        "counts": counts,
        "today": {
            "accepted": float(today_accepted or 0),
            "rejected": float(today_rejected or 0),
        },
        "today_per_item": [
            {"name": n, "accepted": float(a or 0), "rejected": float(r or 0)}
            for (n, a, r) in per_item
        ],
        "recent": [
            {
                "id": o.id,
                "customer_name": o.customer_name,
                "status": o.status,
                "created_at": o.created_at.isoformat(),
            } for o in recent
        ],
        "locations": [{'id': loc.id, 'name': loc.name} for loc in locations],
        "item_stocks_by_location": {item_id: {loc_id: float(stock) for loc_id, stock in stocks.items()} for item_id, stocks in item_stocks_by_location.items()},
        "item_prices": item_prices,
        "item_tax_rates": item_tax_rates,
        "packaging_materials": [
            {"id": m.id, "name": m.name, "unit": m.unit, "current_stock": float(m.current_stock)}
            for m in packaging_materials_api
        ],
    })


@app.route("/reports/stock_csv")
@login_required
@viewer_or_admin_required
def report_stock_csv():
    items = Item.query.order_by(Item.name.asc()).all()
    locations = Location.query.order_by(Location.name.asc()).all()
    item_stocks_by_location = {item.id: {loc.id: item.get_stock_by_location(loc.id) for loc in locations} for item in items}

    import csv
    from io import StringIO

    si = StringIO()
    cw = csv.writer(si)

    # Add title and generation info
    today_str = date.today().strftime("%Y-%m-%d")
    cw.writerow([f"Current Stock Report - Generated on {today_str}"])
    cw.writerow([""])  # Empty row for spacing

    # Header row
    header = ["Item", "Category", "Unit", "Unit Price", "Total Stock"]
    for loc in locations:
        header.append(f"Stock - {loc.name}")
    cw.writerow(header)

    # Data rows
    for item in items:
        total_stock = sum([item_stocks_by_location[item.id].get(loc.id, Decimal("0.000")) for loc in locations])
        row_values = [item.name, item.category.capitalize(), item.unit, f"{item.unit_price:.2f}", f"{total_stock:.3f}"]
        for loc in locations:
            stock = item_stocks_by_location[item.id].get(loc.id, Decimal("0.000"))
            row_values.append(f"{stock:.3f}")
        cw.writerow(row_values)

    output = si.getvalue()
    from flask import make_response
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=stock_report_{today_str}.csv"
    response.headers["Content-type"] = "text/csv"
    return response


@app.route("/reports/orders_csv")
@login_required
@viewer_or_admin_required
def report_orders_csv():
    orders = Order.query.order_by(Order.created_at.desc()).all()

    import csv
    from io import StringIO

    si = StringIO()
    cw = csv.writer(si)

    # Add title and generation info
    today_str = date.today().strftime("%Y-%m-%d")
    cw.writerow([f"Orders Report - Generated on {today_str}"])
    cw.writerow([""])  # Empty row for spacing

    # Header row
    header = ["Order #", "Customer Name", "Company Name", "Status", "Created Date", "Total Items", "Invoice Number"]
    cw.writerow(header)

    # Data rows
    for order in orders:
        total_items = sum([float(li.qty_ordered) for li in order.items])
        row_values = [
            f"#{order.id}",
            order.customer_name,
            order.company_name or "-",
            order.status,
            order.created_at.strftime("%Y-%m-%d %H:%M"),
            f"{total_items:.3f}",
            order.invoice_number or "-",
        ]
        cw.writerow(row_values)

    output = si.getvalue()
    from flask import make_response
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=orders_report_{today_str}.csv"
    response.headers["Content-type"] = "text/csv"
    return response


# PDF generation utilities
def _pdf_header(c: canvas.Canvas, title: str):
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20*mm, 285*mm, title)
    c.setFont("Helvetica", 9)
    c.drawRightString(200*mm, 285*mm, datetime.now().strftime("Generated %Y-%m-%d %H:%M"))


def _pdf_table_header(c: canvas.Canvas, y: float, cols: list[str]):
    c.setFont("Helvetica-Bold", 10)
    x = 20*mm
    for col, width in cols:
        c.drawString(x, y, col)
        x += width
    return y - 6*mm


def _pdf_table_row(c: canvas.Canvas, y: float, values: list[str], widths: list[float]):
    c.setFont("Helvetica", 10)
    x = 20*mm
    for val, width in zip(values, widths):
        c.drawString(x, y, str(val))
        x += width
    return y - 6*mm


@app.route("/reports/stock/<string:day>")
@login_required
@viewer_or_admin_required
def report_stock(day: str):
    if not REPORTLAB_AVAILABLE:
        flash("PDF generation not available. Install reportlab package: pip install reportlab", "error")
        return redirect(url_for("dashboard"))
    
    # day format: YYYY-MM-DD or "today"
    try:
        target = date.today() if day == "today" else datetime.strptime(day, "%Y-%m-%d").date()
    except Exception:
        flash("Invalid date format", "error")
        return redirect(url_for("dashboard"))

    # Build a stock snapshot showing remaining stock per product (across all locations),
    # rather than just the change quantities for the selected day.
    items = Item.query.order_by(Item.name.asc()).all()

    from io import BytesIO
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    _pdf_header(c, f"Stock Levels - {target}")
    y = 272*mm
    cols = [("Item", 80*mm), ("Total Stock", 35*mm), ("Unit", 20*mm), ("Category", 40*mm)]
    widths = [w for _, w in cols]
    y = _pdf_table_header(c, y, cols)

    for item in items:
        if y < 20*mm:
            c.showPage(); _pdf_header(c, f"Stock Levels - {target}"); y = 272*mm; y = _pdf_table_header(c, y, cols)
        total_stock = item.current_stock
        y = _pdf_table_row(
            c,
            y,
            [
                item.name,
                f"{total_stock:.3f}",
                item.unit,
                (item.category or "").capitalize(),
            ],
            widths,
        )

    c.showPage(); c.save()
    buf.seek(0)
    from flask import send_file
    return send_file(buf, as_attachment=True, download_name=f"stock_{target}.pdf", mimetype="application/pdf")


@app.route("/reports/orders/<string:day>")
@login_required
@viewer_or_admin_required
def report_orders(day: str):
    if not REPORTLAB_AVAILABLE:
        flash("PDF generation not available. Install reportlab package: pip install reportlab", "error")
        return redirect(url_for("dashboard"))
    
    try:
        target = date.today() if day == "today" else datetime.strptime(day, "%Y-%m-%d").date()
    except Exception:
        flash("Invalid date format", "error")
        return redirect(url_for("dashboard"))

    orders = (
        Order.query.filter(func.date(Order.created_at) == target).order_by(Order.id.asc()).all()
    )

    from io import BytesIO
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    _pdf_header(c, f"Orders Report - {target}")
    y = 272*mm
    
    for order in orders:
        # Check if we need a new page
        if y < 60*mm:
            c.showPage()
            _pdf_header(c, f"Orders Report - {target}")
            y = 272*mm
        
        # Order header
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20*mm, y, f"Order #{order.id} - {order.customer_name}")
        y -= 8*mm
        
        c.setFont("Helvetica", 10)
        c.drawString(20*mm, y, f"Status: {order.status}")
        if order.company_name:
            c.drawString(80*mm, y, f"Company: {order.company_name}")
        y -= 6*mm
        
        c.drawString(20*mm, y, f"Created: {order.created_at.strftime('%Y-%m-%d %H:%M')}")
        y -= 8*mm
        
        # Items table header
        item_cols = [("Item", 70*mm), ("Qty", 25*mm), ("Unit", 20*mm), ("Price", 30*mm), ("Total", 30*mm)]
        item_widths = [w for _, w in item_cols]
        y = _pdf_table_header(c, y, item_cols)
        
        order_total = Decimal("0")
        total_qty = Decimal("0")
        
        # Items
        for item in order.items:
            line_total = item.qty_ordered * item.unit_price
            order_total += line_total
            total_qty += item.qty_ordered
            
            if y < 20*mm:
                c.showPage()
                _pdf_header(c, f"Orders Report - {target}")
                y = 272*mm
                y = _pdf_table_header(c, y, item_cols)
            
            y = _pdf_table_row(c, y, [
                item.item_name,
                f"{item.qty_ordered:.2f}",
                item.unit,
                f"₹{item.unit_price:.2f}",
                f"₹{line_total:.2f}"
            ], item_widths)
        
        # Order totals
        y -= 4*mm
        c.setFont("Helvetica-Bold", 10)
        c.drawString(20*mm, y, f"Total Items: {total_qty:.2f}")
        c.drawRightString(175*mm, y, f"Order Total: ₹{order_total:.2f}")
        y -= 12*mm
        
        # Separator line
        c.setLineWidth(0.5)
        c.line(20*mm, y, 190*mm, y)
        y -= 8*mm
    
    c.showPage()
    c.save()
    buf.seek(0)
    from flask import send_file
    return send_file(buf, as_attachment=True, download_name=f"orders_{target}.pdf", mimetype="application/pdf")


@app.route("/locations", methods=["GET", "POST"])
@login_required
@viewer_or_admin_required
def manage_locations():
    if request.method == "POST":
        if not current_user.is_admin():
            flash("Only admins can add locations", "error")
            return redirect(url_for("manage_locations"))
        name = request.form.get("name", "").strip()
        if not name:
            flash("Location name is required", "error")
            return redirect(url_for("manage_locations"))
        existing = Location.query.filter(func.lower(Location.name) == func.lower(name)).first()
        if existing:
            flash("Location with this name already exists", "error")
            return redirect(url_for("manage_locations"))
        new_location = Location(name=name)
        db.session.add(new_location)
        db.session.commit()
        flash("Location added successfully", "success")
        return redirect(url_for("manage_locations"))
    locations = Location.query.order_by(Location.name.asc()).all()
    return render_template("locations.html", locations=locations)


@app.route("/locations/<int:location_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_location(location_id: int):
    location = Location.query.get_or_404(location_id)
    
    if request.method == "POST":
        new_name = request.form.get("name", "").strip()
        if not new_name:
            flash("Location name is required", "error")
            return redirect(url_for("edit_location", location_id=location_id))
        
        # Check if another location with this name already exists
        existing = Location.query.filter(
            func.lower(Location.name) == func.lower(new_name),
            Location.id != location_id
        ).first()
        
        if existing:
            flash("Location with this name already exists", "error")
            return redirect(url_for("edit_location", location_id=location_id))
        
        location.name = new_name
        db.session.commit()
        flash("Location updated successfully", "success")
        return redirect(url_for("manage_locations"))
    
    return render_template("location_edit.html", location=location)


@app.route("/locations/<int:location_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_location(location_id: int):
    location = Location.query.get_or_404(location_id)
    if StockEntry.query.filter_by(location_id=location.id).count() > 0:
        flash("Cannot delete location with existing stock entries", "error")
        return redirect(url_for("manage_locations"))
    db.session.delete(location)
    db.session.commit()
    flash("Location deleted successfully", "success")
    return redirect(url_for("manage_locations"))


@app.route("/packaging_materials", methods=["GET", "POST"])
@login_required
@admin_required
def manage_packaging_materials():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        unit = request.form.get("unit", "pcs").strip()
        initial_stock = parse_decimal(request.form.get("initial_stock"), Decimal("0"))

        if not name:
            flash("Packaging material name is required", "error")
            return redirect(url_for("manage_packaging_materials"))

        existing = PackagingMaterial.query.filter(func.lower(PackagingMaterial.name) == func.lower(name)).first()
        if existing:
            flash("Packaging material with this name already exists", "error")
            return redirect(url_for("manage_packaging_materials"))

        new_material = PackagingMaterial(name=name, unit=unit, current_stock=initial_stock)
        db.session.add(new_material)
        db.session.commit()
        flash("Packaging material added successfully", "success")
        return redirect(url_for("manage_packaging_materials"))
    packaging_materials = PackagingMaterial.query.order_by(PackagingMaterial.name.asc()).all()
    return render_template("packaging_materials.html", packaging_materials=packaging_materials)


@app.route("/packaging_materials/<int:material_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def edit_packaging_material(material_id: int):
    material = PackagingMaterial.query.get_or_404(material_id)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        unit = request.form.get("unit", "pcs").strip()
        active = request.form.get("active") == "on"
        stock_change_str = request.form.get("stock_change", "0")
        stock_change = parse_decimal(stock_change_str, Decimal("0"))
        note = request.form.get("note", "").strip()

        if not name:
            flash("Packaging material name is required", "error")
            return redirect(url_for("edit_packaging_material", material_id=material.id))

        if name != material.name and PackagingMaterial.query.filter(func.lower(PackagingMaterial.name) == func.lower(name)).first():
            flash("Packaging material with this name already exists", "error")
            return redirect(url_for("edit_packaging_material", material_id=material.id))

        material.name = name
        material.unit = unit
        material.active = active

        if stock_change != 0:
            material.current_stock = (material.current_stock + stock_change).quantize(Decimal("0.001"))
            db.session.add(PackagingStockEntry(
                packaging_material_id=material.id,
                entry_date=date.today(),
                change_qty=stock_change,
                note=note or "Manual adjustment",
            ))

        db.session.commit()
        flash("Packaging material updated successfully", "success")
        return redirect(url_for("manage_packaging_materials"))
    
    return render_template("packaging_material_edit.html", material=material)


@app.route("/packaging_materials/<int:material_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_packaging_material(material_id: int):
    material = PackagingMaterial.query.get_or_404(material_id)
    if PackagingStockEntry.query.filter_by(packaging_material_id=material.id).count() > 0:
        flash("Cannot delete packaging material with existing stock entries", "error")
        return redirect(url_for("manage_packaging_materials"))

    db.session.delete(material)
    db.session.commit()
    flash("Packaging material deleted successfully", "success")
    return redirect(url_for("manage_packaging_materials"))


@app.route("/packaging_materials/stock_update", methods=["GET", "POST"])
@login_required
@admin_required
def packaging_stock_update():
    packaging_materials = PackagingMaterial.query.filter_by(active=True).order_by(PackagingMaterial.name.asc()).all()

    if request.method == "POST":
        entry_dt = request.form.get("entry_date")
        try:
            entry_date_parsed = datetime.strptime(entry_dt, "%Y-%m-%d").date() if entry_dt else date.today()
        except Exception:
            entry_date_parsed = date.today()

        any_changes = False
        for material in packaging_materials:
            delta_str = request.form.get(f"delta_{material.id}")
            delta = parse_decimal(delta_str, Decimal("0"))

            if delta != 0:
                any_changes = True
                material.current_stock = (material.current_stock + delta).quantize(Decimal("0.001"))
                db.session.add(
                    PackagingStockEntry(
                        packaging_material_id=material.id,
                        entry_date=entry_date_parsed,
                        change_qty=delta,
                        note="Manual update",
                    )
                )
        
        if any_changes:
            db.session.commit()
            flash("Packaging material stock updated", "success")
        else:
            flash("No changes submitted", "info")
        return redirect(url_for("packaging_stock_update"))
    
    return render_template("packaging_stock_update.html", packaging_materials=packaging_materials, today=date.today())


if __name__ == "__main__":
    app.run(debug=True)
