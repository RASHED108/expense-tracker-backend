from datetime import datetime, timedelta
import csv
import io
import os

from dotenv import load_dotenv
load_dotenv()


from bson.objectid import ObjectId
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
from flask_pymongo import PyMongo
import bcrypt
from dotenv import load_dotenv
load_dotenv()


# --- App & Config ---
app = Flask(__name__)

# Allow Angular dev app to call the API
CORS(
    app,
    resources={r"/*": {"origins": ["http://localhost:4200"]}},
    supports_credentials=True
)

# Secrets & DB connection from env (with safe defaults)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-change-me")

# If you set MONGO_URI in your environment it will be used.
# Otherwise we fall back to your Atlas URI below.
app.config["MONGO_URI"] = os.getenv(
    "MONGO_URI",
    "mongodb+srv://islamrashedul:Atlaspass@cluster0.rndhn.mongodb.net/expense_tracker"
    "?retryWrites=true&w=majority&appName=Cluster0"
)

# JWT & Mongo
jwt = JWTManager(app)
mongo = PyMongo(app)

# -------- Collections helpers --------
def users_col():
    return mongo.db.users

def tx_col():
    return mongo.db.transactions

def budget_col():
    return mongo.db.budgets   # { email, limit, threshold? , updatedAt }

# -------- Utilities --------
def to_public_tx(doc):
    """Convert Mongo doc to public JSON (stringify _id)."""
    return {
        "id": str(doc["_id"]),
        "user": doc["user"],
        "amount": float(doc.get("amount", 0)),
        "category": doc.get("category", ""),
        "date": doc.get("date", ""),           # ISO string
        "note": doc.get("note", ""),
        "type": doc.get("type", "expense")     # income | expense
    }

def parse_month_year(query_month: str | None):
    """
    Accepts 'YYYY-MM' or defaults to current month.
    Returns (year, month) as ints.
    """
    now = datetime.now()
    if not query_month:
        return now.year, now.month
    try:
        dt = datetime.strptime(query_month, "%Y-%m")
        return dt.year, dt.month
    except Exception:
        return now.year, now.month

# -------- Health --------
@app.get("/health")
def health():
    return {"ok": True, "service": "expense-tracker-api"}

# -------- Auth --------
@app.post("/auth/register")
def register():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password_raw = (data.get("password") or "")

    if not email or not password_raw:
        return jsonify({"error": "email and password required"}), 400

    if users_col().find_one({"email": email}):
        return jsonify({"error": "user already exists"}), 409

    pw_hash = bcrypt.hashpw(password_raw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users_col().insert_one({"email": email, "password": pw_hash})
    return {"message": "registered"}, 201

@app.post("/auth/login")
def login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password_raw = (data.get("password") or "")

    user = users_col().find_one({"email": email})
    if not user or not bcrypt.checkpw(password_raw.encode("utf-8"), user["password"].encode("utf-8")):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(identity=email, expires_delta=timedelta(hours=8))
    return {"access_token": token, "email": email}

# -------- Budget (per user) --------
@app.get("/budget")
@jwt_required()
def get_budget():
    email = get_jwt_identity()
    doc = budget_col().find_one({"email": email})
    # default limit=50 to match your frontend behavior
    if not doc:
        return {"limit": 50, "threshold": 90}, 200
    return {"limit": float(doc.get("limit", 50)), "threshold": float(doc.get("threshold", 90))}

@app.put("/budget")
@jwt_required()
def upsert_budget():
    email = get_jwt_identity()
    data = request.get_json(force=True)
    try:
        limit = float(data["limit"])
        threshold = float(data.get("threshold", 90))
    except Exception:
        return jsonify({"error": "invalid payload"}), 400

    budget_col().update_one(
        {"email": email},
        {"$set": {"limit": limit, "threshold": threshold, "updatedAt": datetime.utcnow()}},
        upsert=True
    )
    return {"limit": limit, "threshold": threshold}, 200

# -------- Transactions (protected) --------
@app.get("/transactions")
@jwt_required()
def list_transactions():
    email = get_jwt_identity()
    docs = list(tx_col().find({"user": email}).sort("date", -1))
    # back-compat: default missing 'type' to 'expense'
    for d in docs:
        if "type" not in d:
            d["type"] = "expense"
    return {"transactions": [to_public_tx(d) for d in docs]}

@app.post("/transactions")
@jwt_required()
def create_transaction():
    email = get_jwt_identity()
    data = request.get_json(force=True)

    try:
        tx = {
            "user": email,
            "amount": float(data["amount"]),
            "category": data["category"],
            "date": data["date"],                     # ISO string, e.g. "2025-07-22"
            "note": data.get("note", ""),
            "type": data.get("type", "expense")       # income | expense
        }
        if tx["type"] not in ["income", "expense"]:
            tx["type"] = "expense"
    except (KeyError, ValueError, TypeError):
        return jsonify({"error": "invalid payload"}), 400

    res = tx_col().insert_one(tx)
    tx["_id"] = res.inserted_id
    return to_public_tx(tx), 201

@app.put("/transactions/<tx_id>")
@jwt_required()
def update_transaction(tx_id):
    email = get_jwt_identity()
    data = request.get_json(force=True)

    update = {}
    for k in ["amount", "category", "date", "note", "type"]:
        if k in data:
            if k == "amount":
                update[k] = float(data[k])
            elif k == "type":
                update[k] = data[k] if data[k] in ["income", "expense"] else "expense"
            else:
                update[k] = data[k]

    if not update:
        return jsonify({"error": "nothing to update"}), 400

    res = tx_col().update_one(
        {"_id": ObjectId(tx_id), "user": email},
        {"$set": update}
    )
    if res.matched_count == 0:
        return jsonify({"error": "not found"}), 404

    doc = tx_col().find_one({"_id": ObjectId(tx_id), "user": email})
    # back-compat default
    if "type" not in doc:
        doc["type"] = "expense"
    return to_public_tx(doc)

@app.delete("/transactions/<tx_id>")
@jwt_required()
def delete_transaction(tx_id):
    email = get_jwt_identity()
    res = tx_col().delete_one({"_id": ObjectId(tx_id), "user": email})
    if res.deleted_count == 0:
        return jsonify({"error": "not found"}), 404
    return {"deleted": True}

# -------- Monthly summary for dashboard --------
@app.get("/summary/month")
@jwt_required()
def monthly_summary():
    """
    ?month=YYYY-MM  (optional; defaults to current month)
    Returns: totals for income, expenses, net, and category breakdown.
    """
    email = get_jwt_identity()
    year, month = parse_month_year(request.args.get("month"))

    # simple filter on string date "YYYY-MM"
    month_prefix = f"{year:04d}-{month:02d}"
    docs = list(tx_col().find({"user": email, "date": {"$regex": f"^{month_prefix}"}}))

    total_income = sum(float(d.get("amount", 0)) for d in docs if d.get("type", "expense") == "income")
    total_expenses = sum(float(d.get("amount", 0)) for d in docs if d.get("type", "expense") == "expense")
    net = total_income - total_expenses

    # category totals (for expenses)
    category_totals = {}
    for d in docs:
        if d.get("type", "expense") != "expense":
            continue
        cat = d.get("category", "Uncategorised")
        category_totals[cat] = category_totals.get(cat, 0) + float(d.get("amount", 0))

    return {
        "year": year,
        "month": month,
        "totalIncome": total_income,
        "totalExpenses": total_expenses,
        "net": net,
        "categoryTotals": category_totals
    }

# -------- CSV Export --------
@app.get("/transactions/export/csv")
@jwt_required()
def export_csv():
    """
    ?type=income|expense (optional; default = all)
    Streams a CSV file of the user's transactions.
    """
    email = get_jwt_identity()
    tx_type = request.args.get("type")  # None, 'income', 'expense'

    query = {"user": email}
    if tx_type in ["income", "expense"]:
        query["type"] = tx_type

    docs = list(tx_col().find(query).sort("date", -1))
    # back-compat default
    for d in docs:
        if "type" not in d:
            d["type"] = "expense"

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Amount", "Category", "Date", "Note", "Type"])
        yield buf.getvalue()
        buf.seek(0); buf.truncate(0)
        for d in docs:
            writer.writerow([
                f'{float(d.get("amount", 0)):.2f}',
                d.get("category", ""),
                d.get("date", ""),
                d.get("note", ""),
                d.get("type", "expense")
            ])
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)

    filename = f"transactions_{tx_type or 'all'}.csv"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": "text/csv; charset=utf-8"
    }
    return Response(generate(), headers=headers)

# --- Run ---
if __name__ == "__main__":
    # debug=True is fine for local dev
    app.run(debug=True)
