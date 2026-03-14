import os
import datetime
import mysql.connector
from mysql.connector import Error
import jwt
import bcrypt
import csv
import io
from functools import wraps
from flask import Flask, request, jsonify, render_template, make_response, Response
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, 
            template_folder='../templates',
            static_folder='../static')
CORS(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')

# Database connection
def get_db_connection():
    try:
        # Configuration for production (Aiven/Render) or local development
        db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', ''),
            'database': os.getenv('DB_NAME', 'core_inventory'),
            'port': int(os.getenv('DB_PORT', 3306))
        }
        
        # Add SSL if not running locally (Render/Aiven requirement)
        if os.getenv('FLASK_ENV') != 'development':
            db_config['ssl_disabled'] = False
            # Many cloud providers like Aiven require SSL.
            
        connection = mysql.connector.connect(**db_config)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Auth decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            token = token.split(" ")[1] # Bearer Token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'admin':
            return jsonify({'message': 'Admin privileges required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# --- FRONTEND ROUTES ---
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/warehouse')
def warehouse():
    return render_template('warehouse.html')

@app.route('/inventory')
def inventory():
    return render_template('inventory.html')

@app.route('/inventory_history')
def inventory_history():
    return render_template('inventory_history.html')

# --- API ROUTES ---

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Could not verify'}), 401

    conn = get_db_connection()
    if not conn:
        return jsonify({'message': 'Database connection error'}), 500
        
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (data.get('username'),))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    if bcrypt.checkpw(data.get('password').encode('utf-8'), user['password_hash'].encode('utf-8')):
        token = jwt.encode({
            'user': {'id': user['id'], 'username': user['username'], 'role': user['role']},
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({'token': token, 'role': user['role'], 'username': user['username']})

    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'staff')

    if not username or not password:
        return jsonify({'message': 'Missing data'}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", 
                       (username, hashed_pw, role))
        conn.commit()
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 400
    finally:
        cursor.close()
        conn.close()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Total products
    cursor.execute("SELECT COUNT(*) as count FROM products")
    total_products = cursor.fetchone()['count']
    
    # Low stock
    cursor.execute("SELECT COUNT(*) as count FROM products WHERE quantity < 10")
    low_stock = cursor.fetchone()['count']
    
    # Warehouses
    cursor.execute("SELECT COUNT(*) as count FROM warehouses")
    total_warehouses = cursor.fetchone()['count']
    
    # Total Value Estimate
    cursor.execute("SELECT SUM(price * quantity) as total_value FROM products")
    val_res = cursor.fetchone()
    total_value = float(val_res['total_value']) if val_res and val_res['total_value'] else 0.0
    
    # Recent activity
    cursor.execute("""
        SELECT t.*, p.name as product_name
        FROM inventory_transactions t 
        JOIN products p ON t.product_id = p.id 
        ORDER BY t.date DESC LIMIT 5
    """)
    recent_activity = cursor.fetchall()
    
    # Chart aggregations
    
    # 1. Warehouse Distribution (Stock sum by warehouse)
    cursor.execute("""
        SELECT w.name, SUM(p.quantity) as total_stock 
        FROM products p 
        LEFT JOIN warehouses w ON p.warehouse_id = w.id 
        GROUP BY p.warehouse_id
    """)
    warehouse_dist = cursor.fetchall()
    
    # 2. Category Distribution
    cursor.execute("SELECT category, COUNT(*) as count FROM products GROUP BY category")
    category_dist = cursor.fetchall()
    
    # 3. Monthly Stock Movement
    cursor.execute("""
        SELECT DATE_FORMAT(date, '%Y-%m') as month, type, SUM(quantity) as qty 
        FROM inventory_transactions 
        GROUP BY month, type
        ORDER BY month ASC LIMIT 30
    """)
    monthly_moves = cursor.fetchall()
    
    # 4. Top Selling/Moving Products (outgoing)
    cursor.execute("""
        SELECT p.name, SUM(t.quantity) as total_out
        FROM inventory_transactions t
        JOIN products p ON t.product_id = p.id
        WHERE t.type = 'outgoing'
        GROUP BY p.id
        ORDER BY total_out DESC LIMIT 5
    """)
    top_sellers = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return jsonify({
        'total_products': total_products,
        'low_stock_alerts': low_stock,
        'total_warehouses': total_warehouses,
        'total_value': total_value,
        'recent_activity': recent_activity,
        'charts': {
            'warehouse_dist': warehouse_dist,
            'category_dist': category_dist,
            'monthly_moves': monthly_moves,
            'top_sellers': top_sellers
        }
    })

# --- PRODUCT APIs ---
@app.route('/api/products', methods=['GET'])
@token_required
def get_products(current_user):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT p.*, w.name as warehouse_name FROM products p LEFT JOIN warehouses w ON p.warehouse_id = w.id")
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(products)

@app.route('/api/products', methods=['POST'])
@token_required
@admin_required
def add_product(current_user):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "INSERT INTO products (name, category, sku, price, quantity, warehouse_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (data['name'], data['category'], data['sku'], data['price'], data['quantity'], data.get('warehouse_id'))
        )
        conn.commit()
    except Exception as e:
        return jsonify({'message': str(e)}), 400
    finally:
        cursor.close()
        conn.close()
    return jsonify({'message': 'Product added successfully'}), 201

@app.route('/api/products/<int:id>', methods=['PUT', 'DELETE'])
@token_required
@admin_required
def modify_product(current_user, id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'DELETE':
        cursor.execute("DELETE FROM products WHERE id = %s", (id,))
        conn.commit()
        msg = 'Product deleted'
    else:
        data = request.json
        cursor.execute(
            "UPDATE products SET name=%s, category=%s, sku=%s, price=%s, quantity=%s, warehouse_id=%s WHERE id=%s",
            (data['name'], data['category'], data['sku'], data['price'], data['quantity'], data.get('warehouse_id'), id)
        )
        conn.commit()
        msg = 'Product updated'
    cursor.close()
    conn.close()
    return jsonify({'message': msg})

# --- WAREHOUSE APIs ---
@app.route('/api/warehouses', methods=['GET'])
@token_required
def get_warehouses(current_user):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM warehouses")
    warehouses = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(warehouses)

@app.route('/api/warehouses', methods=['POST'])
@token_required
@admin_required
def add_warehouse(current_user):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("INSERT INTO warehouses (name, location) VALUES (%s, %s)", (data['name'], data['location']))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Warehouse added'})

@app.route('/api/warehouses/<int:id>', methods=['PUT', 'DELETE'])
@token_required
@admin_required
def modify_warehouse(current_user, id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'DELETE':
        try:
            cursor.execute("DELETE FROM warehouses WHERE id = %s", (id,))
            conn.commit()
            msg = 'Warehouse deleted'
            status = 200
        except Exception as e:
            return jsonify({'message': str(e)}), 400
    else:
        data = request.json
        try:
            cursor.execute("UPDATE warehouses SET name=%s, location=%s WHERE id=%s", 
                           (data['name'], data['location'], id))
            conn.commit()
            msg = 'Warehouse updated'
            status = 200
        except Exception as e:
            return jsonify({'message': str(e)}), 400
    cursor.close()
    conn.close()
    return jsonify({'message': msg}), status

# --- INVENTORY MOVEMENT APIs ---
@app.route('/api/inventory/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT t.*, p.name as product_name, wf.name as from_warehouse, wt.name as to_warehouse
        FROM inventory_transactions t
        LEFT JOIN products p ON t.product_id = p.id
        LEFT JOIN warehouses wf ON t.warehouse_from = wf.id
        LEFT JOIN warehouses wt ON t.warehouse_to = wt.id
        WHERE 1=1
    """
    params = []
    
    if request.args.get('type'):
        query += " AND t.type = %s"
        params.append(request.args.get('type'))
    if request.args.get('product_id'):
        query += " AND t.product_id = %s"
        params.append(request.args.get('product_id'))
    if request.args.get('warehouse_id'):
        query += " AND (t.warehouse_from = %s OR t.warehouse_to = %s)"
        params.extend([request.args.get('warehouse_id'), request.args.get('warehouse_id')])
    if request.args.get('start_date'):
        query += " AND t.date >= %s"
        params.append(request.args.get('start_date') + " 00:00:00")
    if request.args.get('end_date'):
        query += " AND t.date <= %s"
        params.append(request.args.get('end_date') + " 23:59:59")
        
    query += " ORDER BY t.date DESC"
    
    cursor.execute(query, tuple(params))
    transactions = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(transactions)

@app.route('/api/inventory/move', methods=['POST'])
@token_required
def move_inventory(current_user):
    data = request.json
    product_id = data['product_id']
    m_type = data['type']
    qty = int(data['quantity'])
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check current stock
        cursor.execute("SELECT quantity, warehouse_id FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            return jsonify({'message': 'Product not found'}), 404
            
        current_qty = product['quantity']
        
        # Calculate new stock
        if m_type == 'incoming':
            new_qty = current_qty + qty
            w_to = data.get('warehouse_to', product['warehouse_id'])
            w_from = None
            # Update product quantity
            cursor.execute("UPDATE products SET quantity = %s WHERE id = %s", (new_qty, product_id))
            
        elif m_type == 'outgoing':
            if current_qty < qty:
                return jsonify({'message': 'Insufficient stock'}), 400
            new_qty = current_qty - qty
            w_from = product['warehouse_id']
            w_to = None
            cursor.execute("UPDATE products SET quantity = %s WHERE id = %s", (new_qty, product_id))
            
        elif m_type == 'transfer':
            if current_qty < qty:
                return jsonify({'message': 'Insufficient stock'}), 400
            # A transfer usually implies moving from one warehouse to another
            # For simplicity in this demo, it just records the transaction. 
            # In a real app, product might be tied to multiple warehouses.
            w_from = data.get('warehouse_from')
            w_to = data.get('warehouse_to')
            # Quantity remains same globally, but we just log the transaction
            # (assuming global quantity tracking for this hackathon version)
        
        # Log transaction
        cursor.execute(
            "INSERT INTO inventory_transactions (product_id, type, quantity, warehouse_from, warehouse_to) VALUES (%s, %s, %s, %s, %s)",
            (product_id, m_type, qty, w_from, w_to)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 400
    finally:
        cursor.close()
        conn.close()
        
    return jsonify({'message': 'Transaction successful'}), 201

# --- Smart Restock Prediction (Bonus) ---
@app.route('/api/inventory/predict/<int:product_id>', methods=['GET'])
@token_required
def predict_restock(current_user, product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Calculate 30-day moving average of outgoing stock
    cursor.execute("""
        SELECT SUM(quantity) as total_sold
        FROM inventory_transactions 
        WHERE product_id = %s 
        AND type = 'outgoing' 
        AND date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    """, (product_id,))
    sales_data = cursor.fetchone()
    total_sold = sales_data['total_sold'] if sales_data and sales_data['total_sold'] else 0
    
    # Calculate daily average
    average_daily_sales = round(total_sold / 30, 2)

    cursor.execute("SELECT quantity, name FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not product:
        return jsonify({'message': 'Not found'}), 404
        
    # If no sales, assume very slow movement (e.g. 0.01 per day) to avoid Infinity
    calc_velocity = average_daily_sales if average_daily_sales > 0 else 0.01
    days_left = product['quantity'] / calc_velocity
    
    return jsonify({
        'product': product['name'],
        'current_stock': product['quantity'],
        'average_daily_sales': average_daily_sales,
        'estimated_days_left': round(days_left, 1) if average_daily_sales > 0 else '>999'
    })

# --- CSV EXPORT APIs ---
@app.route('/api/export/products', methods=['GET'])
@token_required
def export_products(current_user):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT p.id, p.sku, p.name, p.category, p.price, p.quantity, w.name as warehouse FROM products p LEFT JOIN warehouses w ON p.warehouse_id = w.id")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=['id', 'sku', 'name', 'category', 'price', 'quantity', 'warehouse'])
    cw.writeheader()
    cw.writerows(rows)
    
    return Response(si.getvalue(), mimetype='text/csv', headers={"Content-disposition": "attachment; filename=products.csv"})

@app.route('/api/export/warehouses', methods=['GET'])
@token_required
def export_warehouses(current_user):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT w.id, w.name, w.location, SUM(p.quantity) as total_items FROM warehouses w LEFT JOIN products p ON p.warehouse_id = w.id GROUP BY w.id")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=['id', 'name', 'location', 'total_items'])
    cw.writeheader()
    cw.writerows(rows)
    
    return Response(si.getvalue(), mimetype='text/csv', headers={"Content-disposition": "attachment; filename=warehouses.csv"})

@app.route('/api/export/transactions', methods=['GET'])
@token_required
def export_transactions(current_user):
    # Quick dump of all transactions
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.id, t.date, t.type, p.name as product, t.quantity, wf.name as from_warehouse, wt.name as to_warehouse 
        FROM inventory_transactions t
        LEFT JOIN products p ON t.product_id = p.id
        LEFT JOIN warehouses wf ON t.warehouse_from = wf.id
        LEFT JOIN warehouses wt ON t.warehouse_to = wt.id
        ORDER BY t.date DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=['id', 'date', 'type', 'product', 'quantity', 'from_warehouse', 'to_warehouse'])
    cw.writeheader()
    cw.writerows(rows)
    
    return Response(si.getvalue(), mimetype='text/csv', headers={"Content-disposition": "attachment; filename=transactions.csv"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')
