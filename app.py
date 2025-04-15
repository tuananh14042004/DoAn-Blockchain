from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask, request, jsonify
import json
from blockchain import Blockchain  # ✅ Import blockchain từ file blockchain.py

app = Flask(__name__)

# 🌟 Cấu hình Flask
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🔧 Khởi tạo các công cụ Flask
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "⚠️ Vui lòng đăng nhập để truy cập trang này!"
login_manager.login_message_category = "danger"

# 🚀 Khởi tạo Blockchain
blockchain = Blockchain()

# 📌 Mô hình User trong Database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 📌 Route: Trang chủ
@app.route('/')
def home():
    return render_template('index.html')

# 📌 Route: Trang giao dịch (CHỈ CHO NGƯỜI DÙNG ĐÃ ĐĂNG NHẬP)
@app.route('/transaction')
@login_required
def transaction():
    return render_template('transactions.html')

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    data = request.get_json()
    print("Dữ liệu nhận được:", data)

    if not data:
        return jsonify({'message': '⚠️ Dữ liệu không hợp lệ!'}), 400

    required_fields = ['sender', 'receiver', 'amount']
    if not all(field in data and data[field] != "" for field in required_fields):
        return jsonify({'message': '⚠️ Thiếu thông tin giao dịch bắt buộc!'}), 400



    sender = data['sender']
    receiver = data['receiver']
    amount = data['amount']
    transaction_name = data.get('transaction_name', '')

    # ✅ Thêm giao dịch
    blockchain.add_transaction(sender, receiver, amount, transaction_name)

    return jsonify({'message': '✅ Giao dịch đã được thêm thành công!'}), 200

# 📌 Route: Đào block mới (CHỈ CHO NGƯỜI DÙNG ĐÃ ĐĂNG NHẬP)
@app.route('/mine_block', methods=['GET'])
@login_required
def mine_block():
    if not blockchain.transactions:
        return jsonify({'error': '⚠️ Không có giao dịch nào để thêm vào block!'}), 400

    previous_block = blockchain.last_block
    previous_hash = blockchain.hash_block(previous_block)
    new_block = blockchain.create_block(previous_hash)

    return jsonify({
        'message': '🎉 Block đã được đào thành công!',
        'index': new_block['index'],
        'timestamp': new_block['timestamp'],
        'previous_hash': new_block['previous_hash'],
        'transactions': new_block['transactions'],
        'hash': new_block['hash'],
        'nonce': new_block['nonce']
    }), 200

# 📌 Route: Xem lịch sử giao dịch (CHỈ CHO NGƯỜI DÙNG ĐÃ ĐĂNG NHẬP)
@app.route('/get_transactions', methods=['GET'])
@login_required
def get_transactions():
    try:
        transactions = blockchain.get_all_transactions()
        return jsonify({"transactions": transactions}), 200
    except Exception as e:
        return jsonify({"error": f"Lỗi server: {str(e)}"}), 500

# 📌 Route: Xem toàn bộ blockchain (CHỈ CHO NGƯỜI DÙNG ĐÃ ĐĂNG NHẬP)
@app.route('/get_chain', methods=['GET'])
@login_required
def get_chain():
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }), 200

# 📌 Route: Đăng ký tài khoản
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('⛔ Không được để trống!', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('🔐 Mật khẩu phải có ít nhất 6 ký tự!', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('❌ Mật khẩu xác nhận không khớp!', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('⚠️ Tên người dùng đã tồn tại!', 'danger')
            return redirect(url_for('register'))

        # ✅ Tạo user mới
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit() 
        flash('✅ Đăng ký thành công!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# 📌 Route: Đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('🎉 Đăng nhập thành công!', 'success')
            return redirect(url_for('home'))
        else:
            flash('⚠️ Sai tên đăng nhập hoặc mật khẩu!', 'danger')

    return render_template('login.html')

# 📌 Route: Đăng xuất
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('🚪 Đăng xuất thành công!', 'info')
    return redirect(url_for('home'))

# 📌 Khởi chạy Flask
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)