from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import sys
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from decimal import Decimal
import uuid
from logging.handlers import RotatingFileHandler
from flask_cors import CORS
import secrets
from flask_migrate import Migrate
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import database configuration
from config import DATABASE_URL, print_db_info

# Ensure we're running from the correct directory
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# Initialize Flask app
app = Flask(__name__)

# Import configuration
# Configuration dictionary for different environments
class BaseConfig:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_ORIGINS = "*"
    
    # Cloud database only - no local instance path needed
    
    def __init__(self):
        # Ensure SECRET_KEY is set for production
        if not self.SECRET_KEY:
            if os.environ.get('FLASK_ENV') == 'production':
                raise ValueError("SECRET_KEY environment variable must be set for production")
            else:
                # Use a secure default for development only
                self.SECRET_KEY = 'dev-secret-key-change-for-production-' + os.urandom(16).hex()

class DevelopmentConfig(BaseConfig):
    DEBUG = True
    # Use PostgreSQL for development (same as production)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', DATABASE_URL)

class ProductionConfig(BaseConfig):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', DATABASE_URL)

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

# Get configuration based on environment
config_name = os.environ.get('FLASK_ENV', 'development')
config_instance = config[config_name]()  # Instantiate the config class
app.config.from_object(config_instance)

# Ensure required directories exist before initializing extensions
def ensure_directories():
    """Ensure required directories exist (logs only - no local database storage)"""
    try:
        logs_dir = os.path.join(app.config['BASE_DIR'], 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        print(f"✓ Directories created successfully:")
        print(f"  - Logs: {logs_dir}")
        
    except Exception as e:
        print(f"✗ Error creating directories: {e}")
        sys.exit(1)

# Create directories first
ensure_directories()

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cors = CORS(app, resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}})


# Setup logging
handler = RotatingFileHandler(
    os.path.join(app.config['BASE_DIR'], 'logs', 'app.log'),
    maxBytes=10000000,
    backupCount=5
)
handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Database Models
class User(db.Model):
    __tablename__ = 'users'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    biometric_id = db.Column(db.String(256), nullable=True)
    face_data = db.Column(db.Text, nullable=True)  # Store face data as base64
    auth_method = db.Column(db.String(20), nullable=True)  # 'biometric', 'face', 'password'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll_number = db.Column(db.String(20), unique=True, nullable=False)
    gender = db.Column(db.String(10))
    category = db.Column(db.String(50), nullable=False)
    academic_year = db.Column(db.String(20), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    fee_type = db.Column(db.String(50))
    bill_number = db.Column(db.String(50))
    total_fees = db.Column(db.Numeric(10, 2), default=0)
    paid_amount = db.Column(db.Numeric(10, 2), default=0)
    pending_amount = db.Column(db.Numeric(10, 2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    transactions = db.relationship('Transaction', backref='student', lazy=True)
    complaints = db.relationship('Complaint', backref='student', lazy=True)
    biometric_id = db.Column(db.String(256), unique=True, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'roll_number': self.roll_number,
            'gender': self.gender,
            'category': self.category,
            'academic_year': self.academic_year,
            'branch': self.branch,
            'fee_type': self.fee_type,
            'bill_number': self.bill_number,
            'total_amount': float(self.total_fees),
            'paid_amount': float(self.paid_amount),
            'pending_amount': float(self.pending_amount),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(50), unique=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    fee_type = db.Column(db.String(50), nullable=False)
    academic_year = db.Column(db.String(20), nullable=False)
    utr_number = db.Column(db.String(50))
    bill_number = db.Column(db.String(50))
    status = db.Column(db.String(20), default='pending')
    verification_comment = db.Column(db.Text)
    verified_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    verified_at = db.Column(db.DateTime)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    mobile_number = db.Column(db.String(15))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Complaint(db.Model):
    __tablename__ = 'complaints'
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.String(50), unique=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    response = db.Column(db.Text)
    responded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/studentlogin')
def student_login():
    return render_template('studentlogin.html')

@app.route('/employlogin')
def employee_login():
    return render_template('employlogin.html')

@app.route('/employloginpage')
def employee_login_page():
    return render_template('employloginpage.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('employee_login'))
    return render_template('dashboard.html')

@app.route('/api/student/auth', methods=['POST'])
def student_auth():
    try:
        data = request.get_json()
        roll_number = data.get('rollNumber')
        password = data.get('password')

        if not roll_number or not password:
            return jsonify({
                'success': False,
                'message': 'Missing credentials'
            }), 400

        student = Student.query.filter_by(roll_number=roll_number).first()
        if not student:
            return jsonify({
                'success': False,
                'message': 'Student not found'
            }), 404

        # Use environment variable for student password or default secure password
        student_password = os.environ.get('STUDENT_LOGIN_PASSWORD', 'secure_student_password_change_me')
        if password != student_password:
            return jsonify({
                'success': False,
                'message': 'Invalid password'
            }), 401

        session['student_id'] = student.id
        return jsonify({
            'success': True,
            'student': {
                'name': student.name,
                'rollNumber': student.roll_number,
                'branch': student.branch,
                'academicYear': student.academic_year
            }
        })

    except Exception as e:
        app.logger.error(f"Authentication error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Authentication failed'
        }), 500

@app.route('/api/employee/auth', methods=['POST'])
def employee_auth():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        auth_method = data.get('authMethod')
        auth_data = data.get('authData')  # For biometric/face data

        if not email:
            return jsonify({
                'success': False,
                'message': 'Email is required'
            }), 400

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404

        # Initial password check for all methods
        if password and not user.check_password(password):
            return jsonify({
                'success': False,
                'message': 'Invalid credentials'
            }), 401

        # Require password for all authentication methods
        if not password:
            return jsonify({
                'success': False,
                'message': 'Password is required'
            }), 400

        # Handle different authentication methods
        if auth_method == 'biometric':
            if not user.biometric_id and auth_data:
                # New registration - require password verification first
                user.biometric_id = auth_data
                db.session.commit()
                session['user_id'] = user.id
                return jsonify({
                    'success': True,
                    'message': 'Biometric registered and authenticated successfully'
                })
            elif user.biometric_id and auth_data and user.biometric_id == auth_data:
                session['user_id'] = user.id
                return jsonify({
                    'success': True,
                    'message': 'Biometric authentication successful'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Biometric authentication failed'
                }), 401
            
        elif auth_method == 'face':
            if not user.face_data and auth_data:
                # New registration - require password verification first
                user.face_data = auth_data
                db.session.commit()
                session['user_id'] = user.id
                return jsonify({
                    'success': True,
                    'message': 'Face data registered and authenticated successfully'
                })
            elif user.face_data and auth_data and user.face_data == auth_data:
                session['user_id'] = user.id
                return jsonify({
                    'success': True,
                    'message': 'Face authentication successful'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Face authentication failed'
                }), 401
        
        else:
            # Password authentication
            session['user_id'] = user.id
            return jsonify({
                'success': True,
                'message': 'Authentication successful'
            })
            
    except Exception as e:
        app.logger.error(f"Employee authentication error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Authentication failed'
        }), 500

@app.route('/api/student/submit-transaction', methods=['POST'])
def submit_transaction():
    try:
        data = request.get_json()
        
        # Require student authentication and validate roll number matches
        if 'student_id' not in session:
            return jsonify({'success': False, 'message': 'Student authentication required'}), 401
            
        # Validate student exists and matches session
        student = Student.query.filter_by(roll_number=data['rollNumber']).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # Verify student can only submit transactions for themselves
        if session['student_id'] != student.id:
            return jsonify({'success': False, 'message': 'Can only submit transactions for your own account'}), 403

        # Create transaction
        transaction = Transaction(
            transaction_id=f"TXN{uuid.uuid4().hex[:8].upper()}",
            student_id=student.id,
            amount=Decimal(str(data['paidAmount'])),
            fee_type=data['feeType'],
            academic_year=data['academicYear'],
            utr_number=data['utrNumber'],
            mobile_number=data['mobileNumber'],
            date=datetime.strptime(data['transDate'], '%Y-%m-%d')
        )

        db.session.add(transaction)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Transaction submitted successfully',
            'transaction': {
                'id': transaction.transaction_id,
                'amount': float(transaction.amount),
                'status': transaction.status
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Transaction error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/verify-transaction', methods=['POST'])
def verify_transaction():
    try:
        # Require authentication
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        data = request.get_json()
        transaction = Transaction.query.filter_by(transaction_id=data['transactionId']).first()
        
        if not transaction:
            return jsonify({'success': False, 'message': 'Transaction not found'}), 404

        if transaction.status != 'pending':
            return jsonify({'success': False, 'message': 'Transaction already processed'}), 400

        action = data['action']
        if action not in ['verify', 'reject']:
            return jsonify({'success': False, 'message': 'Invalid action'}), 400

        transaction.status = 'verified' if action == 'verify' else 'rejected'
        transaction.verification_comment = data.get('comment', '')
        transaction.verified_at = datetime.utcnow()
        transaction.verified_by = session.get('user_id')

        if action == 'verify':
            # Update student's paid amount
            student = transaction.student
            student.paid_amount = float(student.paid_amount or 0) + float(transaction.amount)
            student.pending_amount = float(student.total_fees or 0) - float(student.paid_amount)
            
            if data.get('billNumber'):
                transaction.bill_number = data['billNumber']

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Transaction {transaction.status}',
            'transaction': {
                'id': transaction.transaction_id,
                'status': transaction.status,
                'amount': float(transaction.amount)
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Verification error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/student/payment-details/<roll_number>')
def get_student_payment_details(roll_number):
    try:
        # Require authentication - either student or employee
        if 'student_id' not in session and 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
        student = Student.query.filter_by(roll_number=roll_number).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # If student login, verify they can only access their own data
        if 'student_id' in session and session['student_id'] != student.id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        transactions = Transaction.query.filter_by(student_id=student.id).all()
        
        # Group transactions by academic year
        year_wise_data = {}
        for transaction in transactions:
            year = transaction.academic_year
            if year not in year_wise_data:
                year_wise_data[year] = {
                    'total_amount': float(student.total_fees or 0),
                    'paid_amount': 0,
                    'pending_amount': float(student.total_fees or 0),
                    'transactions': []
                }
            
            if transaction.status == 'verified':
                year_wise_data[year]['paid_amount'] += float(transaction.amount)
                year_wise_data[year]['pending_amount'] = (
                    year_wise_data[year]['total_amount'] - 
                    year_wise_data[year]['paid_amount']
                )
            
            year_wise_data[year]['transactions'].append({
                'transactionId': transaction.transaction_id,
                'date': transaction.date.strftime('%Y-%m-%d'),
                'amount': float(transaction.amount),
                'feeType': transaction.fee_type,
                'status': transaction.status,
                'billNumber': transaction.bill_number
            })

        return jsonify({
            'success': True,
            'student': {
                'name': student.name,
                'rollNumber': student.roll_number,
                'branch': student.branch,
                'academicYear': student.academic_year,
                'totalFees': float(student.total_fees or 0),
                'paidAmount': float(student.paid_amount or 0),
                'pendingAmount': float(student.pending_amount or 0)
            },
            'yearWiseData': year_wise_data
        })

    except Exception as e:
        app.logger.error(f"Error fetching payment details: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/student/complaint', methods=['POST'])
def submit_complaint():
    try:
        if 'student_id' not in session:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401

        data = request.get_json()
        student = Student.query.get(session['student_id'])
        
        complaint = Complaint(
            complaint_id=f"COMP{uuid.uuid4().hex[:8].upper()}",
            student_id=student.id,
            subject=data['subject'],
            description=data['description']
        )

        db.session.add(complaint)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Complaint submitted successfully',
            'complaint': {
                'id': complaint.complaint_id,
                'subject': complaint.subject,
                'status': complaint.status,
                'date': complaint.created_at.isoformat()
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Complaint error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/student/transactions/<roll_number>')
def get_student_transactions(roll_number):
    try:
        # Require authentication - either student or employee
        if 'student_id' not in session and 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
        student = Student.query.filter_by(roll_number=roll_number).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # If student login, verify they can only access their own data
        if 'student_id' in session and session['student_id'] != student.id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        transactions = Transaction.query.filter_by(student_id=student.id).all()
        
        return jsonify({
            'success': True,
            'transactions': [{
                'id': t.transaction_id,
                'amount': float(t.amount),
                'feeType': t.fee_type,
                'academicYear': t.academic_year,
                'status': t.status,
                'date': t.date.isoformat()
            } for t in transactions]
        })

    except Exception as e:
        app.logger.error(f"Error fetching transactions: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/student/complaints/<roll_number>')
def get_student_complaints(roll_number):
    try:
        # Require authentication - either student or employee
        if 'student_id' not in session and 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
        student = Student.query.filter_by(roll_number=roll_number).first()
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
            
        # If student login, verify they can only access their own data
        if 'student_id' in session and session['student_id'] != student.id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        complaints = Complaint.query.filter_by(student_id=student.id).all()
        
        return jsonify({
            'success': True,
            'complaints': [{
                'id': c.complaint_id,
                'subject': c.subject,
                'description': c.description,
                'status': c.status,
                'response': c.response,
                'date': c.created_at.isoformat()
            } for c in complaints]
        })

    except Exception as e:
        app.logger.error(f"Error fetching complaints: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/student/save', methods=['POST'])
def save_student():
    try:
        # Require employee authentication
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Employee authentication required'}), 401
            
        data = request.get_json()
        
        # Check if student already exists
        student = Student.query.filter_by(roll_number=data['rollNumber']).first()
        
        if student:
            # Update existing student
            student.name = data['name']
            student.branch = data['branch']
            student.academic_year = data['academicYear']
            student.category = data['category']
            student.total_fees = data['totalAmount']
            student.paid_amount = data['paidAmount']
            student.pending_amount = data['pendingAmount']
        else:
            # Create new student
            student = Student(
                name=data['name'],
                roll_number=data['rollNumber'],
                branch=data['branch'],
                academic_year=data['academicYear'],
                category=data['category'],
                total_fees=data['totalAmount'],
                paid_amount=data['paidAmount'],
                pending_amount=data['pendingAmount']
            )
            db.session.add(student)

        db.session.commit()
        return jsonify({'success': True, 'message': 'Student saved successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/students/list')
def get_students():
    try:
        # Require employee authentication
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Employee authentication required'}), 401
            
        students = Student.query.all()
        stats = {
            'total': len(students),
            'paid': len([s for s in students if s.pending_amount <= 0]),
            'pending': len([s for s in students if s.pending_amount > 0])
        }
        
        return jsonify({
            'success': True,
            'students': [{
                'name': s.name,
                'rollNumber': s.roll_number,
                'branch': s.branch,
                'academicYear': s.academic_year,
                'category': s.category,
                'totalAmount': float(s.total_fees),
                'paidAmount': float(s.paid_amount),
                'pendingAmount': float(s.pending_amount)
            } for s in students],
            'statistics': stats
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/students/filter', methods=['POST'])
def filter_students():
    try:
        # Require employee authentication
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Employee authentication required'}), 401
            
        filters = request.get_json()
        query = Student.query

        if filters.get('branch'):
            query = query.filter_by(branch=filters['branch'])
        if filters.get('academicYear'):
            query = query.filter_by(academic_year=filters['academicYear'])
        if filters.get('category'):
            query = query.filter_by(category=filters['category'])
        if filters.get('listType'):
            if filters['listType'] == 'paidFee':
                query = query.filter(Student.pending_amount <= 0)
            elif filters['listType'] == 'pendingFee':
                query = query.filter(Student.pending_amount > 0)

        students = query.all()
        
        return jsonify({
            'success': True,
            'students': [{
                'name': s.name,
                'rollNumber': s.roll_number,
                'branch': s.branch,
                'academicYear': s.academic_year,
                'category': s.category,
                'totalAmount': float(s.total_fees),
                'paidAmount': float(s.paid_amount),
                'pendingAmount': float(s.pending_amount)
            } for s in students]
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/students', methods=['POST'])
def add_student():
    try:
        # Require employee authentication
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Employee authentication required'}), 401
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        new_student = Student(
            name=data.get('name'),
            roll_number=data.get('rollNumber'),
            gender=data.get('gender'),
            category=data.get('category'),
            academic_year=data.get('academicYear'),
            branch=data.get('branch'),
            fee_type=data.get('feeType'),
            bill_number=data.get('billNumber'),
            total_fees=Decimal(str(data.get('totalAmount', 0))),
            paid_amount=Decimal(str(data.get('paidAmount', 0))),
            pending_amount=Decimal(str(data.get('totalAmount', 0))) - Decimal(str(data.get('paidAmount', 0)))
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        return jsonify({'message': 'Student added successfully', 'student': new_student.to_dict()}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/logout')
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/employee/session')
def get_employee_session():
    """Get current employee session information"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Not authenticated'}), 401

        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'authMethod': user.auth_method,
                'lastLogin': user.last_login.isoformat() if user.last_login else None
            }
        })

    except Exception as e:
        app.logger.error(f"Session error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/employee/register', methods=['POST'])
def employee_register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        auth_method = data.get('authMethod')
        biometric_data = data.get('biometricData')
        face_data = data.get('faceData')

        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400

        # Create new user
        user = User(
            username=username,
            email=email,
            role='employee',
            auth_method=auth_method
        )
        user.set_password(password)

        # Store authentication data based on method
        if auth_method == 'biometric' and biometric_data:
            user.biometric_id = biometric_data
        elif auth_method == 'face' and face_data:
            user.face_data = face_data

        db.session.add(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Registration successful'
        })

    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/employee/register-auth', methods=['POST'])
def register_auth_method():
    """Register biometric or face authentication for existing user"""
    try:
        data = request.get_json()
        email = data.get('email')
        auth_method = data.get('authMethod')
        biometric_data = data.get('biometricData')
        face_data = data.get('faceData')

        if not email or not auth_method:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        # Find user
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Update authentication method
        user.auth_method = auth_method
        
        if auth_method == 'biometric' and biometric_data:
            user.biometric_id = biometric_data
        elif auth_method == 'face' and face_data:
            user.face_data = face_data

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'{auth_method.capitalize()} authentication registered successfully'
        })

    except Exception as e:
        app.logger.error(f"Auth registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

@app.route('/api/employee/check-registration', methods=['POST'])
def check_user_registration():
    """Check if user has registered authentication method"""
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        return jsonify({
            'success': True,
            'hasRegistered': user.auth_method is not None,
            'authMethod': user.auth_method,
            'hasBiometric': user.biometric_id is not None,
            'hasFaceData': user.face_data is not None
        })

    except Exception as e:
        app.logger.error(f"Registration check error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500


# Create database tables
def init_db():
    with app.app_context():
        try:
            # Check if tables exist
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            app.logger.info(f'Found existing tables: {existing_tables}')
            
            # Create all tables (this will skip if they already exist)
            db.create_all()
            app.logger.info('Database tables ready')
            
            # Check if users already exist
            existing_admin = User.query.filter_by(email='admin@example.com').first()
            existing_employee = User.query.filter_by(email='vemuit@gmail.com').first()
            
            # Create admin user if it doesn't exist
            if not existing_admin:
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    role='admin'
                )
                admin.set_password('admin123')
                db.session.add(admin)
                app.logger.info('Created admin user')
            else:
                app.logger.info('Admin user already exists')
                
            # Create demo employee user if it doesn't exist
            if not existing_employee:
                demo_employee = User(
                    username='Demo Employee',
                    email='vemuit@gmail.com',
                    role='employee'
                )
                demo_employee.set_password('vemuit@2008')
                db.session.add(demo_employee)
                app.logger.info('Created demo employee user')
            else:
                app.logger.info('Demo employee user already exists')
            
            db.session.commit()
            app.logger.info('Database initialization completed successfully')
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error initializing database: {str(e)}')
            # In development, show the error; in production, continue
            if app.config.get('DEBUG', False):
                app.logger.warning(f'Database initialization failed: {str(e)}')
                app.logger.warning('Continuing with existing database state')
            else:
                app.logger.warning('Continuing with existing database state')

@app.route('/api/employee/create-demo-user', methods=['POST'])
def create_demo_user():
    """Create demo employee user for testing"""
    try:
        # Check if demo user already exists
        existing_user = User.query.filter_by(email='vemuit@gmail.com').first()
        if existing_user:
            return jsonify({
                'success': True,
                'message': 'Demo user already exists',
                'user': {
                    'email': existing_user.email,
                    'username': existing_user.username
                }
            })

        # Create demo user
        demo_user = User(
            username='Demo Employee',
            email='vemuit@gmail.com',
            role='employee'
        )
        demo_user.set_password('vemuit@2008')
        
        db.session.add(demo_user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Demo user created successfully',
            'user': {
                'email': demo_user.email,
                'username': demo_user.username
            }
        })

    except Exception as e:
        app.logger.error(f"Demo user creation error: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error'}), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'success': False, 'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

# CLI commands
@app.cli.command("init-db")
def init_db_command():
    """Initialize the database."""
    try:
        init_db()
        print('Database initialized successfully.')
    except Exception as e:
        print(f'Error initializing database: {str(e)}')

if __name__ == '__main__':
    try:
        print("=" * 50)
        print("Fee Management System Starting...")
        print("=" * 50)
        print(f"Working directory: {os.getcwd()}")
        print(f"Script directory: {script_dir}")
        print(f"Cloud database: Using DATABASE_URL environment variable")
        print()
        
        # Show database configuration
        print_db_info()
        print()
        
        # Initialize database
        print("Initializing database...")
        try:
            init_db()
            print("✓ Database initialized successfully")
        except Exception as db_error:
            print(f"⚠️ Database initialization warning: {db_error}")
            print("✓ Continuing with existing database state...")
        print()
        
        # Start the application
        print("Starting Flask application...")
        print("✓ Application will be available at: http://localhost:5000")
        print("✓ Press Ctrl+C to stop the application")
        print("=" * 50)
        
        app.run(debug=True, host='0.0.0.0', port=5000)
        
    except PermissionError as e:
        print(f"✗ Permission Error: {e}")
        print("Please run the application from the correct directory or with proper permissions.")
        print(f"Current directory: {os.getcwd()}")
        print(f"Expected directory: {script_dir}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n✓ Application stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"✗ Application startup error: {str(e)}")
        app.logger.error(f"Application startup error: {str(e)}")
        print("Please check the logs for more details.")
        sys.exit(1)
