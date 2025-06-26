# app.py

import os
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import functools

# Initialize Flask application
app = Flask(__name__)

# Configure the secret key for session management and security
app.config['SECRET_KEY'] = 'your_super_secret_key_here' # Replace with a strong, randomly generated key

# MySQL Database Configuration
DB_USER = 'root'
DB_PASSWORD = '12345678'
DB_HOST = 'localhost'
DB_PORT = 3306
DB_NAME = 'Medical_Management'

# Construct the MySQL database URI
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable tracking modifications overhead

# Initialize SQLAlchemy with the Flask application
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # The route name for the login page
login_manager.login_message_category = 'info' # Category for flash message

# Database Models
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient')

    # Relationships with back_populates for explicit bidirectional setup
    patient_info = db.relationship('PatientInfo', back_populates='user', uselist=False, cascade="all, delete-orphan")
    doctor_info = db.relationship('DoctorInfo', back_populates='user', uselist=False, cascade="all, delete-orphan")
    
    appointments_as_patient = db.relationship('Appointment', foreign_keys='Appointment.patient_id', back_populates='patient_user', lazy='dynamic', cascade="all, delete-orphan")
    appointments_as_doctor = db.relationship('Appointment', foreign_keys='Appointment.doctor_id', back_populates='doctor_user', lazy='dynamic', cascade="all, delete-orphan")
    
    medical_records_as_patient = db.relationship('MedicalRecord', foreign_keys='MedicalRecord.patient_id', back_populates='record_patient_user', lazy='dynamic', cascade="all, delete-orphan")
    medical_records_as_doctor = db.relationship('MedicalRecord', foreign_keys='MedicalRecord.doctor_id', back_populates='record_doctor_user', lazy='dynamic', cascade="all, delete-orphan", overlaps="doctor") # Added overlaps and back_populates for consistency

    prescriptions_issued = db.relationship('Prescription', foreign_keys='Prescription.doctor_id', back_populates='issuer_doctor_user', lazy='dynamic', cascade="all, delete-orphan")
    prescriptions_received = db.relationship('Prescription', foreign_keys='Prescription.patient_id', back_populates='receiver_patient_user', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class PatientInfo(db.Model):
    __tablename__ = 'patient_info'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    insurance_info = db.Column(db.String(200), nullable=True)
    user = db.relationship('User', back_populates='patient_info')

class DoctorInfo(db.Model):
    __tablename__ = 'doctor_info'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    specialty = db.Column(db.String(100), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    clinic_address = db.Column(db.String(200), nullable=True)
    user = db.relationship('User', back_populates='doctor_info')

class Appointment(db.Model):
    __tablename__ = 'appointment'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient_user = db.relationship('User', foreign_keys=[patient_id], back_populates='appointments_as_patient')
    doctor_user = db.relationship('User', foreign_keys=[doctor_id], back_populates='appointments_as_doctor')

    def __repr__(self):
        return f'<Appointment {self.id} on {self.date} at {self.time} with Patient {self.patient_id}>'

class MedicalRecord(db.Model):
    __tablename__ = 'medical_record'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    record_date = db.Column(db.Date, nullable=False)
    diagnosis = db.Column(db.Text, nullable=True)
    treatment_notes = db.Column(db.Text, nullable=True)
    lab_results = db.Column(db.Text, nullable=True)

    record_patient_user = db.relationship('User', foreign_keys=[patient_id], back_populates='medical_records_as_patient')
    record_doctor_user = db.relationship('User', foreign_keys=[doctor_id], back_populates='medical_records_as_doctor')
    doctor = db.relationship('User', foreign_keys=[doctor_id], overlaps="record_doctor_user,medical_records_as_doctor") # This explicit 'doctor' relationship now defines overlaps

    def __repr__(self):
        return f'<MedicalRecord {self.id} for Patient {self.patient_id} on {self.record_date}>'

class Prescription(db.Model):
    __tablename__ = 'prescription'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    medication = db.Column(db.String(100), nullable=False)
    dosage = db.Column(db.String(50), nullable=False)
    instructions = db.Column(db.Text, nullable=True)
    issue_date = db.Column(db.Date, default=date.today)
    expiry_date = db.Column(db.Date, nullable=True)

    receiver_patient_user = db.relationship('User', foreign_keys=[patient_id], back_populates='prescriptions_received')
    issuer_doctor_user = db.relationship('User', foreign_keys=[doctor_id], back_populates='prescriptions_issued')

    def __repr__(self):
        return f'<Prescription {self.id} for Patient {self.patient_id} - {self.medication}>'

#--- Context Processor ---
@app.context_processor
def inject_current_year():
    """Injects the current year into all templates."""
    return {'current_year': datetime.now().year}

# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    """Required by Flask-Login. This function reloads the user object from the user ID from the session."""
    return db.session.get(User, int(user_id))

#--- Access Control Decorators ---
def roles_required(*roles):
    """Decorator to restrict access to a route based on user roles."""
    def wrapper(fn):
        @functools.wraps(fn)
        @login_required
        def decorated_view(*args, **kwargs):
            if current_user.role not in roles:
                flash("You do not have permission to access this page.", 'danger')
                abort(403) # Forbidden
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

#--- Routes ---

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'patient') # Default to patient if not specified

        # Basic validation
        if not username or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        new_user.role = role # Assign role after setting password

        try:
            db.session.add(new_user)
            # Create associated info tables
            if role == 'patient':
                patient_info = PatientInfo(user=new_user, full_name=username)
                db.session.add(patient_info)
            elif role == 'doctor':
                doctor_info = DoctorInfo(user=new_user, full_name=username)
                db.session.add(doctor_info)

            db.session.commit()
            flash(f'Account created for {username}! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'danger')
            print(f"Error during registration: {e}")
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard')) # Redirect to appropriate dashboard
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Redirects to the appropriate dashboard based on user role."""
    if current_user.role == 'patient':
        return redirect(url_for('patient_dashboard'))
    elif current_user.role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Unknown user role.', 'danger')
        logout_user()
        return redirect(url_for('login'))

#--- Patient Routes ---
@app.route('/patient/dashboard')
@roles_required('patient')
def patient_dashboard():
    """Patient dashboard."""
    patient_info = PatientInfo.query.filter_by(user_id=current_user.id).first()
    appointments = Appointment.query.filter_by(patient_id=current_user.id).order_by(Appointment.date.desc(), Appointment.time.desc()).all()

    # To display doctor's name in appointments
    appointments_with_doctor_names = []
    for appt in appointments:
        doctor_user = User.query.get(appt.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=appt.doctor_id).first()
        appointments_with_doctor_names.append({
            'id': appt.id,
            'date': appt.date,
            'time': appt.time,
            'status': appt.status,
            'reason': appt.reason,
            'doctor_name': doctor_info.full_name if doctor_info else doctor_user.username
        })
    return render_template('patient_dashboard.html', patient_info=patient_info, appointments=appointments_with_doctor_names)

@app.route('/patient/appointments/book', methods=['GET', 'POST'])
@roles_required('patient')
def book_appointment():
    """Patient can book an appointment."""
    doctors = DoctorInfo.query.all()
    today = date.today().isoformat() # For min date in HTML input

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        appointment_date_str = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason')

        if not (doctor_id and appointment_date_str and appointment_time):
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('book_appointment'))

        try:
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('book_appointment'))

        # Check if the doctor_id exists and corresponds to a doctor role
        doctor_user = User.query.get(doctor_id)
        if not doctor_user or doctor_user.role != 'doctor':
            flash('Invalid doctor selected.', 'danger')
            return redirect(url_for('book_appointment'))

        # Simple check for existing appointments (can be more sophisticated with time slot management)
        existing_appointment = Appointment.query.filter_by(
            doctor_id=doctor_id,
            date=appointment_date,
            time=appointment_time
        ).first()

        if existing_appointment:
            flash('This time slot is already booked. Please choose another.', 'warning')
            return redirect(url_for('book_appointment'))

        new_appointment = Appointment(
            patient_id=current_user.id,
            doctor_id=doctor_id,
            date=appointment_date,
            time=appointment_time,
            reason=reason,
            status='Pending' # New appointments are pending by default
        )
        db.session.add(new_appointment)
        db.session.commit()
        flash('Appointment booked successfully! It is pending confirmation from the doctor.', 'success')
        return redirect(url_for('patient_dashboard'))

    return render_template('book_appointment.html', doctors=doctors, today=today)

@app.route('/patient/appointments/cancel/<int:appointment_id>')
@roles_required('patient')
def cancel_appointment(appointment_id):
    """Patient can cancel their own appointment."""
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.patient_id != current_user.id:
        flash('You are not authorized to cancel this appointment.', 'danger')
        abort(403)
    
    if appointment.status == 'Completed':
        flash('Cannot cancel a completed appointment.', 'warning')
    elif appointment.status == 'Cancelled':
        flash('Appointment is already cancelled.', 'info')
    else:
        appointment.status = 'Cancelled'
        db.session.commit()
        flash('Appointment cancelled successfully.', 'success')
    return redirect(url_for('patient_dashboard'))

@app.route('/patient/records')
@roles_required('patient')
def view_medical_records():
    """Patient can view their medical records."""
    medical_records = MedicalRecord.query.filter_by(patient_id=current_user.id).order_by(MedicalRecord.record_date.desc()).all()
    # To display doctor's name in records
    records_with_doctor_names = []
    for record in medical_records:
        doctor_user = User.query.get(record.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=record.doctor_id).first()
        records_with_doctor_names.append({
            'id': record.id,
            'record_date': record.record_date,
            'diagnosis': record.diagnosis,
            'treatment_notes': record.treatment_notes,
            'lab_results': record.lab_results,
            'doctor_name': doctor_info.full_name if doctor_info else doctor_user.username
        })
    return render_template('view_medical_records.html', medical_records=records_with_doctor_names)

@app.route('/patient/prescriptions')
@roles_required('patient')
def view_prescriptions():
    """Patient can view their prescriptions."""
    prescriptions = Prescription.query.filter_by(patient_id=current_user.id).order_by(Prescription.issue_date.desc()).all()
    # To display doctor's name in prescriptions
    prescriptions_with_doctor_names = []
    for prescription in prescriptions:
        doctor_user = User.query.get(prescription.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=prescription.doctor_id).first()
        prescriptions_with_doctor_names.append({
            'id': prescription.id,
            'medication': prescription.medication,
            'dosage': prescription.dosage,
            'instructions': prescription.instructions,
            'issue_date': prescription.issue_date,
            'expiry_date': prescription.expiry_date,
            'doctor_name': doctor_info.full_name if doctor_info else doctor_user.username
        })
    return render_template('view_prescriptions.html', prescriptions=prescriptions_with_doctor_names)

@app.route('/patient/profile', methods=['GET', 'POST'])
@roles_required('patient')
def patient_profile():
    """Patient profile management."""
    patient_info = PatientInfo.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        patient_info.full_name = request.form.get('full_name')
        date_of_birth_str = request.form.get('date_of_birth')
        patient_info.date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date() if date_of_birth_str else None
        patient_info.gender = request.form.get('gender')
        patient_info.contact_number = request.form.get('contact_number')
        patient_info.address = request.form.get('address')
        patient_info.insurance_info = request.form.get('insurance_info')
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('patient_profile'))
    return render_template('profile.html', user=current_user, info=patient_info)

@app.route('/doctor/profile', methods=['GET', 'POST'])
@roles_required('doctor')
def doctor_profile():
    """Doctor profile management."""
    doctor_info = DoctorInfo.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        doctor_info.full_name = request.form.get('full_name')
        doctor_info.specialty = request.form.get('specialty')
        doctor_info.contact_number = request.form.get('contact_number')
        doctor_info.clinic_address = request.form.get('clinic_address')
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('doctor_profile'))
    return render_template('doctor_profile.html', user=current_user, info=doctor_info)

# --- Doctor Routes ---
@app.route('/doctor/dashboard')
@roles_required('doctor')
def doctor_dashboard():
    """Doctor dashboard."""
    doctor_info = DoctorInfo.query.filter_by(user_id=current_user.id).first()
    # Get upcoming appointments for the doctor
    today = date.today()
    upcoming_appointments = Appointment.query.filter(
        Appointment.doctor_id == current_user.id,
        Appointment.date >= today,
        Appointment.status.in_(['Pending', 'Confirmed'])
    ).order_by(Appointment.date.asc(), Appointment.time.asc()).all()
    # Get patient names for upcoming appointments
    appointments_with_patient_names = []
    for appt in upcoming_appointments:
        patient_user = User.query.get(appt.patient_id)
        patient_info = PatientInfo.query.filter_by(user_id=appt.patient_id).first()
        appointments_with_patient_names.append({
            'id': appt.id,
            'date': appt.date,
            'time': appt.time,
            'status': appt.status,
            'reason': appt.reason,
            'patient_name': patient_info.full_name if patient_info else patient_user.username
        })
    # Get a list of all patients currently in the system
    all_patients = PatientInfo.query.all()
    # Map patient_info to user objects to easily get username/id
    patients_data = []
    for p_info in all_patients:
        p_user = User.query.get(p_info.user_id)
        if p_user and p_user.role == 'patient': # Ensure it's actually a patient user
            patients_data.append({'user': p_user, 'info': p_info})
    return render_template('doctor_dashboard.html', doctor_info=doctor_info,
                           upcoming_appointments=appointments_with_patient_names,
                           patients=patients_data)

@app.route('/doctor/appointments')
@roles_required('doctor')
def doctor_view_appointments():
    """Doctor can view and manage their appointments."""
    appointments = Appointment.query.filter_by(doctor_id=current_user.id).order_by(Appointment.date.desc(), Appointment.time.desc()).all()
    appointments_with_patient_names = []
    for appt in appointments:
        patient_user = User.query.get(appt.patient_id)
        patient_info = PatientInfo.query.filter_by(user_id=appt.patient_id).first()
        appointments_with_patient_names.append({
            'id': appt.id,
            'date': appt.date,
            'time': appt.time,
            'status': appt.status,
            'reason': appt.reason,
            'patient_name': patient_info.full_name if patient_info else patient_user.username
        })
    return render_template('manage_appointments.html', appointments=appointments_with_patient_names)

@app.route('/doctor/appointments/update_status/<int:appointment_id>', methods=['POST'])
@roles_required('doctor')
def update_appointment_status(appointment_id):
    """Doctor can update appointment status."""
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.doctor_id != current_user.id:
        flash('You are not authorized to update this appointment.', 'danger')
        abort(403)
    
    new_status = request.form.get('status')
    if new_status in ['Pending', 'Confirmed', 'Completed', 'Cancelled']:
        appointment.status = new_status
        db.session.commit()
        flash(f'Appointment {appointment.id} status updated to {new_status}.', 'success')
    else:
        flash('Invalid status provided.', 'danger')
    return redirect(url_for('doctor_view_appointments'))

@app.route('/doctor/patients')
@roles_required('doctor')
def doctor_manage_patients():
    """Doctor views all patients and can search them."""
    search_query = request.args.get('search_query', '')
    patients_data = []
    if search_query:
        # Search by patient full name or username
        patient_infos = PatientInfo.query.filter(PatientInfo.full_name.ilike(f'%{search_query}%')).all()
        user_ids_from_info = [p.user_id for p in patient_infos]
        
        # Also search by username directly
        patient_users = User.query.filter(User.role == 'patient', User.username.ilike(f'%{search_query}%')).all()
        user_ids_from_user = [u.id for u in patient_users]
        # Combine and unique user IDs
        all_relevant_user_ids = list(set(user_ids_from_info + user_ids_from_user))

        for user_id in all_relevant_user_ids:
            p_user = User.query.get(user_id)
            if p_user and p_user.role == 'patient':
                p_info = PatientInfo.query.filter_by(user_id=p_user.id).first()
                if p_info:
                    patients_data.append({'user': p_user, 'info': p_info})
    else:
        # Get all patients if no search query
        all_patient_users = User.query.filter_by(role='patient').all()
        for p_user in all_patient_users:
            p_info = PatientInfo.query.filter_by(user_id=p_user.id).first()
            if p_info: # Ensure patient_info exists
                patients_data.append({'user': p_user, 'info': p_info})
    return render_template('doctor_manage_patients.html', patients=patients_data, search_query=search_query)

@app.route('/doctor/patient/<int:patient_id>/records')
@roles_required('doctor')
def doctor_view_patient_records(patient_id):
    """Doctor views specific patient's medical records and prescriptions."""
    patient_user = User.query.get_or_404(patient_id)
    if patient_user.role != 'patient':
        flash('User is not a patient.', 'danger')
        abort(404)
    patient_info = PatientInfo.query.filter_by(user_id=patient_id).first()
    medical_records = MedicalRecord.query.filter_by(patient_id=patient_id).order_by(MedicalRecord.record_date.desc()).all()
    prescriptions = Prescription.query.filter_by(patient_id=patient_id).order_by(Prescription.issue_date.desc()).all()

    # Get doctor names for medical records and prescriptions
    records_with_doctor_names = []
    for record in medical_records:
        doctor_user = User.query.get(record.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=record.doctor_id).first()
        records_with_doctor_names.append({
            'id': record.id,
            'record_date': record.record_date,
            'diagnosis': record.diagnosis,
            'treatment_notes': record.treatment_notes,
            'lab_results': record.lab_results,
            'doctor_name': doctor_info.full_name if doctor_info else doctor_user.username
        })
    
    prescriptions_with_doctor_names = []
    for prescription in prescriptions:
        doctor_user = User.query.get(prescription.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=prescription.doctor_id).first()
        prescriptions_with_doctor_names.append({
            'id': prescription.id,
            'medication': prescription.medication,
            'dosage': prescription.dosage,
            'instructions': prescription.instructions,
            'issue_date': prescription.issue_date,
            'expiry_date': prescription.expiry_date,
            'doctor_name': doctor_info.full_name if doctor_info else doctor_user.username
        })

    return render_template('doctor_view_patient_records.html', patient_user=patient_user, patient_info=patient_info,
                           medical_records=records_with_doctor_names, prescriptions=prescriptions_with_doctor_names)

@app.route('/doctor/patient/<int:patient_id>/record/add_edit', methods=['GET', 'POST'])
@app.route('/doctor/patient/<int:patient_id>/record/add_edit/<int:record_id>', methods=['GET', 'POST'])
@roles_required('doctor')
def add_edit_medical_record(patient_id, record_id=None):
    """Doctor can add or edit a medical record for a patient."""
    patient_user = User.query.get_or_404(patient_id)
    if patient_user.role != 'patient':
        flash('User is not a patient.', 'danger')
        abort(404)
    
    record = None
    if record_id:
        record = MedicalRecord.query.get_or_404(record_id)
        if record.patient_id != patient_id:
            flash('Record does not belong to this patient.', 'danger')
            abort(400) # Bad Request

    today_date_str = date.today().isoformat() # For default date in form

    if request.method == 'POST':
        record_date_str = request.form.get('record_date')
        diagnosis = request.form.get('diagnosis')
        treatment_notes = request.form.get('treatment_notes')
        lab_results = request.form.get('lab_results')

        if not (record_date_str and diagnosis): # Minimal required fields
            flash('Record Date and Diagnosis are required.', 'danger')
            return redirect(url_for('add_edit_medical_record', patient_id=patient_id, record_id=record_id))

        try:
            record_date = datetime.strptime(record_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('add_edit_medical_record', patient_id=patient_id, record_id=record_id))

        if record: # Editing existing record
            record.record_date = record_date
            record.diagnosis = diagnosis
            record.treatment_notes = treatment_notes
            record.lab_results = lab_results
            flash('Medical record updated successfully!', 'success')
        else: # Adding new record
            new_record = MedicalRecord(
                patient_id=patient_id,
                doctor_id=current_user.id,
                record_date=record_date,
                diagnosis=diagnosis,
                treatment_notes=treatment_notes,
                lab_results=lab_results
            )
            db.session.add(new_record)
            flash('Medical record added successfully!', 'success')
        db.session.commit()
        return redirect(url_for('doctor_view_patient_records', patient_id=patient_id))
    
    return render_template('add_edit_medical_record.html', patient_user=patient_user, record=record, today=today_date_str)

@app.route('/doctor/patient/<int:patient_id>/prescription/issue', methods=['GET', 'POST'])
@roles_required('doctor')
def issue_prescription(patient_id):
    """Doctor can issue a new prescription for a patient."""
    patient_user = User.query.get_or_404(patient_id)
    if patient_user.role != 'patient':
        flash('User is not a patient.', 'danger')
        abort(404)
    
    today_date_str = date.today().isoformat() # For default date in form

    if request.method == 'POST':
        medication = request.form.get('medication')
        dosage = request.form.get('dosage')
        instructions = request.form.get('instructions')
        issue_date_str = request.form.get('issue_date')
        expiry_date_str = request.form.get('expiry_date')

        if not (medication and dosage and issue_date_str):
            flash('Medication, Dosage, and Issue Date are required.', 'danger')
            return redirect(url_for('issue_prescription', patient_id=patient_id))

        try:
            issue_date = datetime.strptime(issue_date_str, '%Y-%m-%d').date()
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('issue_prescription', patient_id=patient_id))

        new_prescription = Prescription(
            patient_id=patient_id,
            doctor_id=current_user.id,
            medication=medication,
            dosage=dosage,
            instructions=instructions,
            issue_date=issue_date,
            expiry_date=expiry_date
        )
        db.session.add(new_prescription)
        db.session.commit()
        flash('Prescription issued successfully!', 'success')
        return redirect(url_for('doctor_view_patient_records', patient_id=patient_id))
    
    return render_template('issue_prescription.html', patient_user=patient_user, today=today_date_str)

# --- Admin Routes ---
@app.route('/admin/dashboard')
@roles_required('admin')
def admin_dashboard():
    """Admin dashboard."""
    total_users = User.query.count()
    total_patients = User.query.filter_by(role='patient').count()
    total_doctors = User.query.filter_by(role='doctor').count()
    total_appointments = Appointment.query.count()
    
    # You can add more summary statistics here
    return render_template('admin_dashboard.html',
                           total_users=total_users,
                           total_patients=total_patients,
                           total_doctors=total_doctors,
                           total_appointments=total_appointments)

@app.route('/admin/users')
@roles_required('admin')
def admin_manage_users():
    """Admin can view and manage user accounts."""
    users = User.query.all()
    # Fetch associated patient/doctor info for display
    users_with_info = []
    for user in users:
        if user.role == 'patient':
            info = PatientInfo.query.filter_by(user_id=user.id).first()
        elif user.role == 'doctor':
            info = DoctorInfo.query.filter_by(user_id=user.id).first()
        else:
            info = None
        users_with_info.append({'user': user, 'info': info})
    return render_template('manage_users.html', users=users_with_info)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_add_user():
    """Admin can add new users (including doctors/staff)."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role') # Role selected by admin

        if not (username and email and password and role):
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('admin_add_user'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('User with this username or email already exists!', 'danger')
            return render_template('admin_add_user.html')

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            # Create associated info tables
            if role == 'patient':
                # Full name for patient_info (using username as default if not provided by form)
                full_name_patient = request.form.get('full_name', username)
                patient_info = PatientInfo(user=new_user, full_name=full_name_patient)
                db.session.add(patient_info)
            elif role == 'doctor':
                # Full name for doctor_info (using username as default if not provided by form)
                full_name_doctor = request.form.get('full_name', username)
                # Ensure these fields are collected if you want them. Otherwise, they'll be None.
                specialty = request.form.get('specialty')
                contact_number = request.form.get('contact_number')
                clinic_address = request.form.get('clinic_address')
                
                doctor_info_obj = DoctorInfo(
                    user=new_user, full_name=full_name_doctor,
                    specialty=specialty, contact_number=contact_number, clinic_address=clinic_address
                )
                db.session.add(doctor_info_obj)
            
            db.session.commit()
            flash(f'User {username} ({role}) added successfully!', 'success')
            return redirect(url_for('admin_manage_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user "{username}": {e}', 'danger')
            print(f"Error adding user: {e}")
            return render_template('admin_add_user.html')
    
    return render_template('admin_add_user.html')


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@roles_required('admin')
def admin_edit_user(user_id):
    """Admin can edit user roles and basic info."""
    user = User.query.get_or_404(user_id)
    # Ensure admin cannot edit their own role easily through this interface to prevent lockout
    if user.id == current_user.id and request.method == 'POST' and request.form.get('role') != current_user.role:
        flash("You cannot change your own role through this interface.", 'danger')
        return redirect(url_for('admin_manage_users'))

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        new_password = request.form.get('password')
        new_role = request.form.get('role')

        if not (user.username and user.email and new_role):
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('admin_edit_user', user_id=user_id))

        # Handle password change
        if new_password:
            user.set_password(new_password)

        # Handle role change
        old_role = user.role
        if new_role != old_role:
            user.role = new_role
            # Clean up old info table and create new one if role changes significantly
            if old_role == 'patient' and new_role != 'patient':
                patient_info = PatientInfo.query.filter_by(user_id=user.id).first()
                if patient_info:
                    db.session.delete(patient_info)
            elif old_role == 'doctor' and new_role != 'doctor':
                doctor_info = DoctorInfo.query.filter_by(user_id=user.id).first()
                if doctor_info:
                    db.session.delete(doctor_info)
            
            if new_role == 'patient' and not PatientInfo.query.filter_by(user_id=user.id).first():
                db.session.add(PatientInfo(user=user, full_name=user.username)) # Use user relationship
            elif new_role == 'doctor' and not DoctorInfo.query.filter_by(user_id=user.id).first():
                db.session.add(DoctorInfo(user=user, full_name=user.username)) # Use user relationship
            # Admin role typically doesn't have an associated info table here

        db.session.commit()
        flash(f'User {user.username} updated successfully!', 'success')
        return redirect(url_for('admin_manage_users'))
    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>')
@roles_required('admin')
def admin_delete_user(user_id):
    """Admin can delete a user."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('admin_manage_users'))
    
    # NOTE: With cascade="all, delete-orphan" on relationships in User model,
    # Flask-SQLAlchemy should automatically handle deleting related records.
    # The explicit deletes below are mostly for clarity/safety, but often not strictly needed
    # if relationships are configured with proper cascade options.
    try:
        if user.role == 'patient':
            PatientInfo.query.filter_by(user_id=user.id).delete()
            Appointment.query.filter_by(patient_id=user.id).delete()
            MedicalRecord.query.filter_by(patient_id=user.id).delete()
            Prescription.query.filter_by(patient_id=user.id).delete()
        elif user.role == 'doctor':
            DoctorInfo.query.filter_by(user_id=user.id).delete()
            Appointment.query.filter_by(doctor_id=user.id).delete()
            MedicalRecord.query.filter_by(doctor_id=user.id).delete()
            Prescription.query.filter_by(doctor_id=user.id).delete()
        
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} and associated data deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user {user.username}: {e}", 'danger')
        print(f"Error deleting user {user.username}: {e}")

    return redirect(url_for('admin_manage_users'))

# --- Admin View All Appointments Route ---
@app.route('/admin/appointments')
@roles_required('admin')
def admin_view_all_appointments():
    """Admin can view all appointments in the system."""
    all_appointments = Appointment.query.order_by(Appointment.date.desc(), Appointment.time.desc()).all()
    
    appointments_display_data = []
    for appt in all_appointments:
        patient_user = db.session.get(User, appt.patient_id)
        patient_info = PatientInfo.query.filter_by(user_id=appt.patient_id).first()
        doctor_user = db.session.get(User, appt.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=appt.doctor_id).first()
        
        appointments_display_data.append({
            'id': appt.id,
            'date': appt.date,
            'time': appt.time,
            'status': appt.status,
            'reason': appt.reason,
            'patient_id': appt.patient_id,
            'patient_name': patient_info.full_name if patient_info else (patient_user.username if patient_user else 'N/A'),
            'doctor_name': doctor_info.full_name if doctor_info else (doctor_user.username if doctor_user else 'N/A')
        })
    
    return render_template('admin_manage_appointments.html', appointments=appointments_display_data)

# --- Admin Create Appointment Route ---
@app.route('/admin/appointments/create', methods=['GET', 'POST'])
@roles_required('admin')
def admin_create_appointment():
    """Admin can create new appointments for any patient with any doctor."""
    doctors = DoctorInfo.query.all()
    patients = PatientInfo.query.all()
    today = date.today().isoformat()

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        doctor_id = request.form.get('doctor_id')
        appointment_date_str = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason')
        status = request.form.get('status', 'Pending')

        if not (patient_id and doctor_id and appointment_date_str and appointment_time):
            flash('Please fill in all required fields (Patient, Doctor, Date, Time).', 'danger')
            return redirect(url_for('admin_create_appointment'))

        try:
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('admin_create_appointment'))
        
        patient_user_check = User.query.get(patient_id)
        doctor_user_check = User.query.get(doctor_id)

        if not patient_user_check or patient_user_check.role != 'patient':
            flash('Invalid patient selected.', 'danger')
            return redirect(url_for('admin_create_appointment'))
        
        if not doctor_user_check or doctor_user_check.role != 'doctor':
            flash('Invalid doctor selected.', 'danger')
            return redirect(url_for('admin_create_appointment'))

        # Check for existing appointment at the same time slot for the selected doctor
        existing_appointment = Appointment.query.filter_by(
            doctor_id=doctor_id,
            date=appointment_date,
            time=appointment_time
        ).first()

        if existing_appointment:
            flash('This time slot is already booked for the selected doctor. Please choose another.', 'warning')
            return redirect(url_for('admin_create_appointment'))

        new_appointment = Appointment(
            patient_id=patient_id,
            doctor_id=doctor_id,
            date=appointment_date,
            time=appointment_time,
            reason=reason,
            status=status
        )
        db.session.add(new_appointment)
        db.session.commit()
        flash(f'Appointment created successfully for {patient_user_check.username} with {doctor_user_check.username}!', 'success')
        return redirect(url_for('admin_view_all_appointments'))

    return render_template('admin_create_appointment.html', doctors=doctors, patients=patients, today=today)

# --- Admin Manage Prescriptions Route ---
@app.route('/admin/prescriptions')
@roles_required('admin')
def admin_manage_prescriptions():
    """Admin can view all prescriptions in the system and potentially manage them."""
    all_prescriptions = Prescription.query.order_by(Prescription.issue_date.desc()).all()
    
    prescriptions_display_data = []
    for prescription in all_prescriptions:
        patient_user = db.session.get(User, prescription.patient_id)
        patient_info = PatientInfo.query.filter_by(user_id=prescription.patient_id).first()
        doctor_user = db.session.get(User, prescription.doctor_id)
        doctor_info = DoctorInfo.query.filter_by(user_id=prescription.doctor_id).first()
        
        prescriptions_display_data.append({
            'id': prescription.id,
            'medication': prescription.medication,
            'dosage': prescription.dosage,
            'instructions': prescription.instructions,
            'issue_date': prescription.issue_date,
            'expiry_date': prescription.expiry_date,
            'patient_name': patient_info.full_name if patient_info else (patient_user.username if patient_user else 'N/A'),
            'doctor_name': doctor_info.full_name if doctor_info else (doctor_user.username if doctor_user else 'N/A')
        })
    
    return render_template('admin_manage_prescriptions.html', prescriptions=prescriptions_display_data)


@app.route('/admin/manage-patients')
@roles_required('admin')
def admin_manage_patients():
    patients = PatientInfo.query.all()
    return render_template('admin_manage_patients.html', patients=patients)

@app.route('/admin/manage-doctors')
@roles_required('admin')
def admin_manage_doctors():
    doctors = DoctorInfo.query.all()
    return render_template('admin_manage_doctors.html', doctors=doctors)

@app.route('/admin/edit-patient/<int:patient_id>', methods=['GET', 'POST'])
@roles_required('admin')
def admin_edit_patient(patient_id):
    patient = PatientInfo.query.get_or_404(patient_id)
    if request.method == 'POST':
        patient.full_name = request.form.get('full_name')
        date_of_birth_str = request.form.get('date_of_birth')
        patient.date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date() if date_of_birth_str else None
        patient.gender = request.form.get('gender')
        patient.contact_number = request.form.get('contact_number')
        patient.address = request.form.get('address')
        patient.insurance_info = request.form.get('insurance_info')
        db.session.commit()
        flash('Patient profile updated!', 'success')
        return redirect(url_for('admin_manage_patients'))
    return render_template('profile.html', user=patient.user, info=patient)

@app.route('/admin/edit-doctor/<int:doctor_id>', methods=['GET', 'POST'])
@roles_required('admin')
def admin_edit_doctor(doctor_id):
    doctor = DoctorInfo.query.get_or_404(doctor_id)
    if request.method == 'POST':
        doctor.full_name = request.form.get('full_name')
        doctor.specialty = request.form.get('specialty') # Corrected field name from 'specialization' to 'specialty' based on model
        doctor.contact_number = request.form.get('contact_number')
        doctor.clinic_address = request.form.get('clinic_address')
        db.session.commit()
        flash('Doctor profile updated!', 'success')
        return redirect(url_for('admin_manage_doctors'))
    return render_template('doctor_profile.html', user=doctor.user, info=doctor)


@app.route('/messages')
@login_required
def messages():
    """A placeholder for secure messaging. In a real app, this would be complex."""
    flash("This is a placeholder for secure messaging functionality. It's under development.", 'info')
    return render_template('messages.html')

# --- Error Handlers ---
# New global error handler for any exception
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error for debugging purposes (e.g., to console or a file)
    print(f"An unexpected error occurred: {e}")
    # Flash a generic message
    flash("An unexpected error occurred. Please try again or contact support.", 'danger')
    # Render the generic error placeholder page
    return render_template('error_placeholder.html', error_message=str(e)), 500 # Use 500 for internal server error

# Specific HTTP error handlers now redirect to the generic placeholder
@app.errorhandler(403)
def forbidden(e):
    flash("You do not have permission to access this page.", 'danger')
    return redirect(url_for('handle_exception', code=403)) # Redirect to the generic handler

@app.errorhandler(404)
def page_not_found(e):
    flash("The page you are looking for does not exist.", 'danger')
    return redirect(url_for('handle_exception', code=404)) # Redirect to the generic handler

@app.errorhandler(500)
def internal_server_error(e):
    flash("An internal server error occurred.", 'danger')
    return redirect(url_for('handle_exception', code=500)) # Redirect to the generic handler


# --- Main entry point ---
if __name__ == '__main__':
    with app.app_context():
        try:
            # Create all tables in the connected MySQL database
            db.create_all()
            print("Database tables created successfully or already exist.")
            # Create default admin, doctor, patient users if they don't exist
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', email='admin@clinic.com', role='admin')
                admin_user.set_password('adminpass')
                db.session.add(admin_user)
                db.session.commit() # Commit admin user immediately to get ID
                print("Default admin user created: username='admin', password='adminpass'")
            
            if not User.query.filter_by(username='doctor1').first():
                doctor_user = User(username='doctor1', email='doctor1@clinic.com', role='doctor')
                doctor_user.set_password('doctorpass')
                db.session.add(doctor_user)
                db.session.flush() # Use flush to assign ID before doctor_info
                doctor_info = DoctorInfo(user=doctor_user, full_name='Dr. Alice Smith', specialty='General Practice', contact_number='555-111-2222', clinic_address='123 Health St')
                db.session.add(doctor_info)
                db.session.commit()
                print("Default doctor user created: username='doctor1', password='doctorpass'")
            
            if not User.query.filter_by(username='patient1').first():
                patient_user = User(username='patient1', email='patient1@example.com', role='patient')
                patient_user.set_password('patientpass')
                db.session.add(patient_user)
                db.session.flush() # Use flush to assign ID before patient_info
                patient_info = PatientInfo(user=patient_user, full_name='John Doe', date_of_birth=date(1990, 5, 15), gender='Male', contact_number='555-999-8888', address='456 Wellness Ave', insurance_info='HealthSure ID: XYZ123')
                db.session.add(patient_info)
                db.session.commit()
                print("Default patient user created: username='patient1', password='patientpass'")
        except Exception as e:
            print(f"An error occurred during database initialization: {e}")
            print("Please ensure your MySQL server is running and the database 'Medical_Management' exists.")
            print("You might need to create the database manually in MySQL Workbench or via command line.")
    
    app.run(debug=True) # Run the Flask app in debug mode
