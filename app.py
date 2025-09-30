# app.py
import os
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, flash, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from config import get_db_connection  
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXT = {'pdf','png','jpg','jpeg','doc','docx'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app = Flask(__name__)
app.secret_key = 'replace_with_a_strong_secret'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT
@app.route('/')
def home():
    return render_template('index.html')
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['name'] = user['name']
            session['email'] = user['email']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        role = request.form.get('role','student')
        enrollment_no = request.form.get('enrollment_no','').strip()
        department = request.form.get('department','').strip()
        hashed = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (name,email,password,role,enrollment_no,department) VALUES (%s,%s,%s,%s,%s,%s)",
                (name,email,hashed,role,enrollment_no,department)
            )
            conn.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash('Email already registered or DB error.', 'danger')
        finally:
            cursor.close()
            conn.close()
    return render_template('register.html')
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM document_requests WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('dashboard.html', requests=requests)
@app.route('/request', methods=['GET','POST'])
def request_form():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))
    if request.method == 'POST':
        doc_type = request.form['document_type'].strip()
        year = request.form.get('year_of_issue','').strip()
        details = request.form.get('additional_details','').strip()
        file_name = None
        enrollment_no = request.form.get('enrollment_no','').strip()
        department = request.form.get('department','').strip()

        uploaded = request.files.get('file')
        if uploaded and uploaded.filename:
            if allowed_file(uploaded.filename):
                filename = secure_filename(uploaded.filename)
                filename = f"{session['user_id']}_{int(__import__('time').time())}_{filename}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded.save(path)
                file_name = filename
            else:
                flash('File type not allowed.', 'danger')
                return redirect(request.url)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
    "INSERT INTO document_requests (user_id, enrollment_no, department, document_type, year_of_issue, additional_details, file_name) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
    (session['user_id'], enrollment_no, department, doc_type, year, details, file_name)
)
        conn.commit()
        cursor.close()
        conn.close()
        flash('Request submitted successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('request_form.html')
@app.route('/verification_result')
def verification_result():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM document_requests WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('verification_result.html', requests=requests)
@app.route('/download_certificate/<int:req_id>')
def download_certificate(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
    SELECT dr.*, u.name, 
       COALESCE(dr.enrollment_no, u.enrollment_no) AS enrollment_no,
       COALESCE(dr.department, u.department) AS department
FROM document_requests dr
JOIN users u ON dr.user_id = u.id
WHERE dr.id = %s
""", (req_id,))
    rec = cursor.fetchone()
    cursor.close()
    conn.close()

    if not rec:
        flash('Record not found', 'danger')
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and session.get('user_id') != rec['user_id']:
        flash('Not authorized', 'danger')
        return redirect(url_for('dashboard'))

    # Render certificate template
    rendered = render_template('verification_result.html', single=rec, base_url=request.host_url)
    resp = make_response(rendered)
    resp.headers['Content-Type'] = 'text/html'
    resp.headers['Content-Disposition'] = f'attachment; filename=verification_{req_id}.html'
    return resp

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
  SELECT dr.*, u.name, u.email
  FROM document_requests dr
  JOIN users u ON dr.user_id = u.id
  ORDER BY dr.created_at DESC
""")
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin_dashboard.html', requests=requests)
@app.route('/update_status/<int:req_id>/<status>')
def update_status(req_id, status):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if status not in ('Approved','Rejected'):
        flash('Invalid status', 'danger')
        return redirect(url_for('admin_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE document_requests SET status=%s WHERE id=%s", (status, req_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash(f'Request {status}.', 'success')
    return redirect(url_for('admin_dashboard'))
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM document_requests WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    records = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('history.html', records=records)
if __name__ == '__main__':
    app.run(debug=True)
