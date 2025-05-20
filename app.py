from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bionet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Species(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.String(500))

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return "Passwords do not match", 400

        if User.query.filter_by(username=username).first():
            return "Username already exists", 400

        new_user = User(fullname=fullname, username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    species_list = Species.query.all()
    return render_template('dashboard.html', species=species_list)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# API endpoint example
@app.route('/api/species', methods=['GET', 'POST'])
def api_species():
    if request.method == 'GET':
        species = Species.query.all()
        return jsonify([{'id': s.id, 'name': s.name, 'description': s.description} for s in species])
    if request.method == 'POST':
        data = request.json
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        if Species.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'Species already exists'}), 400
        new_species = Species(name=data['name'], description=data.get('description', ''))
        db.session.add(new_species)
        db.session.commit()
        return jsonify({'message': 'Species added', 'id': new_species.id}), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
