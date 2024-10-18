from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, send_file, make_response, jsonify

from flask_sqlalchemy import SQLAlchemy

from collections import defaultdict

from datetime import datetime

import pandas as pd

import re, os, werkzeug, random, io, bcrypt

from io import BytesIO
from reportlab.lib.pagesizes import letter, A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak, Spacer

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from functools import wraps

app = Flask(__name__)
app.secret_key = "vthfgMB@a_zizD~v~$RA;.Ba"

# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"

# create the extension
db = SQLAlchemy()
# initialize the app with the extension
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access this page."
login_manager.login_message_category = "error"
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id))

# Base Model with common functionality
class BaseModel(db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    dateCreated = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, name):
        self.name = name

    def __repr__(self) -> str:
        return f"{self.id} - {self.name} - {self.dateCreated}"

    def days_ago(self):
        today = datetime.utcnow().date()
        created_date = self.dateCreated.date()

        years_diff = today.year - created_date.year
        months_diff = today.month - created_date.month
        days_diff = today.day - created_date.day

        if years_diff > 0:
            return f"{years_diff} {'Year' if years_diff == 1 else 'Years'} Ago"
        elif months_diff > 0:
            return f"{months_diff} {'Month' if months_diff == 1 else 'Months'} Ago"
        elif days_diff > 1:
            return f"{days_diff} Days Ago"
        elif days_diff == 1:
            return "Yesterday"
        else:
            return "Today"

    def formatted_date(self):
        return self.dateCreated.strftime('%d-%m-%y')

# Crop Model
class Crops(BaseModel):
    __tablename__ = 'crops'

# Trial Model
class Trials(BaseModel):
    __tablename__ = 'trials'
    abbreviation = db.Column(db.String(100), unique=True, nullable=False)

    def __init__(self, name, abbreviation):
        super().__init__(name)
        self.abbreviation = abbreviation

# Zone Model
class Zones(BaseModel):
    __tablename__ = 'zones'

# Seasons Model
class Seasons(BaseModel):
    __tablename__ = 'seasons'

# Ecosystem Model
class Ecosystem(BaseModel):
    __tablename__ = 'ecosystems'

class Users(BaseModel, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    designation = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    crops = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    first_login = db.Column(db.Integer, default=0)
    directorRequest = db.Column(db.Integer, default=0)
    headOfCropImprovementRequest = db.Column(db.Integer, default=0)
    directorPermission = db.Column(db.String(10), default="Rejected")
    headOfCropImprovementPermission = db.Column(db.String(10), default="Rejected")

    def __init__(self, name, designation, phone, email, crops, password):
        super().__init__(name)
        self.designation = designation
        self.phone = phone
        self.email = email
        self.crops = crops
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.first_login = 0
        self.directorRequest = 0
        self.headOfCropImprovementRequest = 0

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def grant_director_permission(self):
        self.directorPermission = "Granted"
        db.session.commit()

    def revoke_director_permission(self):
        self.directorPermission = "Rejected"
        self.directorRequest = 0
        db.session.commit()

    def grant_headOfCropImprovement_permission(self):
        self.headOfCropImprovementPermission = "Granted"
        db.session.commit()

    def revoke_headOfCropImprovement_permission(self):
        self.headOfCropImprovementPermission = "Rejected"
        self.headOfCropImprovementRequest = 0
        db.session.commit()

# Processed Model
class Processed(db.Model):
    __tablename__ = 'processed'
    id = db.Column(db.Integer, primary_key=True)
    
    year = db.Column(db.Integer, nullable=False)
    crop = db.Column(db.String(100), nullable=False)
    season = db.Column(db.String(100), nullable=False)
    zone = db.Column(db.String(100), nullable=False)
    ecosystem = db.Column(db.String(100), nullable=False)
    abbreviation = db.Column(db.String(100), nullable=False)
    entries = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(100), nullable=False, unique=True)
    pedigree = db.Column(db.String(100), nullable=False)
    centres = db.Column(db.String(100), nullable=False)

    def __init__(self, entries, crop, season, abbreviation, ecosystem, zone, year, code, pedigree, centres):
        self.entries = entries
        self.crop = crop
        self.season = season
        self.abbreviation = abbreviation
        self.ecosystem = ecosystem
        self.zone = zone
        self.year = year
        self.code = code
        self.pedigree = pedigree
        self.centres = centres

class NewProcessed(db.Model):
    __tablename__ = 'new_processed'
    id = db.Column(db.Integer, primary_key=True)
    
    year = db.Column(db.Integer, nullable=False)
    crop = db.Column(db.String(100), nullable=False)
    season = db.Column(db.String(100), nullable=False)
    zone = db.Column(db.String(100), nullable=False)
    ecosystem = db.Column(db.String(100), nullable=False)
    abbreviation = db.Column(db.String(100), nullable=False)
    entries = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(100), nullable=False, unique=True)
    pedigree = db.Column(db.String(100), nullable=False)
    centres = db.Column(db.String(100), nullable=False)

    def __init__(self, entries, crop, season, abbreviation, ecosystem, zone, year, code, pedigree, centres):
        self.entries = entries
        self.crop = crop
        self.season = season
        self.abbreviation = abbreviation
        self.ecosystem = ecosystem
        self.zone = zone
        self.year = year
        self.code = code
        self.pedigree = pedigree
        self.centres = centres

with app.app_context():
    db.create_all()

def capitalize_every_word(sentence):
    def capitalize_word(match):
        word = match.group(0)
        if '/' in word:
            parts = word.split('/')
            capitalized_parts = [part.capitalize() for part in parts]
            return '/'.join(capitalized_parts)
        else:
            return word.capitalize()

    # Use regular expression to find words
    pattern = r'\b\w+\b'
    result = re.sub(pattern, capitalize_word, sentence)

    return result

def capitalize_word(word):
    return word.upper()

def get_crops_and_trials():
    result = defaultdict(list)

    crops = db.session.query(Crops.name).all()
    result['cropName'] = [crop[0] for crop in crops]

    seasons = db.session.query(Seasons.name).all()
    result['seasonName'] = [season[0] for season in seasons]

    zones = db.session.query(Zones.name).all()
    result['zoneName'] = [zone[0] for zone in zones]

    ecosystems = db.session.query(Ecosystem.name).all()
    result['ecosystemName'] = [ecosystem[0] for ecosystem in ecosystems]

    trials = db.session.query(Trials.name, Trials.abbreviation).all()
    result['trial'] = {trial[0]: trial[1] for trial in trials}

    # Calculate year options
    current_year = datetime.now().year
    previous_year = current_year - 1
    year_options = [f"{previous_year}-{str(current_year)[-2:]}", f"{current_year}-{str(current_year + 1)[-2:]}"]
    result['yearOptions'] = year_options

    return result

def get_counts():
    return {
        "User": Users.query.filter(Users.designation != 'Admin').count(),
        "Crop": Crops.query.count(),
        "Trial": Trials.query.count(),
        "Zone": Zones.query.count(),
        "Season": Seasons.query.count(),
        "Ecosystem": Ecosystem.query.count(),
    }

def get_unique_values(session):
    unique_values = {}
    
    unique_values['Crops'] = session.query(NewProcessed.crop).distinct().scalar()
    unique_values['Year'] = session.query(NewProcessed.year).distinct().scalar()
    unique_values['Season'] = session.query(NewProcessed.season).distinct().scalar()
    unique_values['Zone'] = session.query(NewProcessed.zone).distinct().scalar()
    unique_values['Ecosystem'] = session.query(NewProcessed.ecosystem).distinct().scalar()
    unique_values['Abbreviation'] = session.query(NewProcessed.abbreviation).distinct().scalar()

    return unique_values

def get_unique_years():
    unique_years_query = Processed.query.with_entities(Processed.year).distinct()
    unique_years = [year[0] for year in unique_years_query]
    sorted_years = sorted(unique_years, key=lambda x: int(x.split('-')[0]))
    return sorted_years

def get_previous_years():
    current_date = datetime.now()
    current_year = current_date.year
    current_month = current_date.month

    # Query the distinct years from the Processed table
    previous_years_query = db.session.query(Processed.year).distinct().all()
    previous_years = [year[0] for year in previous_years_query]

    # Extract start years and sort them
    sorted_years = sorted(previous_years, key=lambda x: int(x.split('-')[0]))

    # Filter years based on the current date
    filtered_years = []
    for year in sorted_years:
        start_year = int(year.split('-')[0])
        if start_year < current_year - 1 or (start_year == current_year - 1 and current_month > 8):
            filtered_years.append(year)
        elif start_year == current_year - 1 and current_month <= 8:
            continue  # Skip the previous academic year if it's before September
        elif start_year == current_year and current_month > 8:
            filtered_years.append(year)  # Include the current academic year if it's after August
    return filtered_years

def fetch_unique_trials():
    valid_years = get_previous_years()

    # Query to get distinct combinations of abbreviation, ecosystem, and zone for the valid years
    trials_query = (db.session.query(Processed.abbreviation, Processed.ecosystem, Processed.zone)
                    .filter(Processed.year.in_(valid_years))
                    .distinct()
                    .all())

    # Create the unique trial strings
    unique_trials = set()
    for abbreviation, ecosystem, zone in trials_query:
        if ecosystem != 'Utera':
            trial = f"{abbreviation}-{ecosystem}-{zone}"
        else:
            trial = f"{abbreviation}-{ecosystem}"
        unique_trials.add(trial)

    return sorted(unique_trials)

def fetch_unique_entries():
    filtered_years = get_previous_years()
    unique_entries = db.session.query(Processed.entries).filter(Processed.year.in_(filtered_years)).distinct().order_by(Processed.entries).all()
    sorted_entries_list = [entry[0] for entry in unique_entries]
    return sorted_entries_list

def fetch_unique_centres():
    filtered_years = get_previous_years()
    unique_centres = db.session.query(Processed.centres).filter(Processed.year.in_(filtered_years)).distinct().order_by(Processed.centres).all()
    sorted_centres_list = [entry[0] for entry in unique_centres]
    return sorted_centres_list

def fetch_unique_checks():
    filtered_years = get_previous_years()
    unique_checks = db.session.query(Processed.entries).filter(Processed.entries.like('%©%')).filter(Processed.year.in_(filtered_years)).distinct().all()
    unique_checks_list = [entry[0] for entry in unique_checks]
    return unique_checks_list

def get_unique_parents():
    filtered_years = get_previous_years()
    unique_parents = set()
    pattern = re.compile(r'\(.*?\)|[^xX]+')
    
    pedigrees = db.session.query(Processed.pedigree).filter(Processed.year.in_(filtered_years)).all()
    
    for pedigree_tuple in pedigrees:
        pedigree = pedigree_tuple[0]
        parents = pattern.findall(pedigree)
        parents = [parent.strip() for parent in parents if parent.strip()]
        unique_parents.update(parents)
    
    return sorted(unique_parents, key=str.lower)

def is_positive_integer(value):
    try:
        int_value = int(value)
        return int_value >= 0
    except ValueError:
        return False

def role_required(required_roles):
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            if current_user.designation not in required_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return func(*args, **kwargs)
        return decorated_function
    return decorator

def two_factor_authenticated(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if session.get("twoFactorAuthentication") == "Verified":
            return func(*args, **kwargs)
        else:
            flash("Two-factor authentication is required to access this page.", "error")
            return redirect(url_for("home"))
    return decorated_view

@app.route("/login")
def login():
    return render_template('login.html', pageTitle = "Login")

@app.route("/login-user", methods=['post'])
def loginValidation():
    if request.method == 'POST':
        email = request.form['emailAddress'].strip()
        password =  request.form['password'].strip()

        user = Users.query.filter_by(email=email).first()
        if user:
            if user.check_password(password):
                if user.first_login == 0:
                    session['temp'] = user.email
                    flash('Please reset your password as your account was initially set up by an administrator.', 'error')
                    return redirect(url_for('reset_password'))
                else:
                    login_user(user, remember=True)
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
        flash('Invalid credentials. Please double-check your email and password and try again.', 'error')
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route("/account")
@login_required
def account():
    return render_template('account.html', pageTitle = "Account")

@app.route('/account-update', methods=['POST'])
@login_required
def accountUpdate():
    user = Users.query.filter_by(email=current_user.email).first()
    if not user:
        flash('An error occurred while updating your account. Please try again later.', 'error')
        return redirect(url_for('account'))

    fullName = capitalize_every_word(request.form.get('fullName', '').strip())
    email = request.form.get('emailAddress', '').strip()
    phone = request.form.get('phone', '').strip()

    try:
        # Validate email format using a regular expression
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, email):
            raise ValueError('Invalid email address format. Please enter a valid email address.')

        # Check if the email or phone already exists in the database
        existing_user = Users.query.filter((Users.email == email) | (Users.phone == phone)).filter(Users.id != user.id).first()

        if existing_user:
            if existing_user.email == email:
                flash('The provided email address is already associated with another account. Please use a different email address.', 'error')
            else:
                flash('The provided phone number is already associated with another account. Please use a different phone number.', 'error')
            return redirect(url_for('account'))
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('account'))

    changes_made = False

    if fullName != user.name or email != user.email or phone != user.phone:
        user.name = fullName
        user.email = email
        user.phone = phone
        changes_made = True

    if not changes_made:
        flash('No changes needed. Please make modifications to update your account.', 'error')
    else:
        db.session.commit()
        session.clear()
        flash('Your account has been successfully updated, and you have been logged out.', 'success')
        return redirect(url_for('login'))

    return redirect(url_for('account'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def changePassword():
    if request.method == 'POST':
        password = request.form['password']
        confirmPassword = request.form['confirmPassword']
        if password == confirmPassword:
            user = Users.query.filter_by(email=current_user.email).first()
            if user:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                logout_user()
                flash('Password changed successfully. You can now login with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found. Please contact support for assistance.', 'error')
        else:
            flash('Passwords do not match. Please ensure both passwords are identical and try again.', 'error')
    

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        password = request.form.get('password')
        confirmPassword = request.form.get('confirmPassword')
        
        if password == confirmPassword:
            user = Users.query.filter_by(email=session['temp']).first()
            if user:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                user.password = hashed_password
                user.first_login = 1
                db.session.commit()
                session.pop('temp', None)
                flash('Password changed successfully. You can now sign in with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found. Please contact support for assistance.', 'error')
        else:
            flash('Passwords do not match. Please ensure both passwords are identical and try again.', 'error')
    return render_template('changePassword.html')

@app.route("/logout")
@login_required
def logout():
    session["twoFactorAuthentication"] = None
    logout_user()
    return redirect(url_for('login'))

@app.route("/")
@login_required
def home():
    return render_template('home.html', pageTitle="Home")

# Two Factor Authentication
@app.route("/two-factor-authentication", methods=['GET', 'POST'])
@login_required
@role_required(["C.I Head", "Director"])
def twoFactorAuthentication():
    if request.method == "POST":
            directorPassword = request.form["directorPassword"]
            headOfCropImprovementPassword = request.form["headOfCropImprovementPassword"]

            director = Users.query.filter_by(email="director.iior@icar.gov.in").first()
            headOfCropImprovement = Users.query.filter_by(email="vdinesh.kumar1@icar.gov.in").first()

            if director.check_password(directorPassword) and headOfCropImprovement.check_password(headOfCropImprovementPassword):
                session["twoFactorAuthentication"] = "Verified"
                return redirect(url_for("randomCodeGenerator"))
            else:
                flash("You Entered Wrong Password", "error")
                return redirect(url_for("home"))
    
# Random Code Generator
@app.route("/random-code-generator", methods=['GET', 'POST'])
@login_required
@role_required(["C.I Head", "Director"])
@two_factor_authenticated
def randomCodeGenerator():
    if request.method == "POST":
        data = NewProcessed.query.all()
        if not data:
            crop_select = request.form["cropSelect"]
            season_select = request.form["seasonSelect"]

            zone_select = '' if crop_select == 'Castor' else request.form["zoneSelect"]

            ecosystem_select = request.form["ecosystemSelect"]

            trial_select = request.form["trialSelect"]
            year_select = request.form["yearSelect"]
            
            entries_input = int(request.form["entriesInput"])
            starting_entry_code_input = int(request.form["startingEntryCodeInput"])

            uploaded_file = request.files["fileInput"]

            if uploaded_file:
                df = pd.read_excel(uploaded_file)

                df.fillna('-', inplace=True)

                num_rows = len(df)

                if entries_input != num_rows:
                    flash("The number of entries is not equal to the number of rows.", "error")
                    return redirect(url_for("home"))
                else:
                    ending_entry_code = starting_entry_code_input + (num_rows - 1)

                    df["Code"] = random.sample(range(starting_entry_code_input, ending_entry_code + 1), len(df))

                    for _, row in df.iterrows():
                        new_entry = NewProcessed(
                            year=year_select,
                            crop=crop_select,
                            season=season_select,
                            zone=zone_select,
                            ecosystem=ecosystem_select,
                            abbreviation=trial_select,
                            entries=row["Entries"],
                            code=row["Code"],
                            pedigree=row["Pedigree"],
                            centres=row["Centre"]
                        )
                        db.session.add(new_entry)
                    db.session.commit()
                    flash("Random Codes has been generated sucessfully for the given sheet.", "success")
                    return redirect(url_for("randomCodeGeneratorDownload"))
        else:
            flash("Before Generating Codes Again, Add the old Processed Items to Database.", "error")
            return redirect(url_for("randomCodeGeneratorDownload"))
    data = get_crops_and_trials()
    return render_template('RandomCodeGenerator.html', pageTitle = 'Random Code Generator for Co-Ordinated Trails', data = data)

# Random Code Generator
@app.route("/random-code-generator-download")
@login_required
@role_required(["C.I Head", "Director"])
@two_factor_authenticated
def randomCodeGeneratorDownload():
    data = NewProcessed.query.all()
    unique_items = get_unique_values(db.session)
    return render_template('RandomCodeGeneratorDownload.html', pageTitle = 'Download Random Code Generator for Co-Ordinated Trails', data = data, unique_items = unique_items)


def generate_label_pdf(data, crop):
    buffer = BytesIO()
    page_width, page_height = A4

    doc = SimpleDocTemplate(buffer, pagesize=(page_width, page_height), leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0)

    table_data = []

    if crop == "Castor":
        for i in range(0, len(data), 2):
            text1 = f"{data[i].season} - {data[i].year}\n{data[i].abbreviation} - {data[i].ecosystem}\n\n{data[i].code}"
            text2 = ""
            if i + 1 < len(data):
                text2 = f"{data[i + 1].season} - {data[i + 1].year}\n{data[i + 1].abbreviation} - {data[i + 1].ecosystem}\n\n{data[i + 1].code}"
            table_data.append([text1, text2])
    else:

        for i in range(0, len(data), 2):
            text1 = f"{data[i].season} - {data[i].year}\n{data[i].abbreviation} - {data[i].ecosystem} - {data[i].zone}\n\n{data[i].code}"
            text2 = ""
            if i + 1 < len(data):
                text2 = f"{data[i + 1].season} - {data[i + 1].year}\n{data[i + 1].abbreviation} - {data[i + 1].ecosystem} - {data[i + 1].zone}\n\n{data[i + 1].code}"
            table_data.append([text1, text2])
            
    cell_width = page_width / 2
    cell_height = (page_height - 20) / 13

    tables = []
    
    for i in range(0, len(table_data), 13):
        page_data = table_data[i:i + 13]
        table = Table(page_data, colWidths=[cell_width, cell_width], rowHeights=[cell_height] * len(page_data))
        
        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),  # White background
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),  # Black text
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),          # Center text
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),         # Center text vertically
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),          # Zero padding
            ('GRID', (0, 0), (-1, -1), 1, colors.black),    # Grid lines
            ('LINEBELOW', (0, 0), (-1, -1), 1, colors.black) # Divider line under text
        ])

        table.setStyle(style)
        tables.append(table)
        if i + 13 < len(table_data):
            tables.append(PageBreak())

    doc.build(tables)

    buffer.seek(0)
    return buffer

@app.route('/generate-labels')
@login_required
@role_required(["C.I Head", "Director"])
@two_factor_authenticated
def generate_labels():
    data = NewProcessed.query.order_by(NewProcessed.code).all()
    unique_items = get_unique_values(db.session)
    pdf_buffer = generate_label_pdf(data, crop = unique_items['Crops'])
    
    if unique_items['Crops'] == "Castor":
        custom_filename = f"{unique_items['Crops']} - {unique_items['Year']} - {unique_items['Season']} - labels.pdf"
    else:
        custom_filename = f"{unique_items['Crops']} - {unique_items['Year']} - {unique_items['Season']} - {unique_items['Zone']} - labels.pdf"
    
    pdf_buffer.seek(0)
    return send_file(pdf_buffer, as_attachment=True, download_name=custom_filename, mimetype='application/pdf')

@app.route('/generate-pdf')
@login_required
@role_required(["C.I Head", "Director"])
@two_factor_authenticated
def download_codes():
    data = NewProcessed.query.all()

    unique_items = get_unique_values(db.session)

    return generate_codes(data, unique_items)

def generate_codes(data, unique_items):
    pdf_buffer = BytesIO()
    page_width, page_height = A4

    table_width = page_width * 0.8
    column_widths = [table_width * 0.1, table_width * 0.4, table_width * 0.4]

    year = int(unique_items['Year'].split('-')[0])

    filename = f"{unique_items['Crops']}-({unique_items['Year']})-{unique_items['Season']}-({unique_items['Zone']}).pdf"

    doc = SimpleDocTemplate(pdf_buffer, pagesize=A4)

    table_data = [["#", "Entries", "Code"]]
    for row in data:
        table_data.append([row.id, row.entries, str(year) + ' - ' + str(row.code)])

    table = Table(table_data, colWidths=column_widths)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))

    elements = []
    styles = getSampleStyleSheet()

    pdf_heading = f"{unique_items['Crops']} - {unique_items['Season']} \n {unique_items['Abbreviation']} - {unique_items['Ecosystem']} - {unique_items['Zone']} - {unique_items['Year']}"
    elements.append(Paragraph(pdf_heading, styles['Title']))
    elements.append(table)
    doc.build(elements)

    pdf_buffer.seek(0)
    pdf_content = pdf_buffer.read()
    pdf_buffer.close()

    response = Response(pdf_content, content_type='application/pdf')

    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response

@app.route('/add_to_database')
@login_required
@role_required(["C.I Head", "Director"])
@two_factor_authenticated
def add_to_database():
    try:
        new_processed_records = NewProcessed.query.all()

        if new_processed_records:
            for new_processed_record in new_processed_records:
                processed_record = Processed(
                    entries=new_processed_record.entries,
                    crop=new_processed_record.crop,
                    season=new_processed_record.season,
                    abbreviation=new_processed_record.abbreviation,
                    ecosystem=new_processed_record.ecosystem,
                    zone=new_processed_record.zone,
                    year=new_processed_record.year,
                    code=new_processed_record.code,
                    pedigree=new_processed_record.pedigree,
                    centres=new_processed_record.centres
                )
                db.session.add(processed_record)
            db.session.commit()
            NewProcessed.query.delete()
            db.session.commit()

            flash('Data has been successfully processed and added to the main database.', 'success')
        else:
            flash('No records found in the queue for processing.', 'error')

    except Exception as e:
        flash(f'An error occurred while processing the data: {str(e)}', 'error')

    return redirect(url_for('randomCodeGenerator'))

@app.route('/clear-database', methods=['GET', 'POST'])
@login_required
@role_required(["C.I Head", "Director"])
@two_factor_authenticated
def clear_database():
    try:
        db.session.query(NewProcessed).delete()
        db.session.commit()
        flash("Database cleared successfully.", "success")
        return redirect(url_for('randomCodeGenerator'))
    except Exception as e:
        db.session.rollback()
        flash("Error clearing the database: " + str(e), "error")
        return redirect(url_for('randomCodeGenerator'))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html', pageTitle="Dashboard")

@app.route("/dashboard-by-year", methods=['GET', 'POST'])
@login_required
def dashboardByYear():
    years = get_previous_years()
    if request.method == 'POST':
        year = request.form['year']
        data = Processed.query.filter_by(year=year).order_by(Processed.code.asc()).with_entities(
            Processed.abbreviation, Processed.ecosystem, Processed.zone, Processed.entries, Processed.code, Processed.pedigree, Processed.centres
        ).all()
        
        # Processing data to group by (ecosystem, zone)
        grouped_data = {}
        for row in data:
            group_key = f"{row.abbreviation}-{row.ecosystem}-{row.zone}" if row.ecosystem != 'Utera' else f"{row.abbreviation}-{row.ecosystem}"
            if group_key not in grouped_data:
                grouped_data[group_key] = {
                    "entries": 0,
                    "codes": []
                }
            grouped_data[group_key]["entries"] += 1
            grouped_data[group_key]["codes"].append(row.code)
        
        # Prepare the final data for rendering
        processed_data = []
        for group_key, details in grouped_data.items():
            codes_sorted = sorted(details["codes"])
            code_range = f"{codes_sorted[0]}-{codes_sorted[-1]}"
            processed_data.append({
                "group_key": group_key,
                "entries": details["entries"],
                "code_range": code_range
            })
        
        return render_template('dashboardYear.html', pageTitle="By Year - Dashboard", selected_year=year, years=years, data=processed_data)

    return render_template('dashboardYear.html', pageTitle="By Year - Dashboard", years=years)

@app.route("/dashboard-by-year-and-trial", methods=['GET', 'POST'])
@login_required
def dashboardByYearandTrial():
    years = get_previous_years()
    trials = fetch_unique_trials()

    if request.method == 'POST':
        year = request.form['year']
        trial = request.form['trial']

        # Split the trial string to get abbreviation, ecosystem, and possibly zone
        trial_parts = trial.split('-', 2)
        abbreviation = trial_parts[0]
        ecosystem = trial_parts[1]
        zone = trial_parts[2] if len(trial_parts) == 3 else None

        # Build the query based on the presence of zone
        if zone:
            data = (Processed.query
                    .filter_by(year=year)
                    .filter_by(abbreviation=abbreviation)
                    .filter_by(ecosystem=ecosystem)
                    .filter_by(zone=zone)
                    .order_by(Processed.code.asc())
                    .with_entities(Processed.year, Processed.entries, Processed.abbreviation, Processed.ecosystem, Processed.zone, Processed.pedigree, Processed.centres)
                    .all())
        else:
            data = (Processed.query
                    .filter_by(year=year)
                    .filter_by(abbreviation=abbreviation)
                    .filter_by(ecosystem=ecosystem)
                    .filter(Processed.zone.is_(None))
                    .order_by(Processed.code.asc())
                    .with_entities(Processed.year, Processed.entries, Processed.abbreviation, Processed.ecosystem, Processed.zone, Processed.pedigree, Processed.centres)
                    .all())

        print(data)
        return render_template('dashboardByYearandTrial.html', pageTitle="By Year and Trial - Dashboard", years=years, trials=trials, data=data, selected_year=year, selected_trial=trial)

    return render_template('dashboardByYearandTrial.html', pageTitle="By Year and Trial - Dashboard", years=years, trials=trials)

@app.route("/dashboard-by-parent", methods=['GET','POST'])
@login_required
def dashboardByParent():
    parent_items = get_unique_parents()
    valid_years = get_previous_years()

    if request.method == 'POST':
        parent = request.form['parent']
        data = (Processed.query
                .filter(Processed.pedigree.like(f'%{parent}%'))
                .filter(Processed.year.in_(valid_years))
                .order_by(Processed.year, Processed.code.asc())
                .with_entities(Processed.year, Processed.entries, Processed.abbreviation, Processed.ecosystem, Processed.zone, Processed.code, Processed.pedigree, Processed.centres)
                .all())
        return render_template('dashboardByParent.html', pageTitle="By Parent - Dashboard", parentItems=parent_items, data=data, parent=parent)

    return render_template('dashboardByParent.html', pageTitle="By Parent - Dashboard", parentItems=parent_items)

@app.route("/dashboard-by-entry", methods=['GET', 'POST'])
@login_required
def dashboardByEntry():
    unique_entries = [entry for entry in fetch_unique_entries() if '©' not in entry]
    valid_years = get_previous_years()

    if request.method == 'POST':
        entry = request.form['entry']
        data = (Processed.query
                .filter_by(entries=entry)
                .filter(Processed.year.in_(valid_years))
                .order_by(Processed.entries, Processed.code.asc())
                .with_entities(Processed.year, Processed.abbreviation, Processed.ecosystem, Processed.zone, Processed.pedigree, Processed.centres)
                .all())
        return render_template('dashboardByEntry.html', pageTitle="By Entry - Dashboard", unique_entries=unique_entries, entry=entry, data=data)

    return render_template('dashboardByEntry.html', pageTitle="By Entry - Dashboard", unique_entries=unique_entries)

@app.route("/dashboard-by-centre", methods=['GET','POST'])
@login_required
def dashboardByCentre():
    unique_centres = fetch_unique_centres()
    valid_years = get_previous_years()

    if request.method == 'POST':
        centre = request.form['centre']
        data = (Processed.query
                .filter_by(centres=centre)
                .filter(Processed.year.in_(valid_years))
                .order_by(Processed.centres, Processed.code.asc())
                .with_entities(Processed.year, Processed.entries, Processed.abbreviation, Processed.ecosystem, Processed.zone, Processed.pedigree)
                .all())
        return render_template('dashboardByCentre.html', pageTitle="By Centre - Dashboard", unique_centres=unique_centres, centre=centre, data=data)

    return render_template('dashboardByCentre.html', pageTitle="By Centre - Dashboard", unique_centres=unique_centres)

@app.route("/dashboard-by-check", methods=['GET','POST'])
@login_required
def dashboardByCheck():
    unique_checks = fetch_unique_checks()
    valid_years = get_previous_years()

    if request.method == 'POST':
        check = request.form['check']
        data = (Processed.query
                .filter_by(entries=check)
                .filter(Processed.year.in_(valid_years))
                .order_by(Processed.code.asc())
                .with_entities(Processed.year, Processed.abbreviation, Processed.ecosystem, Processed.zone)
                .all())
        return render_template('dashboardByCheck.html', pageTitle="By Check - Dashboard", unique_checks=unique_checks, check=check, data=data)

    return render_template('dashboardByCheck.html', pageTitle="By Check - Dashboard", unique_checks=unique_checks)

@app.route("/team")
def team():
    return render_template('team.html', pageTitle="Team")

# Admin Home
@app.route("/admin-home")
@login_required
@role_required(["Admin"])
def adminHome():
    counts = get_counts()
    data = get_crops_and_trials()
    years = get_unique_years()
    return render_template('adminHome.html', pageTitle="Admin - Home", counts = counts, trialData=data['trial'], years = years)

@app.route("/admin-users")
@login_required
@role_required(["Admin"])
def adminUsers():
    allUsers = Users.query.filter(Users.designation != 'Admin').order_by(Users.designation.asc(), Users.name.asc()).all()
    allCrops = Crops.query.with_entities(Crops.name).order_by(Crops.name.asc()).all()
    return render_template('adminUsers.html', pageTitle = "Admin - Users", allUsers  = allUsers, allCrops = allCrops)

@app.route("/admin-add-users", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminRegisterUsers():
    if request.method == 'POST':
        designation = capitalize_every_word(request.form['designation'])
        fullName = capitalize_every_word(request.form['fullName'].strip())
        crops = request.form['crops']
        email = request.form['emailAddress'].strip()
        phone = request.form['phone'].strip()
        password = request.form['password'].strip()

        existing_user = Users.query.filter((Users.email == email) | (Users.phone == phone)).first()

        if existing_user:
            if existing_user.email == email:
                flash('Sorry, the provided email address is already registered. Please use a different email address.', 'error')
            else:
                flash('Sorry, the provided phone number is already registered. Please use a different phone number.', 'error')
        else:
            newUser = Users(name=fullName, email=email, phone=phone, designation=designation, crops=crops, password=password)
            db.session.add(newUser)
            db.session.commit()
        
        return redirect(url_for('adminUsers'))

@app.route("/admin-reset-user-password", methods=['POST'])
@login_required
@role_required(["Admin"])
def adminResetUserPassword():
    try:
        email = request.form['emailAddress'].strip()
        password = request.form['password'].strip()

        user = Users.query.filter_by(email=email).first_or_404()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = hashed_password
        user.first_login = 0
        db.session.commit()

        flash('Password for user {} has been changed successfully. They can now log in with their new password.'.format(user.email), 'success')

    except Exception as e:
        flash('An error occurred while resetting the password: {}'.format(str(e)), 'error')

    return redirect(url_for('adminUsers'))

# Admin User Update
@app.route("/admin-user-update/<int:id>", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminUserUpdate(id):
    if request.method == 'POST':
        fullName = capitalize_every_word(request.form['fullName'].strip())
        email = request.form['emailAddress'].strip()
        phone = request.form['phone'].strip()

        updateUser = Users.query.filter_by(id = id).first()

        updateUser.name = fullName
        updateUser.email = email
        updateUser.phone = phone

        db.session.add(updateUser)
        db.session.commit()
        return redirect(url_for('adminUsers'))

# Admin User Delete
@app.route("/admin-user-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminUserDelete(id):
    deleteUser = Users.query.filter_by(id = id).first()
    db.session.delete(deleteUser)
    db.session.commit()
    return redirect(url_for('adminUsers'))

# Admin Crops
@app.route("/admin-crops", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminCrops():
    if request.method == 'POST':
        cropName = capitalize_every_word(request.form['cropName'].strip())
        
        existing_crop = Crops.query.filter(Crops.name == cropName).first()

        if not existing_crop:
            crops = Crops(name = cropName)
            db.session.add(crops)
            db.session.commit()
        else:
            flash("Crop already exists", "error")

        
        return redirect(url_for('adminCrops'))
    allCrops = Crops.query.order_by(Crops.name.asc()).all()
    return render_template('adminCrops.html', pageTitle = "Admin - Crops", allCrops = allCrops)

# Admin Crops Update
@app.route("/admin-crops-update/<int:id>", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminCropsUpdate(id):
    if request.method == 'POST':
        cropName = request.form['cropName']
        # Capitalize the first letter of each word
        cropName = capitalize_every_word(cropName)
        updateCrop = Crops.query.filter_by(id = id).first()
        updateCrop.name = cropName
        db.session.add(updateCrop)
        db.session.commit()
        return redirect(url_for('adminCrops'))

# Admin Crop Delete
@app.route("/admin-crops-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminCropsDelete(id):
    deleteCrop = Crops.query.filter_by(id = id).first()
    db.session.delete(deleteCrop)
    db.session.commit()
    return redirect(url_for('adminCrops'))

# Admin Trials
@app.route("/admin-trials", methods=['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminTrials():
    if request.method == 'POST':
        trialName = capitalize_every_word(request.form['trialName'])
        trialAbbreviation = capitalize_word(request.form['trialAbbreviation'])
        
        existing_trial = Trials.query.filter_by(abbreviation = trialAbbreviation).first()
        
        if not existing_trial:
            new_trial = Trials(name=trialName, abbreviation=trialAbbreviation)
            db.session.add(new_trial)
            db.session.commit()
        else:
            flash("Trial already exists", "error")
        
        return redirect(url_for('adminTrials'))
    
    allTrials = Trials.query.order_by(Trials.name.asc()).all()
    return render_template('adminTrials.html', pageTitle="Admin - Trials", allTrials=allTrials)


# Admin Trial Update
@app.route("/admin-trial-update/<int:id>", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminTrialUpdate(id):
    if request.method == 'POST':
        trialName = capitalize_every_word(request.form['trialName'])
        trialAbbreviation = capitalize_word(request.form['trialAbbreviation'])

        updateTrial = Trials.query.filter_by(id = id).first()

        updateTrial.name = trialName
        updateTrial.abbreviation = trialAbbreviation

        db.session.add(updateTrial)
        db.session.commit()
        return redirect(url_for('adminTrials'))

# Admin Trials Delete
@app.route("/admin-trials-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminTrailsDelete(id):
    deleteTrail = Trials.query.filter_by(id = id).first()
    db.session.delete(deleteTrail)
    db.session.commit()
    return redirect(url_for('adminTrials'))

# Admin Zones
@app.route("/admin-zones", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminZones():
    if request.method == 'POST':
        zoneName = request.form['zoneName']
        zones = Zones(name = zoneName)
        db.session.add(zones)
        db.session.commit()
        return redirect(url_for('adminZones'))
    allZones = Zones.query.order_by(Zones.name.asc()).all()
    return render_template('adminZones.html', pageTitle = "Admin - Zones", allZones = allZones)

# Admin Zones Delete
@app.route("/admin-zones-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminZonesDelete(id):
    deleteZone = Zones.query.filter_by(id = id).first()
    db.session.delete(deleteZone)
    db.session.commit()
    return redirect(url_for('adminZones'))


# Admin Seasons
@app.route("/admin-seasons", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminSeasons():
    if request.method == 'POST':
        seasonName = capitalize_every_word(request.form['seasonName'])

        existing_season = Seasons.query.filter_by(name=seasonName).first()
        
        if not existing_season:
            seasons = Seasons(name = seasonName)
            db.session.add(seasons)
            db.session.commit()
        else:
            flash("Season already exists", "error")
        
        return redirect(url_for('adminSeasons'))
    allSeasons = Seasons.query.order_by(Seasons.name.asc()).all()
    return render_template('adminSeasons.html', pageTitle = "Admin - Seasons", allSeasons = allSeasons)

# Admin Seasons Update
@app.route("/admin-seasons-update/<int:id>", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminSeasonsUpdate(id):
    if request.method == 'POST':
        seasonName = capitalize_every_word(request.form['seasonName'])

        updateSeason = Seasons.query.filter_by(id = id).first()
        updateSeason.name = seasonName
        db.session.add(updateSeason)
        db.session.commit()
        return redirect(url_for('adminSeasons'))

# Admin Seasons Delete
@app.route("/admin-seasons-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminSeasonsDelete(id):
    deleteSeason = Seasons.query.filter_by(id = id).first()
    db.session.delete(deleteSeason)
    db.session.commit()
    return redirect(url_for('adminSeasons'))


@app.route("/admin-ecosystem", methods=['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminEcosystem():
    if request.method == 'POST':
        ecosystem_name = capitalize_every_word(request.form.get('ecosystemName'))

        existing_ecosystem = Ecosystem.query.filter_by(name=ecosystem_name).first()

        if not existing_ecosystem:
            ecosystem = Ecosystem(name=ecosystem_name)
            db.session.add(ecosystem)
            db.session.commit()
        else:
            flash("Ecosystem already exists", "error")

        return redirect(url_for('adminEcosystem'))

    # For GET request, retrieve and display all ecosystems
    all_ecosystems = Ecosystem.query.order_by(Ecosystem.name.asc()).all()
    return render_template('adminEcosystem.html', pageTitle="Admin - Ecosystems", allEcosystems=all_ecosystems)

# Admin Ecosystem Update
@app.route("/admin-ecosystem-update/<int:id>", methods = ['GET', 'POST'])
@login_required
@role_required(["Admin"])
def adminEcosystemUpdate(id):
    if request.method == 'POST':

        ecosystemName = capitalize_every_word(request.form['ecosystemName'])

        updateEcosystem = Ecosystem.query.filter_by(id = id).first()
        updateEcosystem.name = ecosystemName
        db.session.add(updateEcosystem)
        db.session.commit()
        return redirect(url_for('adminEcosystem'))

# Admin Ecosystem Delete
@app.route("/admin-ecosystem-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminEcosystemDelete(id):
    deleteEcosystem = Ecosystem.query.filter_by(id = id).first()
    db.session.delete(deleteEcosystem)
    db.session.commit()
    return redirect(url_for('adminEcosystem'))

@app.route("/admin-temp")
@login_required
@role_required(["Admin"])
def temp():
    all_processed = Processed.query.order_by(Processed.code.asc()).all()
    return render_template('temp.html', pageTitle="Admin - Temp", all_processed=all_processed)

@app.route("/admin-temp-delete/<int:id>")
@login_required
@role_required(["Admin"])
def adminTempDelete(id):
    deleteProcessed = Processed.query.filter_by(id = id).first()
    db.session.delete(deleteProcessed)
    db.session.commit()
    return redirect(url_for('temp'))

@app.errorhandler(404)
def page_not_found_error(error):
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run()