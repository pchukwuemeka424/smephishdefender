from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_bcrypt import Bcrypt
import tldextract
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.secret_key = 'your_secret_key'  # Change this to a secure random key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
from bs4 import BeautifulSoup
from googlesearch import search
import pickle
from sklearn.ensemble import RandomForestClassifier
import sklearn
import pickle
import numpy as np
login_manager = LoginManager()
login_manager.init_app(app)
from flask import session


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    telephone = db.Column(db.String(20))
    business_name = db.Column(db.String(100))
    business_type = db.Column(db.String(100))
    role = db.Column(db.String(20))

    # Define the foreign key relationship
    parent_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Define the relationship
    sub_users = db.relationship('User', backref=db.backref('parent', remote_side=[id]))

def digit_count(URL):
    digits = 0
    for i in URL:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(URL):
    letters = 0
    for i in URL:
        if i.isalpha():
            letters = letters + 1
    return letters

def get_ip_reputation(api_key, url):
    try:
        # Construct the API URL
        api_url = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{url}"
        
        # Make a GET request to the API
        response = requests.get(api_url)
        
        # Check if request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON response
            ip_reputation = response.json()
            return ip_reputation
        else:
            print(f"Failed to retrieve IP reputation. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return None

def get_root_domain(url):
    # Extract the domain using tldextract
    ext = tldextract.extract(url)
    # Construct and return the root domain
    return f"{ext.domain}.{ext.suffix}"




def sum_count_special_characters(URL):
    special_chars = ['@','?','-','=','.','#','%','+','$','!','*',',','//']

    num_special_chars = sum(char in special_chars for char in URL)
    return num_special_chars

from urllib.parse import urlparse
import re
def abnormal_url(URL):
    hostname = urlparse(URL).hostname
    hostname = str(hostname)
    match = re.search(hostname, URL)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

import re
#Use of IP or not in domain
def having_ip_address(URL):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', URL)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
    
    from urllib.parse import urlparse
import re
def abnormal_url(URL):
    hostname = urlparse(URL).hostname
    hostname = str(hostname)
    match = re.search(hostname, URL)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def httpSecured(URL):
    htp = urlparse(URL).scheme
    match = str(htp)
    if match == 'https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

from googlesearch import search
def google_index(URL):
    site = search(URL, 9)
    return 0 if site else 1

def Shortining_Service(URL):
    match = re.search(
                      'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      URL)
    if match:
        return 1
    else:
        return 0
import re

def is_free_hosting(url):
    # Define regular expression patterns for common free hosting services
    free_hosting_patterns = [
        r'\b(?:wordpress|blogspot|weebly|wix|tumblr)\b',  
        r'\b(?:github\.io|gitlab\.io|herokuapp\.com)\b',  
        r'\b(?:000webhost|biz\.ly|000webhostapp|googlesites|awsmppl)\b',
        r'\b(?:cloudfront|firebaseapp|firebaseio|appspot|azurewebsites)\b',
        r'\b(?:azurewebsites|azure-mobile|azurestaticapps|myfreesites|netlify)\b',
        r'\b(?:webcindario|beepworld|tripod|yola|ucoz)\b',
        r'\b(?:freehosting|freehostia|bplaced|byethost|infinityfree)\b',
        r'\b(?:awardspace|freewebhostingarea|profreehost|googledrive|dropbox)\b',
        r'\b(?:wordpress|blogspot|weebly|wix|tumblr)\b',
        r'\b(?:ipage|biz\.ly|awardspace|herokuapp|biz\.nf)\b',
        r'\b(?:biz\.nf|freewebspace|freesite|prophp|freedomains)\b',
        r'\b(?:gofreeserve|phpnet|zoho|zohosites|freehomepage)\b',
        r'\b(?:freeoda|freeflux|freeweb7|my3gb|goo)\b',
        r'\b(?:freehomepage|000space|phoenixsites|inube|2freehosting)\b',
        r'\b(?:3owl|ateam|webfreehosting|webfreehost|webs|epizy)\b',
        r'\b(?:aejux|awardspace|uwu|unity3d|webnode)\b',
        r'\b(?:sites\.google|spanglefish|myopera|moonfruit|freewebpages)\b',
        r'\b(?:wikipedia|fandom|webself|zumvu|zymbio)\b',
        r'\b(?:wikidot|wikispaces|pbworks|sites\.google|webflow)\b',
        r'\b(?:over-blog|overblog|webspawner|simbla|page\.tl)\b',
        r'\b(?:jimdo|hatenablog|joomla|siterubix|kazeo)\b',
        r'\b(?:yola|page\.tl|strikingly|snack\.ws|edublogs)\b',
        r'\b(?:ucoz|simplecast|site\.guru|site\.123|sitey)\b',
        r'\b(?:simdif|seesaa|seesaawiki|sapo\.pt|quora)\b',
        r'\b(?:puzl|pagexl|pagevamp|pagevampapp|moonsy)\b',
        r'\b(?:mystrikingly|mystrikingly|mozello|moonfruit|moonfruit)\b',
        r'\b(?:mikz|mihanblog|mihanblog|mihanblog|mihanblog)\b',
        r'\b(?:ipfs://|ipfs|dweb)\b'  
    ]
    
    # Check if any of the patterns match the URL
    for pattern in free_hosting_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return 1  # Indicates free hosting
    return 0  # Indicates not free hosting


import requests
from bs4 import BeautifulSoup

def get_favicon_and_logo(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract favicon link
        favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        favicon_url = favicon_link.get('href') if favicon_link else None

        # Extract logo (you may need to customize this based on the website structure)
        logo_img = soup.find('img', alt='Logo') or soup.find('img', alt='logo')
        logo_url = logo_img.get('src') if logo_img else None

        return favicon_url, logo_url
    except Exception as e:
        print(f"Error: {e}")
        return None, None


# Load the saved model
model_filename = 'fmodel.pkl'
with open(model_filename, 'rb') as model_file:
    loaded_model = pickle.load(model_file)




# Assuming 'get_url' is implemented somewhere in your code
def get_url(url):
    url = url.replace('www.', '')
    url_len = len(url)
    letters_count = letter_count(url)
    digits_count  = digit_count(url)
    special_chars_count = sum_count_special_characters(url)
    shortened = Shortining_Service(url)
    abnormal = abnormal_url(url)
    secure_https = httpSecured(url)
    have_ip = having_ip_address(url)
    index_google = google_index(url)
    # Parse the URL to extract components
    parsed_url  = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    domain_length = len(domain)
    path_length = len(path)
    free_hosting = is_free_hosting(url)
    
    parsed_url  = urlparse(url)
    
    return {
        'url_len': url_len,
        'letters_count': letters_count,
        'digits_count': digits_count,
        'special_chars_count': special_chars_count,
        'shortened': shortened,
        'abnormal': abnormal,
        'secure_http': secure_https,
        'have_ip': have_ip,
        'GoogleIndex' : index_google,
        'Domain_length': domain_length,
        # 'Path_length': path_length,
        'free_hosting' :free_hosting
    }

# Function to make predictions using the loaded model
def make_prediction(url):
    numerical_values = get_url(url)
    numerical_features = np.array(list(numerical_values.values())).reshape(1, -1)
    prediction_int = loaded_model.predict(numerical_features)[0]

    # Mapping for prediction labels
    class_mapping = {0: 'Suspicious', 1: 'Legitimate'}
    prediction_label = class_mapping.get(prediction_int, 'Unknown')
    

    return prediction_int, prediction_label

# Flask route for the index page
@app.route('/predict', methods=['GET', 'POST'])




def result():
    prediction_result = None
    secure_http = None  # Initialize secure_http variable
    url_len = None
    letters_count = None
    digits_count  = None
    special_chars_count = None
    shortened = None
    abnormal = None
    have_ip = None
    index_google = None
    iframe_src = None
    favicon_url = None
    logo_url = None
    root_domain = None
    reputation = None

    if request.method == 'POST':

        url_to_predict = request.form['url']
        prediction_int,prediction_label = make_prediction(url_to_predict)
        prediction_result = f" {prediction_label}"
        secure_http = httpSecured(url_to_predict)  # Calculate secure_http value
        url_len = len(url_to_predict)
        letters_count = letter_count(url_to_predict)
        digits_count  = digit_count(url_to_predict)
        special_chars_count = sum_count_special_characters(url_to_predict)
        shortened = Shortining_Service(url_to_predict)
        abnormal = abnormal_url(url_to_predict)
        have_ip = having_ip_address(url_to_predict)
        index_google = google_index(url_to_predict)
        url_to_preview = request.form.get('url')
        iframe_src = url_to_preview
        favicon_url, logo_url = get_favicon_and_logo(url_to_preview)
        root_domain = get_root_domain(url_to_predict)
      
        reputation = get_ip_reputation('D3aS8wtUXlNjHRu63mvIraGTeXe7NP5U', root_domain)
    if current_user.role != 'admin':
        # Fetch the current user's information from the database
        user = User.query.get(current_user.id)
       
        return render_template('user_dashboard.html',url_to_predict=url_to_predict,reputation = reputation,user=user,favicon_url=favicon_url, logo_url=logo_url,iframe_src=iframe_src,index_google=index_google,have_ip=have_ip,abnormal=abnormal,shortened=shortened,digits_count = digits_count,special_chars_count=special_chars_count, prediction_result=prediction_result,letters_count = letters_count ,secure_http=secure_http,url_len=url_len)
    else:
         flash('Unauthorized access.', 'error')
         return redirect(url_for('index'))







@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sub_user')
def sub_use():
    return render_template('sub_users.html')

@app.route('/resource')
def resource():
    return render_template('resource.html')

@app.route('/sub_user_dashboard')
def sub_user_dashboard():
    return render_template('add_sub_user.html')

@app.route('/index')
def signin():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    telephone = request.form['telephone']
    business_name = request.form['business_name']
    business_type = request.form['business_type']
    role = request.form['role']

    # Hash the password using Werkzeug's generate_password_hash function
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    with app.app_context():
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email address.', 'error')
            return redirect(url_for('index'))

        user = User(name=name, email=email, password=hashed_password, telephone=telephone, business_name=business_name, business_type=business_type, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')

    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.email  # Store user ID in session
            if user.role == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
            return redirect(url_for('signin'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)  # Remove user ID from session upon logout
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role == 'admin':
        # Fetch all users from the database
        users = User.query.get(session['user_id'])
        return render_template('admin_dashboard.html', users=users)
    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))

# Update the /sub_users route in your Flask app
# Update the sub_users route to properly filter sub-users
@app.route('/sub_users')
@login_required
def sub_users():
    if current_user.role == 'admin':
        # Fetch all sub-users associated with the current admin user's ID
        users = User.query.filter_by(parent_id=current_user.id).all()
        return render_template('sub_users.html', users=users)
    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))


from sqlalchemy.exc import IntegrityError

@app.route('/add_sub_user', methods=['POST'])
@login_required
def add_sub_user_post():
    if current_user.role == 'admin':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email address.', 'error')
            return redirect(url_for('sub_user_dashboard'))

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new sub user and add it to the database
        sub_user = User(name=name, email=email, password=hashed_password, role='sub_user', parent_id=current_user.id)
        db.session.add(sub_user)
        try:
            db.session.commit()
            flash('Sub user added successfully!', 'success')
            return redirect(url_for('sub_users'))
        except IntegrityError:
            db.session.rollback()
            flash('Failed to add sub user. Please try again.', 'error')
            return redirect(url_for('sub_user_dashboard'))
    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))

@app.route('/delete_sub_user/<int:user_id>', methods=['POST'])
@login_required
def delete_sub_user(user_id):
    if current_user.role == 'admin':
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            flash('Sub user deleted successfully!', 'success')
        else:
            flash('Sub user not found.', 'error')
    else:
        flash('Unauthorized access.', 'error')
    return redirect(url_for('sub_users'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():

    if current_user.role != 'admin':
        # Fetch the current user's information from the database
        session['user_email'] = current_user.email
        user = User.query.get(current_user.id)
        return render_template('user_dashboard.html', user=user)
    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))

    





from datetime import datetime  # Import datetime module

# Assuming you have a SQLAlchemy model named PredictionReport
class PredictionReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    secure_http = db.Column(db.String(10))
    have_ip = db.Column(db.String(10))
    abnormal = db.Column(db.String(10))
    shortened = db.Column(db.String(10))
    url_len = db.Column(db.Integer)
    special_chars_count = db.Column(db.Integer)
    letters_count = db.Column(db.Integer)
    digits_count = db.Column(db.Integer)
    domain_age = db.Column(db.String(100))
    google_index = db.Column(db.String(10))
    email = db.Column(db.String(100))
    parent_id = db.Column(db.Integer)
    url = db.Column(db.String(255))  # URL field
    result = db.Column(db.String(50))  # Result field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/save_prediction', methods=['POST'])
@login_required
def save_prediction():
    if request.method == 'POST':
        secure_http = request.form['secure_http']
        have_ip = request.form['have_ip']
        abnormal = request.form['abnormal']
        shortened = request.form['shortened']
        url_len = request.form['url_len']
        special_chars_count = request.form['special_chars_count']
        letters_count = request.form['letters_count']
        digits_count = request.form['digits_count']
        domain_age = request.form['domain_age']
        google_index = request.form['google_index']
        email = request.form['email']
        parent_id = request.form['parent_id']
        url = request.form['url']  # Extract URL from the form submission
        result = request.form['result']  # Extract result from the form submission

        prediction_report = PredictionReport(secure_http=secure_http, have_ip=have_ip, abnormal=abnormal, 
                                shortened=shortened, url_len=url_len, special_chars_count=special_chars_count, 
                                letters_count=letters_count, digits_count=digits_count, domain_age=domain_age, 
                                google_index=google_index, email=email, parent_id=parent_id, url=url, result=result)
        db.session.add(prediction_report)
        db.session.commit()
        flash('Prediction report saved successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    else:
        flash('Failed to save prediction report. Please try again.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/predictions')
@login_required
def predictions():
    # Get the user's email address from the session
    user_email = session.get('user_email')
    
    if user_email:
        # Fetch prediction reports associated with the current user's email address
        predictions = PredictionReport.query.filter_by(email=user_email).all()
        return render_template('predictions.html', predictions=predictions, user_email=user_email)
    else:
        flash('User email not found in session.', 'error')
        return redirect(url_for('index'))

@app.route('/edit_sub_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_sub_user(user_id):
    if current_user.role == 'admin':
        user = User.query.get(user_id)
        if user:
            if request.method == 'POST':
                # Update sub-user information
                user.name = request.form['name']
                user.email = request.form['email']
                db.session.commit()
                flash('Sub user updated successfully!', 'success')
                return redirect(url_for('sub_users'))
            return render_template('edit_sub_user.html', user=user)
        else:
            flash('Sub user not found.', 'error')
            return redirect(url_for('sub_users'))
    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))
    


@app.route('/reports')
@login_required
def report():
    if current_user.role == 'admin':
        # Fetch all prediction reports associated with the admin user's ID (parent ID)
        predictions = PredictionReport.query.filter_by(parent_id=current_user.id).all()
        return render_template('reports.html', predictions=predictions)
    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))




@app.route('/admin')
def admin():
    if current_user.role == 'admin':
        # Fetch all prediction reports associated with the admin user's ID (parent ID)
        predictions = PredictionReport.query.filter_by(parent_id=current_user.id).all()
        
        # Retrieve the total number of reports from the database for the current user's ID
        total_reports = PredictionReport.query.filter_by(parent_id=current_user.id).count()
        
        # Retrieve the count of reports with "Legitimate" result
        total_legitimate = PredictionReport.query.filter_by(parent_id=current_user.id, result=" Legitimate").count()
        
        # Retrieve the count of reports with "Suspicious" result
        total_suspicious = PredictionReport.query.filter_by(parent_id=current_user.id, result=" Suspicious").count()
        
        # Render the admin template and pass the counts
        return render_template('admin.html', predictions=predictions, total_reports=total_reports, total_legitimate=total_legitimate, total_suspicious=total_suspicious)
    else:
        # Redirect the user to the login page or display an error message
        flash('You are not authorized to access this page.', 'error')
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
