# SmePhishDefender

A web application that helps detect phishing URLs using machine learning. Submit a URL to get a risk assessment (Suspicious or Legitimate) along with supporting analysis such as WHOIS data, HTTPS status, and reputation checks.

## Features

- **URL phishing detection** — Classifies URLs as **Suspicious** or **Legitimate** using a trained Random Forest model
- **Detailed analysis** — URL length, special characters, digit/letter counts, shortening services, HTTPS, IP in domain, Google indexing, domain age (WHOIS), free hosting indicators, and more
- **User accounts** — Sign up, login, and role-based access (admin vs regular user)
- **Admin dashboard** — Manage sub-users, view reports, and see prediction statistics
- **Prediction history** — Save and view past URL checks and results

## Tech Stack

- **Backend:** Flask, Flask-SQLAlchemy, Flask-Login, Flask-Bcrypt  
- **ML:** scikit-learn (Random Forest), NumPy  
- **Data:** SQLite (default), WHOIS, DNS lookups, tldextract  
- **Frontend:** Jinja2 templates, Bootstrap-style UI  

## Prerequisites

- Python 3.8+
- pip

## Installation

1. **Clone the repository** (or navigate to the project folder):

   ```bash
   cd smephishdefender
   ```

2. **Create a virtual environment** (recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure the app** (optional but recommended):

   - Set a strong `secret_key` in `app.py` for production (replace `'your_secret_key'`).
   - If you use external APIs (e.g. AbuseIPDB, IPQualityScore), set your keys via environment variables or config and avoid committing them.

## Running the App

1. From the project root, run:

   ```bash
   python app.py
   ```

2. Open a browser and go to:

   ```
   http://127.0.0.1:5000
   ```

3. Sign up or log in, then use the dashboard to enter a URL and run a phishing check.

## Project Structure

```
smephishdefender/
├── app.py                 # Flask app, routes, ML prediction logic
├── requirements.txt       # Python dependencies
├── machine_train_model.pkl  # Trained phishing-detection model
├── instance/
│   └── app.db            # SQLite database (created on first run)
├── static/               # CSS, JS, images
├── templates/            # HTML templates (login, dashboards, reports, etc.)
└── README.md
```

## Model & Training

The phishing classifier is trained on URL features (length, special characters, shortening services, HTTPS, IP in URL, Google index, domain length, free hosting, etc.). The serialized model is stored in `machine_train_model.pkl`. Training code is available in the included Jupyter notebook (`2020 machie (2).ipynb`) for reference or retraining.

## License

Use and modify as needed for your project. Consider adding a specific license file if you plan to publish.
