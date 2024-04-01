from flask import Flask, request, render_template, jsonify, make_response,session, redirect, url_for, flash
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import pickle
from datetime import datetime, timedelta
import mysql.connector,json
import threading
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from functools import wraps

app = Flask(__name__)
oauth = OAuth(app)
# Disable caching for static files
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
# Google Calendar API scopes
scopes = ['https://www.googleapis.com/auth/calendar']

app.secret_key = 'Amazon'  # set a secret key for session management
cnx = mysql.connector.connect(
    user='root',
    password='root1234',
    host='stackdb-02-masterdb-ap69ncgbzsu3.cjeo2c4qygzv.us-east-1.rds.amazonaws.com',
    database='db1'
)

# Create a cursor object to execute SQL queries
cursor = cnx.cursor()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=50)

cnt = 0  # Declare cnt outside of the route function

# Define a decorator function to check authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'error')
            # Use a JavaScript alert and then redirect
            return f'''
            <script>
                alert('Login is required !!');
                window.location.href = '/login';
            </script>
            '''
        return f(*args, **kwargs)
    return decorated_function
# Define routes for signup and login

@app.route('/signup', methods=['GET', 'POST'])
def signup_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        number = request.form['number']
        hashed_password = generate_password_hash(password)

        # Check if the username already exists in the database
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user:
            return f'''
            <script>
                alert('Username already exists !!');
                window.location.href = '/signup';
            </script>
            '''

        # Insert the new user into the Users table
        insert_query = "INSERT INTO Users (username, password, email, number) VALUES (%s, %s, %s, %s)"
        insert_data = (username, hashed_password, email, number)
        cursor.execute(insert_query, insert_data)
        cnx.commit()
        subject="Welcome Mail"
        # Add the username to the session
        session['username'] = username
        session['email'] = email
        message="Thank You "+username+" for registering with EasySchedular "
        send_email(email,subject,message)
        return redirect(url_for('Home'))  # Redirect to the user dashboard page after signup

    return render_template('newsignup.html')

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the database to find the user by username
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[1], password):  # Check password hash
            # Add username and email to the session
            session['username'] = username
            session['email'] = user[2]  # Assuming email is stored in the third column
            return redirect(url_for('Home'))

        else:
            return '''
            <script>
                alert('Invalid username or password');
                window.location.href = '/login';
            </script>
            '''

    return render_template('login.html')



@app.route('/delete/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    try:
        # Execute SQL query to delete the task with the given ID
        cursor.execute("DELETE FROM SCHEDULER WHERE task_id = %s", (task_id,))
        cnx.commit()
        return jsonify({'message': 'Task deleted successfully'}), 200
    except Exception as e:
        print(f'Error deleting task: {str(e)}')
        return jsonify({'error': 'Failed to delete task'}), 500


@app.route('/logout',methods=['GET', 'POST'])
def logout_user():
    session.pop('username', None)  # Remove username from the session
    session.pop('credentials', None)
    return redirect(url_for('login_user'))  # Redirect to login page after logout
 

@app.route('/charts', methods=['GET'])
@login_required
def Analysis():
    # Query the database to get the number of completed and pending tasks for the logged-in user
    cursor.execute("SELECT COUNT(*) FROM SCHEDULER WHERE username = %s AND status = 'completed'", (session['username'],))
    completed_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM SCHEDULER WHERE username = %s AND status = 'pending'", (session['username'],))
    pending_count = cursor.fetchone()[0]

    print(completed_count)
    print(pending_count)
    # Prepare the data for the pie chart
    chart_data = {
        'labels': ['Completed', 'Pending'],
        'datasets': [{
            'label': 'Tasks',
            'backgroundColor': ['#36A2EB', '#FFCE56'],
            'data': [completed_count, pending_count]
        }]
    }

    # Convert the chart data to JSON format
    chart_data_json = json.dumps(chart_data)
    username= session.get('username')
    # Render the template with the chart data
    return render_template("charts.html", chart_data=chart_data_json,username=username)


@app.route('/', methods=['GET'])
@login_required
def Home():
    # Get the username from the session
    username = session.get('username')

    # Execute SQL queries to get task counts
    cursor.execute("SELECT COUNT(*) FROM SCHEDULER WHERE username = %s", (username,))
    total_tasks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM SCHEDULER WHERE username = %s AND status = 'completed'", (username,))
    completed_tasks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM SCHEDULER WHERE username = %s AND status = 'pending'", (username,))
    pending_tasks = cursor.fetchone()[0]

    all_tasks = get_all_tasks()
    if all_tasks:
        print(all_tasks)
        print(cnt)
        return render_template('index.html', taskss=all_tasks, username=username, total_tasks=total_tasks, completed_tasks=completed_tasks, pending_tasks=pending_tasks)
    else:
        return '''
            <script>
                alert('There are no scheduled Tasks!!');
                window.location.href = '/schedule';
            </script>
            '''
            
@login_required
def get_all_tasks():
    try:
        # Get the username from the session
        username = session.get('username')
        
        # Create a cursor object to execute SQL queries
        cursor = cnx.cursor(dictionary=True)
        
        # Execute the SQL query to select attributes from the Scheduler table for the specific user
        cursor.execute("SELECT * FROM SCHEDULER WHERE username = %s", (username,))
        
        # Fetch all rows from the result set
        tasks = cursor.fetchall()
        
        # Close the cursor
        cursor.close()
        
        return tasks
    except mysql.connector.Error as err:
        print("Error:", err)
        return '''
            <script>
                alert('There are no scheduled Tasks!!');
                window.location.href = '/schedule';
            </script>
            '''


@app.route('/schedule', methods=['GET'])
@login_required
def ScheduleTask():
    username = session.get('username')
    return render_template('forms.html',username=username)


# Load or create credentials using OAuth 2.0 flow
from google.oauth2.credentials import Credentials
def get_credentials():
    try:
        # Try loading existing credentials from session
        credentials_data = session.get('credentials')

        if not credentials_data:
            # If credentials not found in session, initiate OAuth 2.0 flow
            flow = InstalledAppFlow.from_client_secrets_file("client_secret.json", scopes=scopes)
            credentials = flow.run_local_server(port=0)
            # Serialize the credentials object to a dictionary
            credentials_data = {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': credentials.scopes,
            }
            # Save the obtained credentials in the session
            session['credentials'] = credentials_data

        else:
            # Deserialize the credentials data back to a Credentials object
            credentials = Credentials(
                token=credentials_data['token'],
                refresh_token=credentials_data['refresh_token'],
                token_uri=credentials_data['token_uri'],
                client_id=credentials_data['client_id'],
                client_secret=credentials_data['client_secret'],
                scopes=credentials_data['scopes'],
            )

        return credentials

    except Exception as e:
        print("Error:", e)


def build_calendar_service():
    credentials = get_credentials()
    service = build('calendar', 'v3', credentials=credentials)
    return service


@app.route('/insert-event', methods=['POST'])
@login_required
def insert_event():
    try:
        data = request.json
        print("Received data:", data)  # For debugging purposes

        # Call the function to insert event data into the database
        success = insert_into_database(data)

        # Send email notification
        if success:
            username = session.get('username')
            subject = "Reminder!"
            date = data.get('date')
            start_time = data.get('start_time')
            email = session.get('email')
            message = f"Be Ready! {username}, your task is scheduled on {date} at {start_time}"
            send_email(email, subject, message)

            return {'success': True}, 200
        else:
            return {'success': False, 'message': 'Failed to insert event into database'}, 400
    except Exception as e:
        return {'success': False, 'message': f'Error inserting event and data: {str(e)}'}, 500

def insert_into_database(data):
    try:
        # Extract data
        task_name = data.get('task_name')
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        description = data.get('description')
        status = 'pending'  # Assuming the status is initially pending

        # Get the username from the session
        username = session.get('username')

        # Insert data into the SCHEDULER table
        insert_query = "INSERT INTO SCHEDULER (task_name, date, start_time, end_time, description, status, username) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        insert_data = (task_name, date, start_time, end_time, description, status, username)

        cursor.execute(insert_query, insert_data)
        cnx.commit()
        return True
    except Exception as e:
        print(f'Error inserting into database: {str(e)}')
        return False



@app.route('/update', methods=['POST'])
@login_required
def update_task_status():
    try:
        data = request.json
        task_id = data.get('task_id')
        new_status = data.get('status')

        # Perform the update operation in the database
        success = update_status_in_database(task_id, new_status)

        if success:
            return jsonify({'success': True, 'message': 'Task status updated successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to update task status'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

def update_status_in_database(task_id, new_status):
    try:
        # Perform the update operation using cursor
        cursor = cnx.cursor()
        update_query = "UPDATE SCHEDULER SET status = %s WHERE task_id = %s"
        cursor.execute(update_query, (new_status, task_id))
        cnx.commit()
        cursor.close()
        return True
    except mysql.connector.Error as err:
        print("Error:", err)
        return False

@app.route('/google/')
def google():

    GOOGLE_CLIENT_ID = '202782780730-au1pe7280jn50nbhpsg0lmedlmk9djpu.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'

    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

     # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    print(redirect_uri)
    session['nonce'] = generate_token()
    return oauth.google.authorize_redirect(redirect_uri, nonce=session['nonce'])

import random
@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    user = oauth.google.parse_id_token(token, nonce=session['nonce'])
    
    # Convert user dictionary to a proper format
    user_data = {
        'name': user.get('name'),
        'email': user.get('email'),
        # Add other relevant fields as needed
    }

    session['user'] = user_data
    session['username'] = user_data['name']  # Assuming 'name' is the username
    session['email'] = user_data['email']  # Store email in session
    print(" Google User ", user_data)
    
    # Check if the username already exists in the database
    cursor.execute("SELECT * FROM USERS WHERE username = %s", (user_data['name'],))
    existing_user = cursor.fetchone()

    if not existing_user:  # If username does not exist, insert the user into the database
        # Generate a random password (you may need to adjust this logic)
        random_password = generate_password_hash(str(random.randint(100000, 999999)))
        
        # Set default value for the number field
        default_number = '9421636870'
        
        # Insert the user's information into the USERS table
        cursor.execute("INSERT INTO USERS (username, email, password, number) VALUES (%s, %s, %s, %s)",
                       (user_data['name'], user_data['email'], random_password, default_number))
        cnx.commit()  # Commit the transaction

    return '''
    <script>
        alert('Sign in Successful from Google!!');
        window.location.href = '/';
    </script>
    '''
   
#SMTP Part
import smtplib
import threading
from datetime import timedelta
# Gmail SMTP settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "adityadhanwai8@gmail.com"
SMTP_PASSWORD = "dqua dmxa mhpd lcdp"
# Email account credentials
email_address = "adityadhanwai8@gmail.com"
password = "dqua dmxa mhpd lcdp"
def send_email(recipient, subject, message):
    try:
        print(recipient)
        # Connect to the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)

        # Compose the email
        email_message = f"Subject: {subject}\n\n{message}"
        server.sendmail(SMTP_USERNAME, recipient, email_message)

        server.quit()

        # Return a success message when the email is successfully sent
        return "Email sent successfully."
    except smtplib.SMTPException as e:
        error_message = f'Email could not be sent. SMTP Error: {str(e)}'
        print(error_message)
        return error_message
    except Exception as e:
        error_message = f'Email could not be sent. Error: {str(e)}'
        print(error_message)
        return error_message

if __name__ == '__main__':
    app.run(debug=True)
