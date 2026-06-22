from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "secretkey123"
bcrypt = Bcrypt(app)

# Create database table
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
password TEXT
)
''')

conn.commit()
conn.close()

# Home Page
@app.route('/')
def home():
    if 'user' in session:
        return f"Welcome {session['user']}! <br><a href='/logout'>Logout</a>"
    return redirect('/login')


# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users(username,password) VALUES (?,?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration Successful")
            return redirect('/login')

        except:
            flash("Username already exists")

    return render_template('register.html')


# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[0], password):
            session['user'] = username
            return redirect('/')
        else:
            flash("Invalid Username or Password")

    return render_template('login.html')


# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')


if __name__ == "__main__":
    app.run(debug=True)