from flask import Flask, render_template, redirect, url_for, request, flash, session
import os.path
# from OpenSSL import SSL

# Use bcrypt for password handling
import bcrypt

PASSWORDFILE = 'passwords'
PASSWORDFILEDELIMITER = ":"


app = Flask(__name__)
# The secret key here is required to maintain sessions in flask
app.secret_key = b'8852475abf1dcc3c2769f54d0ad64a8b7d9c3a8aa8f35ac4eb7454473a5e454c'

# Initialize Database file if not exists.
if not os.path.exists(PASSWORDFILE):
    open(PASSWORDFILE, 'w').close()


@app.route('/')
def home():

    # TODO: Check if user is logged in
    # if user is logged in
    #    return render_template('loggedin.html')

    return render_template('home.html')


# Display register form
@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register.html')

# Handle registration data


@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    matchpassword = request.form['matchpassword']

    if password != matchpassword:
        return render_template('register.html', error="Passwords do not match")

    # check if username is already taken in usernames file
    with open(PASSWORDFILE, 'r') as f:
        for line in f:
            if username == line.split(PASSWORDFILEDELIMITER)[0]:
                return render_template('register.html', error="Username already taken")

    # write username to passwords file
    with open(PASSWORDFILE, 'a') as f:
        f.write(username + PASSWORDFILEDELIMITER)

    # hash password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # write hashed password to passwords file
    with open(PASSWORDFILE, 'a') as f:
        f.write(hashed.decode('utf-8') + "\n")

    return redirect(url_for('home'))


# Display login form


@ app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')


# Handle login credentials
@ app.route('/login', methods=['POST'])
def login_post():

    username = request.form['username']
    password = request.form['password']

    # check if username is in passwords file
    with open(PASSWORDFILE, 'r') as f:
        for line in f:
            if username == line.split(PASSWORDFILEDELIMITER)[0]:
                # check if password is correct
                if bcrypt.checkpw(password.encode('utf-8'), line.split(PASSWORDFILEDELIMITER)[1].rstrip('\n').encode('utf-8')):
                    return render_template('loggedin.html')
                else:
                    return render_template('login.html', error="Incorrect password. Password was: " + line.split(PASSWORDFILEDELIMITER)[1])

    return render_template('login.html', error="Username not found")


if __name__ == '__main__':

    # TODO: Add TSL
    app.run(debug=True, ssl_context='adhoc')
