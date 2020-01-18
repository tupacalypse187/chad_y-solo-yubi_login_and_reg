import os
import re
import base64

from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
from yubico_client import Yubico, otp, yubico_exceptions
from yubico_client.py3 import b

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
yubi_client_id = "51542"
yubi_secret_key = "B2Q6oZvOHQIAMxxEDVXM+XaN5D8="
myDB = "f8x0a94mtjmenwxa"
rand_str = b(os.urandom(30))
nonce = base64.b64encode(rand_str, b('xz'))[:25].decode('utf-8')
yubi_client = Yubico(yubi_client_id, yubi_secret_key)
app = Flask(__name__)
app.secret_key = 'keep it secret, keep it safe'
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/create_user', methods=['POST'])
def create():
    is_valid = True		# assume True
    if len(request.form['fname']) < 1:
        is_valid = False
        flash("Please enter a first name")
    if len(request.form['lname']) < 1:
        is_valid = False
        flash("Please enter a last name")
    if len(request.form['email']) < 1:
        is_valid = False
        flash("Email cannot be blank", 'email')
    elif not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        is_valid = False
        flash("Invalid email address!", 'email')
    if len(request.form['pw']) < 5:
        is_valid = False
        flash("Please enter a password of at least 5 characters")
    if request.form['pw'] != request.form['c_pw']:
        is_valid = False
        flash("Passwords do not match")
    if len(request.form['yubi']) < 1:
        is_valid = False
        flash("Yubikey cannot be blank", 'yubikey')
    elif len(request.form['yubi']) > 0:
        try:
            yubi_client.verify(request.form['yubi'])
        except (yubico_exceptions.StatusCodeError, yubico_exceptions.SignatureVerificationError,
                yubico_exceptions.InvalidClientIdError, yubico_exceptions.InvalidValidationResponse,
                yubico_exceptions.YubicoError) as e:
            is_valid = False
            flash("There is an issue with your Yubikey, please try again", 'yubikey')
        except:
            is_valid = False
            flash("Your Yubikey is invalid, please try again", 'yubikey')
    if is_valid:
        # include some logic to validate user input before adding them to the database!
        # create the hash
        pw_hash = bcrypt.generate_password_hash(request.form['pw'])
        yubi_device_id = otp.OTP(request.form['yubi']).device_id
        # print(pw_hash)  
        # prints something like b'$2b$12$sqjyok5RQccl9S6eFLhEPuaRaJCcH3Esl2RWLm/cimMIEnhnLb7iC'
        # be sure you set up your database so it can store password hashes this long (60 characters)
        mysql = connectToMySQL(myDB)
        query = "INSERT INTO users (first_name, last_name, email, password, yubikey, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, %(yu)s, NOW(), NOW());"
        data = {
            "fn": request.form["fname"],
            "ln": request.form["lname"],
            "em": request.form["email"],
            "pw": pw_hash,
            "yu": yubi_device_id
        }
        session['user_id'] = mysql.query_db(query, data)
        # add user to database
        # display success message
        # flash("User successfully added")
        print(request.form['yubi'])
        return redirect('/success') # either way the application should return to the index and display the message
    else:
        return redirect("/")


@app.route("/login", methods=["POST"])
def on_login():
    is_valid = True

    if len(request.form['email']) < 1:
        is_valid = False
        flash("Email cannot be blank")
    elif not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        is_valid = False
        flash("Invalid email address!", 'email')
    if len(request.form['yubi']) < 1:
        is_valid = False
        flash("Yubikey cannot be blank", 'yubikey')
    elif len(request.form['yubi']) > 0:
        try:
            yubi_client.verify(request.form['yubi'])
        except (yubico_exceptions.StatusCodeError, yubico_exceptions.SignatureVerificationError, yubico_exceptions.InvalidClientIdError, yubico_exceptions.InvalidValidationResponse, yubico_exceptions.YubicoError) as e:
        # except:
            is_valid = False
            flash("There is an issue with your Yubikey, please try again", 'yubikey')
        except:
            is_valid = False
            flash("Your Yubikey is invalid, please try again", 'yubikey')

    if is_valid:
        yubi_device_id = otp.OTP(request.form['yubi']).device_id
        mysql = connectToMySQL(myDB)
        query = "SELECT user_id, email, password, yubikey FROM users WHERE email = %(em)s AND yubikey = %(yu)s"
        data = {
            "em": request.form['email'],
            "yu": yubi_device_id
        }
        user_data = mysql.query_db(query, data)

        if user_data:
            user = user_data[0]

            if bcrypt.check_password_hash(user_data[0]['password'], request.form['pw']) and (user_data[0]['yubikey'] == yubi_device_id):
                session['user_id'] = user['user_id']
            # verify password
            # print(user_data)
                return redirect("/success")
            else:
                flash("Email/Password combo is invalid")
                return redirect("/")
        else:
            flash("Email or yubikey is not valid")
            # print(user_data)
            return redirect("/")
    else:
        return redirect("/")


@app.route('/success')
def landing():
    if 'user_id' not in session:
        return redirect("/")
    mysql = connectToMySQL(myDB)
    query = "SELECT first_name FROM users WHERE user_id = %(u_id)s"
    data = {
            "u_id": session['user_id']
        }
    user_data = mysql.query_db(query, data)
    if user_data:
        user_data = user_data[0]
    else:
        return redirect("/")

    return render_template("landing.html", user=user_data)

@app.route('/yubi_update', methods=['POST'])
def yubi_update():
    if 'user_id' not in session:
        return redirect("/")
    is_valid = True
    if len(request.form['yubi']) < 1:
        is_valid = False
        flash("Yubikey cannot be blank", 'yubikey')
    elif len(request.form['yubi']) > 0:
        try:
            yubi_client.verify(request.form['yubi'])
        except (yubico_exceptions.StatusCodeError, yubico_exceptions.SignatureVerificationError, yubico_exceptions.InvalidClientIdError, yubico_exceptions.InvalidValidationResponse, yubico_exceptions.YubicoError) as e:
        # except:
            is_valid = False
            flash("There is an issue with your Yubikey, please try again", 'yubikey')
        except:
            is_valid = False
            flash("Your Yubikey is invalid, please try again", 'yubikey')

    if is_valid:
        yubi_device_id = otp.OTP(request.form['yubi']).device_id
        mysql = connectToMySQL(myDB)
        query = "UPDATE users SET yubikey = %(yu_id)s, updated_at = NOW() WHERE user_id = %(u_id)s"
        data = {
            "yu_id": yubi_device_id,
            "u_id": session['user_id']
        }
        user_data = mysql.query_db(query, data)
        flash("Yubikey successfully updated")
        return redirect('/success')
    else:
        flash("Yubikey could not be udpated")
        return redirect('/success')

@app.route('/logout')
def on_logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # app.run(ssl_context="adhoc", debug=True)
    app.run(debug=True)