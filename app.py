import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from passlib.hash import bcrypt
from datetime import datetime
import datetime as date


from functions import login_required, check_email, check_language

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


Session(app)

db = SQL("sqlite:///language.db")
# Make hasher slower
hasher = bcrypt.using(rounds=13)

#password = getpass()
#hashed_password = hasher.hash(password)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # get the input
    email = request.form.get("email")
    password = request.form.get("password")

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Query database for email
        rows = db.execute("SELECT * FROM users WHERE email = ?", email)

        # Ensure email exists and password is correct
        if len(rows) != 1 or hasher.verify(password, rows[0]["hash"]) == False:
            check = "Invalid email and/or password!"
            return render_template("login.html", check=check)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # get the input
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        confirmation = request.form.get("confirmation")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username doesn't exists
        if len(rows) == 1:
            check = "Username already exists!"
            return render_template("register.html", check=check)

        # Query database for an email
        rows = db.execute("SELECT * FROM users WHERE username = ?", email)
        if len(rows) == 1:
            check = "Email is registered!"
            return render_template("register.html", check=check)

        # Ensure password is long enough and has special charecters
        if len(password) < 8 or password.isalnum() == True:
            check = "Password is too short or doesn't contain special characters!"
            return render_template("register.html", check=check)

        # Ensure password and confirmation password are the same
        if password != confirmation:
            check = "Passwords do not match!"
            return render_template("register.html", check=check)

        # Ensure email is valid
        if check_email(email) == False:
            check = "E-mail is not valid!"
            return render_template("register.html", check=check)

        db.execute("INSERT INTO users (username, hash, email) VALUES(?, ?, ?)",
                   username, hasher.hash(password), email)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/security", methods=["GET", "POST"])
@login_required
def security():
    if request.method == "POST":
        # Get users' input
        c_password = request.form.get("current_password")
        n_password = request.form.get("new_password")
        cnfm_password = request.form.get("confirmation")

        # Ensure submitted password is users' current password submitted
        id = session["user_id"]
        user_password = db.execute("SELECT hash FROM users WHERE id= ? ", id)

        if hasher.verify(c_password, user_password[0]["hash"]) == False:
            check = "Your current password does not match!"
            return render_template("security.html", check=check)

        if n_password == c_password:
           check = "Choose different password!"
           return render_template("security.html", check=check)
         # Ensure password is long enough and has special charecters
        if len(n_password) < 6 or n_password.isalnum() == True:
           check = "Password is too short or doesn't have special characters!"
           return render_template("security.html", check=check)

        # Ensure password and repeat password are the same
        if n_password != cnfm_password:
           check = "Passwords do not match!"
           return render_template("security.html", check=check)

        db.execute("UPDATE users SET hash = ? WHERE id = ?",  hasher.hash(n_password), id)
        flash("Password changed!")
        return redirect("/")

    return render_template("security.html")

@app.route("/profile-edited", methods=["GET", "POST"])
@login_required
def profile_edited():
    if request.method == "POST":
        return redirect("/profile")
    else:
        user_id = session["user_id"]
        profile = db.execute("SELECT * FROM profiles WHERE user_id = ?", user_id)
        if len(profile) == 1:
            return render_template("/profile-edited.html", profiles=profile)
        return redirect("/profile")

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        # get the user's input
        name = request.form.get("name").capitalize()
        lastname = request.form.get("lname").capitalize()
        language = request.form.get("language").capitalize()
        level = request.form.get("level")
        email = request.form.get("email")

        #get user's id
        user_id = session["user_id"]
        profile = db.execute("SELECT * FROM profiles WHERE user_id = ?", user_id)

        if check_language(language.lower()) == False:
            check = "Enter a valid language!"
            return render_template("profile.html", check=check, profiles=profile)

        # update profile information
        if len(profile) == 1:
            if not level:
                level = profile[0]["level"]
            db.execute("UPDATE profiles SET name = ?, lastname = ?, language = ?, level = ?, email = ? WHERE user_id = ?", name, lastname, language, level, email, user_id)
            db.execute("UPDATE users SET email = ? WHERE id = ?", email, user_id)
            return redirect("/profile-edited")
        else:
            db.execute("INSERT INTO profiles (name, lastname, language, level, email, user_id) VALUES (?, ?, ?, ?, ?, ?)", name, lastname, language, level, email, user_id)
            return redirect("/profile-edited")
    else:
        user_id = session["user_id"]
        profile = db.execute("SELECT * FROM profiles WHERE user_id = ?", user_id)
        return render_template("/profile.html", profiles=profile)

@app.route("/")
@login_required
def index():
    # get a main language
    user_id = session["user_id"]
    language = db.execute("SELECT language FROM profiles WHERE user_id= ?", user_id)
    if len(language) != 0:
        language = language[0]["language"]

        # check when was the last day the user have studied their main language
        lstday = db.execute("SELECT date FROM study_history WHERE language = ? ORDER BY id DESC LIMIT 1", language)
        if len(lstday) < 1:
            message = "It's been a while since you have studied your main language. Would you like to learn somethig new today?"
            return render_template("index.html", message=message)
        lstday = lstday[0]["date"]
        # convert the string into a date
        lstday = datetime.strptime(lstday, "%Y-%m-%d")

        # check today's date
        day = date.datetime.now()
        # calculate how many days it has been since the user have studies the main language
        delta = day - lstday

        # return message
        if delta.days > 4:
            message = "It's been a while since you have studied your main language. Would you like to learn somethig new today?"
            return render_template("index.html", message=message)

        message = "You are moving towards your goal! What would you like to study today?"
        return render_template("index.html", message=message)
    return render_template("index.html")

@app.route("/study", methods=["GET", "POST"])
@login_required
def study():
    if request.method == "POST":
       #get user's input
       user_id = session["user_id"]
       language = request.form.get("language").capitalize()
       min = request.form.get("time")
       focus = request.form.get("focus")

       day = date.datetime.now()
       day = day.date()

       db.execute("INSERT INTO study_history (language, time, user_id, focus, date) VALUES (?, ?, ?, ?,?)",language, min, user_id, focus, day)
    return render_template("/study.html")

@app.route("/statistics", methods=["GET", "POST"])
@login_required
def statistics():
    user_id = session["user_id"]
    choose_language = db.execute("SELECT language FROM study_history WHERE user_id = ? GROUP BY language", user_id)
    if request.method == "POST":
        language = request.form.get("language")
        data = db.execute("SELECT SUM(time) as time, focus, date, language FROM study_history WHERE language = ? AND user_id= ? GROUP BY focus", language, user_id)
        label = language
        data_lnchrt =db.execute("SELECT SUM(time) as time, date, language FROM study_history WHERE language = ? AND user_id = ? GROUP BY date", language, user_id)
        if len(data) < 1 or len(data_lnchrt) < 1:
            return render_template("/statistics-sorry.html")
        return render_template("/statistics.html", info=data, label=label, data_lnchrt=data_lnchrt, choose_language=choose_language)
    else:
        data = db.execute("SELECT SUM(time) as time, focus, date, language FROM study_history WHERE user_id= ? GROUP BY focus", user_id)
        label = "The amount of time spent on languages"
        data_lnchrt =db.execute("SELECT SUM(time) as time, date, language FROM study_history WHERE user_id = ? GROUP BY date", user_id)
        if len(data) == 1 or len(data_lnchrt) < 1:
             return render_template("/statistics-sorry.html")
        return render_template("/statistics.html", info=data, label=label, data_lnchrt=data_lnchrt, choose_language=choose_language)