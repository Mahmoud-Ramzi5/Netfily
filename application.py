import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///Records.db")

@app.route("/")
def main():

    return render_template("main.html")
    
@app.route("/Menu")
@login_required
def index():

    return render_template("Menu.html")

@app.route("/pizza", methods=["GET", "POST"])
@login_required
def pizza():
    if request.method == "POST":
        user_id = session["user_id"]
        pizza_name = request.form.get("name")
        quantity = request.form.get("quantity")
        size = request.form.get("size")
        
        if not request.form.get("name"):
            return apology("Must Choose Pizza")

        elif not request.form.get("size"):
            return apology("Must Choose Pizza Size")

        db.execute("INSERT INTO cart(user_id, type, name, quantity, size, price) VALUES(?, ?, ?, ?, ?, ?)",
                       user_id, "Pizza", pizza_name, quantity, size, "Currently Unavailable")
        return redirect("/Menu")
    else:
        return render_template("pizza.html")

@app.route("/potato", methods=["GET", "POST"])
@login_required
def potato():
    if request.method == "POST":
        user_id = session["user_id"]
        potato_type = request.form.get("name")
        quantity = request.form.get("quantity")
        size = request.form.get("size")
        
        if not request.form.get("name"):
            return apology("Must Choose Potato")

        elif not request.form.get("size"):
            return apology("Must Choose Potato Size")
            
        db.execute("INSERT INTO cart(user_id, type, name, quantity, size, price) VALUES(?, ?, ?, ?, ?, ?)",
                       user_id, "Potato", potato_type, quantity, size, "Currently Unavailable")
        return redirect("/Menu")
    else:
        return render_template("potato.html")

@app.route("/meat", methods=["GET", "POST"])
@login_required
def meat():
    if request.method == "POST":
        user_id = session["user_id"]
        meat_name = request.form.get("name")
        quantity = request.form.get("quantity")
        size = request.form.get("size")
        
        if not request.form.get("name"):
            return apology("Must Choose Meat")

        elif not request.form.get("size"):
            return apology("Must Choose Meat Size")
            
        db.execute("INSERT INTO cart(user_id, type, name, quantity, size, price) VALUES(?, ?, ?, ?, ?, ?)",
                       user_id, "Meat", meat_name, quantity, size, "Currently Unavailable")
        return redirect("/Menu")
    else:
        return render_template("meat.html")

@app.route("/chicken", methods=["GET", "POST"])
@login_required
def chicken():
    if request.method == "POST":
        user_id = session["user_id"]
        chicken_name = request.form.get("name")
        quantity = request.form.get("quantity")
        size = request.form.get("size")

        if not request.form.get("name"):
            return apology("Must Choose Chicken")

        elif not request.form.get("size"):
            return apology("Must Choose Chicken Size")
            
        db.execute("INSERT INTO cart(user_id, type, name, quantity, size, price) VALUES(?, ?, ?, ?, ?, ?)",
                       user_id, "Chicken", chicken_name, quantity, size, "Currently Unavailable")
        return redirect("/Menu")
    else:
        return render_template("chicken.html")

@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    """Show cart"""
    cart = db.execute("SELECT * FROM cart WHERE user_id = ?;", session["user_id"])
    if request.method == "POST":
        name = request.form.get("name")
        if not request.form.get("name"):
            return apology("Must Choose")
            
        db.execute("DELETE FROM cart WHERE name = ?", name)
        return redirect("/cart")
    else:
        return render_template("cart.html", cart=cart)

@app.route("/confirm", methods=["GET", "POST"])
@login_required
def confirm():
    if request.method == "POST":
        db.execute("DELETE FROM cart WHERE user_id = ?;", session["user_id"])
        return redirect("/Menu")
    else:
        return render_template("confirm.html", cart=cart)
    
@app.route("/Today's Offer", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        user_id = session["user_id"]
        meat_name = request.form.get("name")
        quantity = request.form.get("quantity")
        size = request.form.get("size")
        
        if not request.form.get("name"):
            return apology("Must Choose Offer")

        elif not request.form.get("size"):
            return apology("Must Choose Offer Size")
        elif not request.form.get("quantity"):
            return apology("Must Choose Offer Quantity")
        
        db.execute("INSERT INTO cart(user_id, type, name, quantity, size, price) VALUES(?, ?, ?, ?, ?, ?)",
                       user_id, "Meat", meat_name, quantity, size, "Currently Unavailable")
        return redirect("/Menu")
    else:
        return render_template("Offer.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        return redirect("/Menu")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/Sign Up", methods=["GET", "POST"])
def SignUp():
    """Sign Up user"""

    if request.method == "POST":

        username = request.form.get("username")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        email = request.form.get("email")
        city = request.form.get("city")
        street = request.form.get("street")
        building = request.form.get("building")
        password = request.form.get("password")
        
        if not username:
            return apology("must provide username")
        elif len(db.execute('SELECT username FROM users WHERE username = ?', request.form.get("username"))) != 0:
            return apology("must provide different username")

        elif not firstname:
            return apology("must provide firstname")
        elif not lastname:
            return apology("must provide lastname")
        elif not email:
            return apology("must provide email")
        elif not city:
            return apology("must provide city")
        elif not street:
            return apology("must provide street")
        elif not building:
            return apology("must provide building")
        elif not password:
            return apology("must provide password")

        elif password != request.form.get("confirmation"):
            return apology("must provide the same password")

        id = db.execute("INSERT INTO users (username, firstname, lastname, email, country, city, street, building, hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            username, firstname, lastname, email, "Syria", city, street, building, generate_password_hash(password))

        return redirect("/login")

    else:
        return render_template("Sign Up.html")
        
@app.route("/me")
@login_required
def ME():
    """Show user"""
    ME = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])

    return render_template("Me.html", ME=ME)
    
@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    if request.method == "POST":
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        email = request.form.get("email")
        city = request.form.get("city")
        street = request.form.get("street")
        building = request.form.get("building")
        password = request.form.get("password")
        
        if not firstname:
            return apology("must provide firstname")
        elif not lastname:
            return apology("must provide lastname")
        elif not email:
            return apology("must provide email")
        elif not city:
            return apology("must provide city")
        elif not street:
            return apology("must provide street")
        elif not building:
            return apology("must provide building")
        elif not password:
            return apology("must provide password")

        elif password != request.form.get("confirmation"):
            return apology("must provide the same password")
        
        db.execute ("UPDATE users SET firstname = (?), lastname = (?), email =(?), city = (?), street = (?), building = (?), hash = (?) where ID = (?) ",
                        (firstname), (lastname), (email), (city), (street), (building), (generate_password_hash(password)), (session["user_id"]))
        return redirect("/me")
    else:
        username = db.execute("SELECT username FROM users WHERE id = ?;", session["user_id"])[0]['username']
        return render_template("edit.html", username=username)

@app.route("/about")
def about():

    return render_template("about.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
