import os
import re

from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT symbol, SUM(shares) FROM depot WHERE user_id=? GROUP BY symbol;", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id=?;", session["user_id"])
    grand_total = cash[0]['cash']

    for i in range (0, len(stocks)):
        total_usd = {"total": None}
        quote = lookup(stocks[i]['symbol'])
        total = quote['price'] * stocks[i]['SUM(shares)']
        total_usd['total'] = usd(total)
        stocks[i].update(quote)
        stocks[i].update(total_usd)
        grand_total += total

    grand_total_usd = usd(grand_total)
    cash_usd = usd(cash[0]['cash'])
    return render_template("index.html", stocks=stocks, grand_total_usd=grand_total_usd, cash_usd=cash_usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide a valid symbol", 403)

        # Ensure amount was submitted
        elif not request.form.get("shares"):
            return apology("must provide the number of shares you want to buy", 403)

        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("This symbol does not exist." , 403)

        total_price = int(request.form.get("shares")) * int(quote["price"])

        cash = db.execute("SELECT cash FROM users WHERE id=?;", session["user_id"])

        # Checks if the user can afford that many shares.
        if total_price > cash[0]['cash']:
            flash("Total price: " + usd(total_price) + " $.")
            return apology("You can't afford that.", 403)
        else:
            db.execute("INSERT INTO depot VALUES (?, UPPER(?), ?)", session["user_id"], request.form.get("symbol"), request.form.get("shares"))
            db.execute("INSERT INTO history VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], "Buy", request.form.get("symbol"), request.form.get("shares"), datetime.now(), usd(total_price))
            db.execute("UPDATE users SET cash = cash - ? WHERE id=?;", total_price, session["user_id"]) # Reduce cash
            flash("Shares bought. Total price: " + usd(total_price) + " $.")

            return render_template("buy.html")

    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT sale, symbol, shares, date, price FROM history WHERE user_id=?;", session['user_id'])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("This symbol does not exist." , 403)

        flash("One share of " + quote["name"] + "costs " + str(quote["price"]) + " $.")
        return render_template("quote.html")

    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

         # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Password and confirmation do not match", 403)

        if len(request.form.get("password")) < 8:
            return apology("Your Password is too short. Use at least 8 letters.", 403)
        elif re.search('[0-9]', request.form.get("password")) is None:
            return apology("Your password must contain at least one digit.", 403)
        elif re.search('[A-Z]', request.form.get("password")) is None:
            return apology("Your password must contain at least one capital letter.", 403)

        # Query database for username
        rows = db.execute("SELECT username FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) == 1:
            return apology("username already taken", 403)

        hashpw = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?);", request.form.get("username"), hashpw)

        if rows == None:
            return apology("Error", 403)

        flash(u"Registration successful! Please login.")

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("invalid symbol", 403)
        # Ensure amount was submitted

        if not request.form.get("shares"):
            return apology("must provide the number of shares you want to sell", 403)

        amount = db.execute("SELECT SUM(shares) FROM depot WHERE user_id=? AND symbol=?;", session["user_id"], request.form.get("symbol"))

        if int(request.form.get("shares")) > amount[0]['SUM(shares)']:
            return apology("You can't sell more than you have", 403)

        new_amount = amount[0]['SUM(shares)'] - int(request.form.get("shares"))
        quote = lookup(request.form.get("symbol"))

        total_price = int(request.form.get("shares")) * int(quote["price"])

        cash = db.execute("SELECT cash FROM users WHERE id=?;", session["user_id"])

        db.execute("UPDATE depot SET shares = ? WHERE user_id=? AND symbol=?;", new_amount, session["user_id"], request.form.get("symbol"))
        db.execute("INSERT INTO history VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], "Sale", request.form.get("symbol"), request.form.get("shares"), datetime.now(), usd(total_price))
        db.execute("UPDATE users SET cash = cash + ? WHERE id=?;", total_price, session["user_id"]) # Increase cash
        db.execute("DELETE FROM depot WHERE shares<1;")

        flash("Shares sold. Total price: " + usd(total_price) + " $.")

        return render_template("sell.html")

    else:
        symbols = db.execute("SELECT symbol FROM depot WHERE user_id=? GROUP BY symbol;", session["user_id"])
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
