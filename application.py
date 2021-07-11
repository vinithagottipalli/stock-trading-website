import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
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
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, name, price, SUM(shares) AS totalShares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    total = cash
    for stock in stocks:
        total += stock["price"] * stock["totalShares"]

    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)
        user_id = session["user_id"]

        if not symbol:
            return apology("you should enter symbol")
        elif not stock:
            return apology("Invalid symbol")

        if not shares:
            return apology("enter number of shares")

        if shares <= 0:
            return apology("enter valid number of shares")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        total_cost = stock["price"] * shares

        if total_cost > cash:
            return apology("Sorry! you have insufficient money")

        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_cost, user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, stock["name"], shares, stock["price"], 'buy', symbol)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol AS Symbol, SUM(shares) AS Shares, price AS Price, time AS Transacted FROM transactions WHERE user_id = ? GROUP BY type AND symbol", 
                        session["user_id"])
                        
    return render_template("history.html", transactions=transactions, usd=usd)
    
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Enter a valid symbol")

        quote = lookup(symbol)
        return render_template("quoted.html", quote=quote, usd=usd)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)

        elif not password:
            return apology("must provide password", 400)

        elif not confirmation:
            return apology("must provide confirmation password", 400)

        elif password != confirmation:
            return apology("Sorry, passwords do not match", 400)

        else:
            rows = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))
            u_id = db.execute("SELECT * FROM users WHERE username = ?", username)
            session["user_id"] = u_id[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)
        user_id = session["user_id"]
        price = stock["price"] * shares
        
        if not symbol:
            return apology("Enter a symbol")
        elif not shares:
            return apology("Enter number of shares")
        if shares <= 0:
            return apology("Enter valid number of shares")
            
        shares_owned = db.execute("SELECT shares FROM transactions WHERE id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]
        
        if shares > shares_owned:
            return apology("Insufficient number of shares")
            
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + price, user_id)    
        
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, stock["name"], -shares, stock["price"], 'sell', symbol)
            
        return redirect("/")
    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
