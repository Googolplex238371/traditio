from flask import Blueprint,render_template,request,flash,redirect,url_for
from .models import User
from website import db
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,login_required,logout_user,current_user
auth = Blueprint("auth",__name__)
@auth.route('/login',methods=["GET","POST"])
def login():
  x = False
  if request.method == "POST":
    email = request.form.get("email")
    pwd = request.form.get("password")
    user = User.query.filter_by(email=email).first()
    if user: 
      if not check_password_hash(user.password, pwd):
        flash('Incorrect password',category = 'error')
      else: 
        flash('Success',category='success')
        x = True
        login_user(user,remember=True)
    else: 
      flash('Email does not exist',category='error')
    if(x):
      return redirect(url_for('views.home'))
  return render_template("login.html",user=current_user)
@auth.route('/logout')
@login_required
def logout():
  logout_user()
  flash('Logged Out Successfully!',category='success')
  return redirect(url_for("auth.login"))
@auth.route('/register',methods=["GET","POST"])
def signup():
  if request.method == "POST":
    email = request.form.get("email")
    pwd = request.form.get("password1")
    confirm = request.form.get("password2")
    user = User.query.filter_by(email=email).first()
    if user: 
      flash("Email already exists",category="error")
    elif len(pwd)<8 or len(pwd)>64: 
      flash('Password must be between 8 and 64 characters',category='error')
    elif confirm != pwd:
      flash("Passwords do not match",category="error")
    else: 
      flash("Success!",category="success")
      new_user = User(email=email,password=generate_password_hash(pwd,method='sha256'))
      db.session.add(new_user)
      db.session.commit()
      login_user(new_user,remember=True)
      return redirect(url_for('views.home'))
  return render_template("register.html",user=current_user)
