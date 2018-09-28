from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from flaskpanel import app, db, bcrypt
from flaskpanel.forms import RegistrationForm, LoginForm, ResetPasswordForm, VerifyResetPasswordForm
from flaskpanel.models import User, ResetPassword
from flaskpanel.utils import *
import time
from threading import Thread

@app.route('/home')
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        if not User.is_exist(username, email):
            user = User(username=username, email=email, password=password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been create ~', 'success')
            return redirect(url_for('login'))
        flash('Username or email has been registered in our website.')
        return redirect(url_for('register'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        next = request.args.get('next')
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if not next:
                flash(f'Login successful. Welcome,{current_user.username}', 'success')
                return redirect(url_for('userpanel', username=current_user.username))
            flash('Login success, then redirect to the site you visited before.')
            return redirect(next)
        flash('Invalid User')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)



@app.route('/userpanel/<username>')
@login_required
def userpanel(username):
    return render_template('userpanel.html', username=username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Your account has been logged out.', 'info')
    return redirect('home')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            vcode = generate_vcode()
            resetpassword = ResetPassword(user_id=user.id, verify_code=vcode)
            thr = Thread(target=send_mail, args=[app, user, vcode])
            thr.start()
            db.session.add(resetpassword)
            db.session.commit()
            # Generate verify code and store into tabel:ResetPassword
            return redirect(url_for('verify_reset_password'))
        flash('Your email address has not been logged!', 'warning')
    # send recaptcha code to this email address,them redirect to verify page.
    return render_template('reset_password.html', form=form)


@app.route('/verify_reset_password', methods=['GET', 'POST'])
def verify_reset_password():
    form = VerifyResetPasswordForm()
    if form.validate_on_submit():
        new_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        vcode = form.verify_code.data
        t = int(time.time())
        resetpassword = ResetPassword.query.filter_by(verify_code=vcode).first()
        if resetpassword:
            if t - resetpassword.generate_time <= 300:
                resetpassword.user.password = new_password
                db.session.commit()
                flash('Your password has been updated.', 'success')
                #删除数据库验证码
                return redirect(url_for('login'))
                db.session.delete(resetpassword)
                db.session.commit()
            flash('Your Vcode is expired.', 'warning')
            return redirect(url_for('reset_password'))
            db.session.delete(resetpassword)
            db.session.commit()
        flash('Your Vcode is invalid.', 'warning')
        return redirect(url_for('reset_password'))
        db.session.delete(resetpassword)
        db.session.commit()
    return render_template('verify_reset_password.html', form=form)
