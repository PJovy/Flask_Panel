from flask import render_template, url_for, flash, redirect, request, current_app
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from flaskpanel import app, db, bcrypt, mail
from flaskpanel.forms import RegistrationForm, LoginForm, ResetPasswordForm, \
    VerifyResetPasswordForm, PostNew, PostUpdate
from flaskpanel.models import User, Post


@app.route('/home')
@app.route('/')
def home():
    posts = Post.query.order_by(Post.date_post.desc()).all()
    print(posts)
    return render_template('home.html', posts=posts)


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
    posts = Post.query.all()
    return render_template('userpanel.html', posts=posts, username=username, active='list')


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
        # generate JWT for the user who want to reset password
        if user:
            token = user.generate_token()
            msg = Message(subject='Reset Password', recipients=[email], sender=current_app.config['MAIL_USERNAME'])
            msg.html = f"""
                <h1>You can click the url bellow to confirm your resetpassword request.</h1>
                <a href="{url_for('verify_reset_password', token=token, _external=True )}">点击该链接</a>
            """
            mail.send(msg)
            flash('We have sent a email to your email address', 'success')
            return redirect(url_for('home'))
        flash('Your email has not been logged.', 'warning')
        return redirect(url_for('reset_password'))
    return render_template('reset_password.html', form=form)


@app.route('/verify_reset_password/<token>', methods=['GET', 'POST'])
def verify_reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_password'))
    form = VerifyResetPasswordForm()
    if form.validate_on_submit():
        new_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = new_password
        db.session.commit()
        flash('Your password has been update! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('verify_reset_password.html', form=form)


@app.route('/post_new', methods=['POST', 'GET'])
@login_required
def post_new():
    form = PostNew()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        post = Post(title=title, content=content, owner=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been added!', 'success')
        return redirect('home')
    return render_template('post_new.html', form=form, active='new')


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', post=post)


@app.route('/post/<int:post_id>/post_delete')
@login_required
def post_delete(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('This post has been deleted.', 'info')
    return redirect(url_for('home'))


@app.route('/post/<int:post_id>/post_update', methods=['GET', 'POST'])
@login_required
def post_update(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostUpdate()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated.', 'success')
        return redirect(url_for('post', post_id=post.id))
    form.title.data = post.title
    form.content.data = post.content
    return render_template('post_update.html', form=form)

