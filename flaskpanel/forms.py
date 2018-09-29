from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegistrationForm(FlaskForm):
    username = StringField(label='username', validators=[DataRequired(), Length(min=4, max=10)])
    email = StringField(label='email', validators=[DataRequired(), Email()])
    password = PasswordField(label='password', validators=[DataRequired()])
    confirm_password = PasswordField(label='confirm_password',
                                     validators=[EqualTo(fieldname='password')])
    submit = SubmitField(label='submit')


class LoginForm(FlaskForm):
    email = StringField(label='email', validators=[DataRequired(), Email()])
    password = PasswordField(label='password', validators=[DataRequired()])
    submit = SubmitField(label='submit')


class ResetPasswordForm(FlaskForm):
    email = StringField(label='email', validators=[DataRequired(), Email()])
    submit = SubmitField(label='submit')


class VerifyResetPasswordForm(FlaskForm):
    password = PasswordField(label='new_password', validators=[DataRequired()])
    confirm_password = PasswordField(label='confirm_new_password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField(label='submit')
