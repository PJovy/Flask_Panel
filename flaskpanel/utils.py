import os
import string
import random
from flask_mail import Message
from flaskpanel import mail


def generate_vcode():
    chars = string.ascii_letters + string.digits
    vcode = ''.join(random.choice(chars) for i in range(10))
    return vcode


def send_mail(app, user, vcode):
    with app.app_context():
        msg = Message('Password Reset Request',
                      sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[user.email])
        msg.body = f'''Your Vcode is:
        {vcode}
        '''
        mail.send(msg)

