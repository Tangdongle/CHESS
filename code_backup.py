import web
from datetime import date, datetime, timedelta
import re
import bcrypt
from hashlib import sha256
import model
from uuid import uuid4
from os import path as ospath
import base64

MIN_PASS_LEN = 4
BCRYPT_WLOAD = 10


#Map urls to classes
urls = (
        '/','Index',
        '/admin','Admin',
        '/home','Index',
        '/login','Login',
        '/register','Register',
        '/recover','Recover',
        '/forgotpassword/(\d+)@(\d+)@(\S+)','PasswordChange',
        '/logout','Logout',
        '/category/(\S+)/[A-Z]','Category',
        )

app = web.application(urls, globals())

############################################################
#Functions
############################################################

#sessions setup
if web.config.get('_session') is None:
    session = web.session.Session(app, web.session.DiskStore('sessions'), initializer={'logged_in':False,'username':'Guest','cin':000000,})
    web.config._session = session
else:
    session = web.config._session

#web.config.session_parameters['ignore_change_ip'] = False
web.config.session_parameters['cookie_name'] = 'chess_session_id'
#web.config.session_parameters['timeout'] = 86400
#web.config.session_parameters['ignore_expiry'] = False
#set smtp server
web.config.smtp_server = 'mail.westnet.com.au'

#True if loggin_in is a key in sessions dict
def logged_in():
    if session.get('logged_in'):
        return True
    else:
        return False

def check_pwd_len(pwd):
    return bool(len(pwd) >= MIN_PASS_LEN)

#setup validators with functions
vpass = web.form.Validator('Password too short', check_pwd_len)

def notfound():
    return web.notfound("Sorry, the page you were looking for cannot be found!")

def csrf_token():
    if not session.has_key('csrf_token'):
        session.csrf_token=uuid4().hex
    return session.csrf_token

def csrf_protected(f):
    def decorated(*args,**kwargs):
        i = web.input()
        if not (i.has_key('csrf_token') and i.csrf_token==session.pop('csrf_token',None)):
            raise web.HTTPError(
                    "400 Bad request",
                    {'content-type': 'text/html'},
                    """Cross-site request forgery (CSRF) attempt (or stale browser form).
    <a href="">Back to the form</a>.""")
        return f(*args,**kwargs)
    return decorated


############################################################
# render setup (add globals here)
############################################################

#Setup template rendering usinglayout
render = web.template.render('templates/', base='layout', cache=False, globals={'csrf_token':csrf_token,'context':session})
#setup template rendering without layout (for popups and the like)
render_plain = web.template.render('templates/')

############################################################
# Classes for pages
############################################################

class Index:
    r"""
    Home splash page
    """
    def GET(self):
        if logged_in():
            res_cats = model.get_resource_categories()
            return render.index(res_cats)
        else:
            raise web.seeother('/login')

    def POST(self):
        return render.index()


class Admin:
    r"""
    Admin panel
    """

    form = web.form.Form(
            web.form.Textbox('cin', web.form.notnull,
                size=25,
                description="Enter CIN: "),
            web.form.Textbox('username', web.form.notnull,
                size=25,
                description="Username: "),
            web.form.Password('password', web.form.notnull,
                size=25,
                description="Password: "),
            web.form.Textbox('email',
                size=25,
                description="Email: "),
            web.form.Textbox('privilege',
                size=25,
                description="Privilege Level: "),
            web.form.Button('add_user', type="submit",
                description="Add User"),
            )


    def GET(self):
        users = model.get_all_users()
        user_form = self.form()
        return render.admin(users, user_form)

    def POST(self):
        i = web.input()
        user_form = self.form()
        if not user_form.validates():
            return render.admin(model.get_all_users(),user_form)
        if 'uid' in i:
            model.del_user(i.cin, i.uid)
        elif 'username' in i:
            uname, pwd, email = i.username.strip().lower(), i.password.strip(), i.email.strip()
            pwd = bcrypt.hashpw(pwd, bcrypt.gensalt(BCRYPT_WLOAD))
            model.add_user(i.cin, uname,pwd, email)
        return render.admin(model.get_all_users(), user_form)

class RegForm(web.form.Form):
    r"""
    Subclasses web.form.Form to use divs instead of tables

    """

    def __init__(self, *inputs, **kw):
        super(RegForm, self).__init__(*inputs, **kw)
    def render(self):
        out = ''
        out += self.rendernote(self.note)
        out += '<div class="_form">\n'

        for n,i in enumerate(self.inputs):
            html = web.utils.safeunicode(i.pre) + i.render() + web.utils.safeunicode(i.post)
            if i.is_hidden():
                out += '    <div style="display:none">%s</div>\n' % (html)
            else:
                out += '    <div style="height:auto;">%s</div><div><label for="%s">%s</label>%s</div>\n' % (i.rendernote(i.note), i.id, web.net.websafe(i.description), html)
        out += "</div>"
        return out

class Login:
    r"""
    Deals with user login
    """

    form = RegForm(
        web.form.Textbox('cin', web.form.notnull,
            size=25,
            description="Enter CIN: "),
        web.form.Textbox('username', web.form.notnull,
            size=25,
            description="Username:"),
        web.form.Password('password', web.form.notnull, vpass,
            size=25,
            description="Password:"),
        web.form.Button('Login'),
    )

    def GET(self):
        if logged_in():
            web.seeother('/')
        else:
            form = self.form()
            return render.login(form,users=model.get_all_users())

    @csrf_protected
    def POST(self):
        """
        Compares given CIN, username and password to db entry
        TODO: Rewrite me: I need to get rid of authenticate_user as
            it seems to be just doubling my code
        """
        i = web.input()
        form = self.form()
        if not form.validates():
            return render.login(form, users=model.get_all_users())
        else:
            try:
                u = model.get_user_by_name(i.cin, i.username.strip().lower())[0]
            except IndexError:
                return render.login(form,"User does not exist! Need an account? <a href='/register'>Register Here</a>", users=model.get_all_users())
            check = True if bcrypt.hashpw(i.password, u.password) == u.password else False
            print bcrypt.hashpw(i.password, u.password)
        if check:
            session.logged_in = True
            session.username = i.username
            session.cin = i.cin
            raise web.seeother('/admin')
        else:
            return render.login(form,"login failed!", users=model.get_all_users())

class Logout:
    r"""
    User logout page
    """

    def GET(self):
        if session.logged_in == True:
            session.logged_in = False
            session.username = 'Guest'
        raise web.seeother('/')

class Register:
    r"""
    Register Page
    Deals with creating new users. Ensures duplicate users aren't created
    """
    form = RegForm(
            web.form.Textbox('cin', web.form.notnull,
                size=25,
                description="Enter CIN: "),
            web.form.Textbox('username', web.form.notnull,
                size=25,
                description="Enter your Username"),
            web.form.Textbox('email', web.form.notnull,
                size=25,
                description="Enter a Email"),
            web.form.Password('password', web.form.notnull, vpass,
                size=25,
                description="Enter Password"),
            web.form.Password('password2', web.form.notnull,
                size=25,
                description="Repeat Password"),
            web.form.Button('submit', type='submit', description="Register"),
            validators=[
                web.form.Validator("Passwords didn't match", lambda i: i.password == i.password2)],
    )

    def GET(self):
        form = self.form()
        return render.register(form,model.get_all_users())

    @csrf_protected
    def POST(self):
        i = web.input()
        form = self.form()
        if not form.validates() or i.username in [u.username for u in model.get_all_users()]:
            return render.register(form,model.get_all_users())
        else:
            cin, uname, pwd, email = i.cin, i.username.strip().lower(), i.password.strip(), i.email.strip()
            #register parsing here
            pwd = bcrypt.hashpw(pwd, bcrypt.gensalt(BCRYPT_WLOAD))
            model.add_user(cin, uname,pwd, email)
            session.logged_in = True
            session.username = uname
            session.cin = cin
            raise web.seeother('/')

#Depracated
#class Report:
#    r"""
#    Adding and viewing reports
#
#    """
#
#    form = RegForm(
#            web.form.Textbox('incident', web.form.notnull,
#                size=30,
#                description="Incident"),
#            web.form.Textbox('country', web.form.notnull,
#                size=30,
#                description="Country"),
#            web.form.Textbox('state', web.form.notnull,
#                size=30,
#                description="State"),
#            web.form.Textbox('site', web.form.notnull,
#                size=30,
#                description="Site"),
#            web.form.Button('submit', type='submit', description="Submit"),
#    )
#
#    del_report = web.form.Form(
#        web.form.Button('delete', type='submit', description="Delete"),
#    )
#
#    def GET(self):
#        form = self.form
#        del_report = self.del_report
#        return render.report(model.get_reports(), form, uname=session.get('username'), delete=del_report, timeconv=datetime.utcfromtimestamp)
#
#    def POST(self):
#        i = web.input()
#        uname = session['username']
#        if not logged_in():
#            raise web.seeother('/login')
#        form = self.form
#        del_report = self.del_report
#        if form.validates():
#            text = i.incident.strip()
#            model.add_report(username=uname, text=text, country=i.country, state=i.state, site=i.site)
#            return render.report(model.get_reports(), form, msg="Incident report submitted", uname=uname.capitalize(), delete=del_report, timeconv=datetime.utcfromtimestamp)
#        else:
#            return render.report(model.get_reports(), form, msg='Must fill in all fields', uname=uname, delete=del_report, timeconv=datetime.utcfromtimestamp)
#
#class Delete:
#    r"""
#    Delete Reports
#    """
#    def POST(self, id):
#        model.delete_report(int(id))
#        raise web.seeother('/report')

class Recover:
    r"""
    User must enter username and CIN (Client Identification Number)
    """

    form_uname = web.form.Form(
            web.form.Textbox('uname', web.form.notnull,
                size=30,
                description='Enter username to begin the recovery process:'),
            web.form.Textbox('cin', web.form.notnull,
                size=30,
                description='Now enter your CIN (Client identification number: '),
            web.form.Button('submit', type='submit', description="Submit")
    )

    def GET(self):
        form = self.form_uname
        return render.recover(form)

    @csrf_protected
    def POST(self):
        i = web.input()
        users = model.get_user_by_name(i.cin, i.uname)
        try:
            user = [u for u in users if u.username == i.uname.lower()][0]
        except IndexError:
            raise web.notfound("User doesn't exist")
        if user:
            key = uuid4().hex

            #web.sendmail('developer@skybell.com.au',user.email,'Password Reset Email',
            #        'Dear %s,\n We have received notice that you have submitted a password reset.\n You can follow up on this by following this link: %s\n If you did not request this, alert us to possible security exploits by contacting us at (08)95863555 or by email at developer@skybell.com.au' % (user.username, '/forgottenpassword/'+str(user.userID)+'@'+str(user.FK_clientID)+'@'+key))
            model.generate_recovery_link(user.FK_clientID, user.userID, key)
            raise web.seeother('/forgotpassword/'+str(user.userID)+'@'+str(user.FK_clientID)+'@'+key)
        else:
            raise web.seeother('/recover/')

class PasswordChange:
    r"""
    Generated by a random collection of characters based on uname,id and password hash
    """

    form = web.form.Form(
            web.form.Password('password', web.form.notnull,
                size=30,
                description="Enter a new password"),
            web.form.Password('password2', web.form.notnull,
                size=30,
                description="Re-enter newpassword"),
            web.form.Button('submit', type='submit', description="Submit"),
            web.form.Button('incorrect', type='submit', description="Incorrectly sent"),
            validators=[
                web.form.Validator("Passwords didn't match", lambda i: i.password == i.password2)],
            )

    def GET(self, uid, cin, key=None):
        r"""
        Retrieves UID,CIN and key from HTML GET query and uses the values
        to generate a page where the
        """
        if key is not None:
            form = self.form
            try:
                recovery = model.get_recovery_time(cin, uid, key)[0]
                user = model.get_user_by_id(cin, uid)[0]
                t = timedelta(days=1)
                d1, d2 = datetime.utcnow(), datetime.utcfromtimestamp(recovery.timestamp)
                if d2 + t > d1:
                    return render.passwordchange(form, user, key, d2+t)
                else:
                    raise web.notfound('Link has expired')
            except IndexError:
                raise web.notfound()
        else:
            raise web.notfound()

    @csrf_protected
    def POST(self, uid,cin, key):
        i = web.input()
        user = model.get_user_by_id(cin, uid)[0]
        form = self.form
        if form.validates():
            pwd = bcrypt.hashpw(i.password, bcrypt.gensalt(BCRYPT_WLOAD))
            model.update_user(cin, uid, pwd, user.email, user.privilege)
            raise web.seeother('/login')
        else:
            try:
                recovery = model.get_recovery_time(cin, userid, key)[0]
                t = timedelta(days=1)
                d1, d2 = datetime.utcnow(), datetime.utcfromtimestamp(recovery.timestamp)
                if d2 + t > d1:
                    return render.passwordchange(form, user, key, d2+t)
                else:
                    raise web.notfound('Link has expired')
            except IndexError:
                raise web.notfound()

#Depracated
#class Display:
#    r"""
#    Files forced to download by altering the header
#    """
#    form = web.form.Form(
#            web.form.Button('save', type="submit",
#                description="Save File")
#            )
#
#    def GET(self, fn):
#        form = self.form
#        return render.display(fn, form)
#
#    def POST(self, fn):
#        path = self.resource_dir + fn
#        print path
#        if ospath.exists(path):
#            resource = file(path,'rb')
#            print resource
#            web.header('Content-Type','attachment/octet-stream')
#            web.header('Content-transfer-encoding','base64')
#            return resource.read()
#        else:
#            raise web.notfound()

#class Table:
#    r"""
#    Displays and formats a table directly from an xlsx (excel) spreadsheet
#    """

class Category:

    def GET(self, cat, letter):
        resources = model.get_resource_by_category_for_letter(cat, letter)
        return render.category(resources)

    def POST(self):
        pass

if __name__ == '__main__':
    app.notfound = notfound
    app.internalerror = web.debugerror
    app.run()
