import web
import re
import bcrypt
import model
from MySQLdb import IntegrityError

MIN_PASS_LEN = 6
BCRYPT_WLOAD = 15

db = web.database(dbn='mysql', user='tang', pw='d565458520', db='pyweb')


render = web.template.render('templates/', base='layout', cache=False)
render_plain = web.template.render('templates/')

urls = (
        '/','Index',
        '/admin','Admin',
        '/home','Home',
        '/login','Login',
        '/register','Register',
        )

app = web.application(urls, globals())

if web.config.get('_session') is None:
    session = web.session.Session(app, web.session.DiskStore('sessions'), initializer={'logged_in':False})
    web.config._session = session
else:
    session = web.config._session

def is_valid_uname(uname):
    return bool(len(model.get_user_by_name(uname)) == 0)

def logged_in():
    if session.get('logged_in', True):
        return True
    else:
        return False

def check_pwd_len(pwd):
    return bool(len(pwd) >= MIN_PASS_LEN)

vpass = web.form.Validator('Password too short', check_pwd_len)
vuname = web.form.Validator('Username already exists!', is_valid_uname)

class Index:

    def GET(self):
        if logged_in():
            p = render_plain.popup()
            return render.index(p)
        else:
            raise web.seeother('/login')

    def POST(self):
        p = render_plain.popup()

        return render.index(p)


class Admin:

    def GET(self):
        return render.admin()

    def POST(self):
        return render.admin()

class RegForm(web.form.Form):
    """
    html

    """

    def __init__(self, *inputs, **kw):
        super(RegForm, self).__init__(*inputs, **kw)

    def render(self):
        out = ''
        out += self.rendernote(self.note)
        out += '<div class="_form">\n'

        for n,i in enumerate(self.inputs):
            html = web.utils.safeunicode(i.pre) + i.render() + self.rendernote(i.note) + web.utils.safeunicode(i.post)
            if i.is_hidden():
                out += '    <div style="display:none">%s</div>\n' % (html)
            else:
                out += '    <div><label for="%s">%s</label>%s</div>\n' % (i.id, web.net.websafe(i.description), html)
        out += "</div>"
        return out

class Login:

    form = RegForm(
        web.form.Textbox('username', web.form.notnull,
            size=25,
            description="Username:"),
        web.form.Password('password', web.form.notnull, vpass,
            size=25,
            description='Password:'),
        web.form.Button('Login'),
    )

    def GET(self):
        if logged_in():
            web.seeother('/splash')
        else:
            form = self.form()
            return render.login(form)

    def POST(self):
        form = self.form()
        if not form.validates():
            return render.login(form)
        else:
            i = web.input()
            pwdhash = bcrypt.hashpw(i.password, bcrypt.gensalt(BCRYPT_WLOAD))
            check = db.execute('select * from ohms_users where username=? and password=?', (i.username, pwdhash))   #check hash vs db
        if check:
            session.logged_in = True
            session.username = i.username
            raise web.seeother('/admin')
        else:
            return render.login("Those login details are INCORRECT!")


class Register:
    r"""
    Register Page
    Deals with creating new users. Ensures duplicate users aren't created
    """
    form = RegForm(
            web.form.Textbox('username', web.form.notnull, vuname,
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
        #if logged_in():
        #    raise web.seeother('/')
        #else:
        form = self.form()
        return render.register(form,model.get_users_by_privilege())

    def POST(self):
        i = web.input()
        form = self.form()
        if not form.validates():
            return render.register(form,model.get_users_by_privilege())
        else:
            uname, pwd = i.username.strip(), i.password.strip()
            #register parsing here
            pwd = bcrypt.hashpw(pwd, bcrypt.gensalt(BCRYPT_WLOAD))
            model.add_user(uname,pwd)
            session.logged_in = True
            raise web.seeother('/')



if __name__ == '__main__':
    app.internalerror = web.debugerror
    app.run()
