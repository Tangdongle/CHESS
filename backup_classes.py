
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
        form = self.form()
        return render.register(form,model.get_users_by_privilege())

    def POST(self):
        i = web.input()
        form = self.form()
        if not form.validates():
            return render.register(form,model.get_users_by_privilege())
        else:
            uname, pwd, email = i.username.strip().lower(), i.password.strip(), i.email.strip()
            #register parsing here
            pwd = bcrypt.hashpw(pwd, bcrypt.gensalt(BCRYPT_WLOAD))
            model.add_user(uname,pwd, email)
            session.logged_in = True
            session.username = uname
            raise web.seeother('/')

class Login:
    """
    Deals with user login
    """

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
            web.seeother('/')
        else:
            form = self.form()
            return render.login(form,users=model.get_users_by_privilege())

    def POST(self):
        form = self.form()
        if not form.validates():
            return render.login(form)
        else:
            i = web.input()
            pwdhash = bcrypt.hashpw(i.password, bcrypt.gensalt(BCRYPT_WLOAD))
            check = model.authenticate_user(i.username, pwdhash)
        if check:
            session.logged_in = True
            session.username = i.username
            raise web.seeother('/admin')
        else:
            return render.login(form,"login failed!")

class Recover:
    """
    For password recovery. Probably deliver 2 options: email and question
    """

    form_uname = web.form.Form(
            web.form.Textbox('uname', web.form.notnull,
                size=30,
                description='Enter username to begin the recovery process:'),
            web.form.Button('submit', type='submit', description="Submit")
    )

    def GET(self):
        form = self.form_uname
        return render.recover(form)

    def POST(self):
        i = web.input()
        users = model.get_user_by_name(i.uname)
        user = [u for u in users if u.username == i.uname.lower()][0]
        if user:
            key = bcrypt.hashpw(user.username+str(user.id)+str(user.password), bcrypt.gensalt(BCRYPT_WLOAD))
            #web.sendmail('developer@skybell.com.au',user.email,'Password Reset Email',
            #        'Dear %s,\n We have received notice that you have submitted a password reset.\n You can follow up on this by following this link: %s\n If you did not request this, alert us to possible security exploits by contacting us at (08)95863555 or by email at developer@skybell.com.au' % (user.username, '/forgottenpassword/'+key))
            model.generate_recovery_link(user.id, key, datetime.time(datetime.now()).isoformat())
            raise web.seeother('/forgotpassword/'+key)
        else:
            raise web.seeother('/recover/')
