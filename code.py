import web
import logging
from datetime import date, datetime, timedelta
import re
import bcrypt
#database interface
import model
#for CSRF tokens
from uuid import uuid4
import os
from os import path as ospath
#For limiting upload size
import cgi
from shutil import move, copy

MIN_PASS_LEN = 4
BCRYPT_WLOAD = 10
RESOURCE_DIR = 'static/resources/'
ROOT_RESOURCE_DIR = RESOURCE_DIR + '0/'
REPO_DIR = 'repo/'
MAX_LOGIN_ATTEMPTS = 5

DOWNLOAD_COUNT = {}

#Set max upload limit to 30MB
cgi.maxlen = 30 * 1024 * 1024

logging.basicConfig(format='%(asctime)s - %(message)s ', filename='chess.log',level=logging.WARNING)
#logging.basicConfig(filename='chess.log',level=logging.INFO)
logger = logging.getLogger(__name__)

urls = (
        '/','Index',
        '/admin','Admin',
        '/home','Index',
        '/login','Login',
        '/recover','Recover',
        '/forgotpassword/(\d+)@(\d+)@(\S+)','PasswordChange',
        '/logout','Logout',
        #'/register','Register',
        '/category/(\S+)/([A-Z])','Category',
        '/download/(\S+)/([A-Z])/(\d+)/(\w+)','Download',
        '/upload[/]*(\d*)$','Upload',
        '/settings','Settings',
        '/repository[/]*(\d*)[/]*([\w\d.]*)[/]*([TF]*)[/]*$','Repository',
        )

app = web.application(urls, globals())


if web.config.get('_session') is None:
    session = web.session.Session(app, web.session.DiskStore('sessions'),
            initializer={'logged_in':False,'priv':0,'username':'Guest','cin':0,'loginfails':0,})
    web.config._session = session
else:
    session = web.config._session

web.config.session_parameters['cookie_name'] = 'chess_session_id'
web.config.smtp_server = 'mail.westnet.com.au'

def logged_in():
    if session.get('logged_in'):
        return True
    else:
        return False

def check_pwd_len(pwd):
    return bool(len(pwd) >= MIN_PASS_LEN)

vpass = web.form.Validator('Password too short', check_pwd_len)

def check_priv_lvl(priv):
    return session.priv >= priv

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



render = web.template.render('templates/', base='layout', cache=False, globals={'csrf_token':csrf_token,'context':session,'no_header':0})
render_plain = web.template.render('templates/')


class Index:
    r"""
    Home splash page
    """
    def GET(self):
        if logged_in():
            res_cats = [i.resourcecat for i in model.get_resource_categories()]
            l = list(set(res_cats))
            return render.index(l)
        else:
            raise web.seeother('/login')


    def POST(self):
        raise web.seeother('/')


class Admin:
    r"""
    Admin panel
    """

    form = web.form.Form(
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

    cin_form = web.form.Form(
            web.form.Textbox('new_client', web.form.notnull,
                size=25,
                description="Enter new client ID"),
            web.form.Textbox('client_name', web.form.notnull,
                size=25,
                description='Enter Client name'),
            web.form.Button('add_cin', type='submit',
                description='Add Client'),
            )


    def GET(self):
        if not logged_in():
            raise web.seeother('/login')
        if not check_priv_lvl(2):
            raise web.notfound("You don't have the right privilege level to access this")
        users = model.get_user_by_cin(session.cin)
        client_form = self.cin_form()
        user_form = self.form()
        return render.admin(model.get_all_users() if session.cin==0 else users, user_form, client_form)

    @csrf_protected
    def POST(self):
        if not check_priv_lvl(2):
            raise web.notfound("You don't have the right privilege level to access this")
        i = web.input(cin=None)
        user_form = self.form()
        client_form = self.cin_form()
        if 'uid' in i:
            logger.info("Deleting user")
            model.del_user(i.cin, i.uid)
            logger.debug('User Deleted: %d',i.uid)
        elif 'new_client' in i:
            if client_form.validates():
                logger.info("Adding new client")
                model.add_client(i.new_client, i.client_name)
                logger.debug('Client Added: %d|%s',i.new_client, i.client_name)
        elif 'username' in i:
            logger.info("Adding user")
            if not user_form.validates():
                return render.admin(model.get_all_users() if session.cin==0 else model.get_user_by_cin(session.cin), user_form, client_form)
            uname, pwd, email = i.username.strip().lower(), i.password.strip(), i.email.strip()
            pwd = bcrypt.hashpw(pwd, bcrypt.gensalt(BCRYPT_WLOAD))
            cin = i.cin if i.cin else session.cin
            ret = model.add_user(cin, uname,pwd, email, i.privilege)
            #Checks if CIN exists and if CIN/Username combination exists
            if ret == 0:
                raise web.notfound("No client exists with this CIN")
            elif ret == -1:
                raise web.notfound("Username exists with identical CIN")
            logger.debug('User added %s', uname)
        raise web.seeother('/admin')

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
                out += '    <div style="height:auto;">%s</div><div class="%s"><label for="%s">%s</label>%s</div>\n' % (i.rendernote(i.note), web.net.websafe(i.name), i.id, web.net.websafe(i.description), html)
        out += "</div>"
        return out

class Login:
    r"""
    Deals with user login
    """

    form = RegForm(
        web.form.Textbox('username', web.form.notnull,
            size=25, placeholder="Username...",
            description="username:"),
        web.form.Password('password', web.form.notnull, vpass,
            size=25, placeholder="Password...",
            description="password:"),
        web.form.Textbox('cin', web.form.notnull,
            size=25, placeholder="Customer Identification Number",
            description="Enter CIN: "),
        web.form.Button('login', type="submit", description="login"),
    )

    bannedtimer = timedelta(minutes=15)
    time_format = '%Y-%m-%d %H:%M:%S.%f'

    def GET(self):
        logger.debug('Logged_in: %s', session.logged_in)
        if logged_in():
            web.seeother('/')
        else:
            form = self.form()
            return render.login(form,users=model.get_all_users())

    @csrf_protected
    def POST(self):
        """
        Compares given CIN, username and password to db entry
        """
        i = web.input()
        form = self.form()
        logger.debug('Logged_in: %s', session.logged_in)
        output=[]
        if ospath.exists('banned_ip.chess'):
            with open('banned_ip.chess','r') as bfd:
                for line in bfd:
                    if web.ctx['ip'] in line:
                        t = line[line.find('|')+2:-1].strip()
                        d = datetime.strptime(t,self.time_format)
                        dc = datetime.utcnow()
                        if d + self.bannedtimer <= dc:
                            return "<h1>Too many failed login attempts.</h1><br /><h2>Please try again at a later time</h2>"
                        else:
                            output.append(line)
            with open('banned_ip.chess','w') as bfd:
                f.writelines(output)
        if not form.validates():
            return render.login(form, users=model.get_all_users())
        else:
            try:
                u = model.get_user_by_name(i.cin, i.username.strip().lower())[0]
            except IndexError:
                return render.login(form,"User does not exist! If you need an account, please contact your local admin.", users=model.get_all_users())
            check = True if bcrypt.hashpw(i.password, u.password) == u.password else False
        #Check is user authentication was a great success
        if check:
            session.logged_in = True
            session.username = i.username
            session.cin = int(i.cin)
            session.priv = u.privilege
            raise web.seeother('/')
        else:
            try:
                session['loginfails'] += 1
            except KeyError:
                session['loginfails'] = 0
            if session['loginfails'] > MAX_LOGIN_ATTEMPTS:
                ip = web.ctx['ip']
                logger.warning('IP %s has attempted too many unsuccessfull logins', ip)
                session['loginfails']=0
                with open('banned_ip.chess','a') as bfd:
                    bfd.write("%s | %s"%(web.ctx['ip'],datetime.utcnow()))
            return render.login(form,"login failed!", users=model.get_all_users())


class Logout:
    r"""
    User logout page
    """

    def GET(self):
        if session.logged_in == True:
            session.logged_in = False
            session.username = 'Guest'
            session.priv = 0
            session.cin = -1
        raise web.seeother('/')

#Depracated in favor of allowing only admins to create accounts for their CIN
#class Register:
#    r"""
#    Register Page
#    Deals with creating new users. Ensures duplicate users aren't created
#    """
#    form = RegForm(
#            web.form.Textbox('cin', web.form.notnull,
#                size=25,
#                description="Enter CIN: "),
#            web.form.Textbox('username', web.form.notnull,
#                size=25,
#                description="Enter your Username"),
#            web.form.Textbox('email', web.form.notnull,
#                size=25,
#                description="Enter a Email"),
#            web.form.Password('password', web.form.notnull, vpass,
#                size=25,
#                description="Enter Password"),
#            web.form.Password('password2', web.form.notnull,
#                size=25,
#                description="Repeat Password"),
#            web.form.Button('submit', type='submit', description="Register"),
#    )
#
#    def GET(self):
#        form = self.form()
#        return render.register(form,model.get_all_users())
#
#    @csrf_protected
#    def POST(self):
#        i = web.input()
#        form = self.form()
#        if not form.validates() or i.username in [u.username for u in model.get_all_users()]:
#            return render.register(form,model.get_all_users())
#        else:
#            cin, uname, pwd, email = i.cin, i.username.strip().lower(), i.password.strip(), i.email.strip()
#            #register parsing here
#            pwd = bcrypt.hashpw(pwd, bcrypt.gensalt(BCRYPT_WLOAD))
#            model.add_user(cin, uname,pwd, email)
#            session.logged_in = True
#            session.username = uname
#            session.cin = int(cin)
#            session.priv = 0
#            raise web.seeother('/')


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
        form = self.form_uname()
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

            web.sendmail('developer@skybell.com.au',user.email,'Password Reset Email',
                    'Dear %s,\n We have received notice that you have submitted a password reset.\n You can follow up on this by following this link: %s\n If you did not request this, alert us to possible security exploits by contacting us at (08)95863555 or by email at developer@skybell.com.au' % (user.username, '/forgottenpassword/'+str(user.userID)+'@'+str(user.FK_clientID)+'@'+key))
            model.generate_recovery_link(user.FK_clientID, user.userID, key)
            raise web.seeother('/forgotpassword'+str(user.userID)+'@'+str(user.FK_clientID)+'@'+key)
        else:
            raise web.seeother('/recover')

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
            form = self.form()
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
        form = self.form()
        if form.validates():
            pwd = bcrypt.hashpw(i.password, bcrypt.gensalt(BCRYPT_WLOAD))
            model.update_user(cin, uid, pwd, user.email, user.privilege)
            raise web.seeother('/login')
        else:
            raise web.seeother('/passwordchange/%d/%d/%s') %(uid, cin, key)

class Category:
    """
    Displays all documents for a letter of a chosen category
    """
    def GET(self, cat, letter):
        if not logged_in():
            raise web.seeother('/login')
        if cat == "Archive":
            return render.category(model.get_all_resources_for_letter(letter), cat, letter, session.cin)
        user_resources = model.get_resource_by_category_for_letter(session.cin, cat.replace('_',' '), letter)
        root_resources = model.get_resource_by_category_for_letter(0, cat.replace('_',' '), letter)
        ps = []
        for i in root_resources:
            ts = web.storage()
            for d in user_resources:
                if d:
                    ts['resourcefname']=d.resourcefname
                    ts['FK_clientID']=d.FK_clientID
                    break
            try:
                ts['resourcefname']
            except KeyError:
                ts['resourcefname'] = i.resourcefname
                ts['FK_clientID']=i.FK_clientID
            ps.append(ts)
        ips = iter(ps)
        pool_resources = web.IterBetter(ips)
        return render.category(pool_resources, cat, letter, session.cin)

    def POST(self):
        pass

class Download:
    """
    Serves a chosen file to download
    """
    def GET(self, cat, letter, cin, fn):
        if not logged_in():
            raise web.seeother('/login')
        if cin != session.cin and cin!='0':
            raise web.notfound('You do not have access to that file.')
        else:
            user_resource_dir = RESOURCE_DIR + str(session.cin) + '/'

            #First, check if local repository exists
            logger.info('Checking if user-specific file exists')
            path = user_resource_dir + fn
            logger.debug('Path: %s',path)
            if ospath.exists(path):
                pass
            else:
                #Else, take file from root depository
                logger.info("User file doesn't exist, checking for root file")
                path = ROOT_RESOURCE_DIR + fn
                logger.debug('Root path: %s', path)
                if not ospath.exists(path):
                    logger.info('File not found')
                    raise web.notfound('Oops, file not found!')
            resource = file(path,'rb')
            logger.info('Setting headers to serve file download')
            logger.debug('File: %s', resource)
            # TODO: Track statistics of downloads per user
            web.header('Content-Type','attachment/octet-stream')
            web.header('Content-transfer-encoding','base64')
            return resource.read()

class Upload:
    """
    Handles file uploads
    """

    form = web.form.Form(
            web.form.File("userfile", type="file",
                description="File"),
            web.form.Button("upload", type="submit",
                description="Upload")
            )

    def GET(self, s=0):
        if not logged_in():
            raise web.seeother('/login')
        if not check_priv_lvl(2):
            return web.notfound("Insufficient privileges")
        form = self.form()
        d_list = (list(set([i.resourcecat for i in model.get_resource_categories() if i.resourcecat!='Archive'])))
        msg=None
        if s>0:
            msg = "Upload Successful"
        return render.upload(form, d_list, msg)

    @csrf_protected
    def POST(self):

        if not check_priv_lvl(2):
            return web.notfound("Insufficient privileges")
        form = self.form()
        i = web.input(userfile={})
        web.debug(i['userfile'].filename)
        web.debug(i['userfile'])
        #define user resource directory
        user_resource_dir = 'static/resources/' + str(session.cin) + '/'
        #check if user added a file
        if 'userfile' in i:
            #Ensure any windows separators are replaced to *nix style separators
            filepath = i.userfile.filename.replace('\\','/')
            #Get file name from path
            filename = filepath.split('/')[-1]
            logger.info('Open file to write')
            try:
                #Construct a path for the file to be saved in
                if not ospath.exists(user_resource_dir):
                    os.mkdir(user_resource_dir)
                fout = open(user_resource_dir + filename,'wb')
                logger.info('Write upoloaded file to local file')
                logger.debug('Filename: %s', filename)
                #Write a copy of the submitted file to the server
                fout.write(i.userfile.file.read())
                fout.close()
                logger.info('Get filetype')
                dotindex = filename.find('.')
                if dotindex < 0:
                    ftype = 'doc'
                else:
                    ftype = filename[dotindex:]
                    #Add resource path to database
                    logger.info('Add file to database')
                    logger.debug('Cin: %d, Ftype: %s, Category: %s, \
                            filename: %s, user privilege: %d', session.cin, ftype, \
                            i.category, filename, session.priv)

                model.add_resource(session.cin, ftype,
                        i.category, filename, 0)
                logger.info('Upload successful!')
                raise web.seeother('/upload/1')
            except IOError:
                logger.info('Upload Failed!')
                #Just pass and reload page with "Upload Failed"
                pass
        d_list = (list(set([i.resourcecat for i in model.get_resource_categories() if i.resourcecat!='Archive'])))
        return render.upload(form, d_list, "Upload failed!")

class Settings:
    """
    Allows for user settings alterations"
    """
    form = RegForm(
            web.form.Textbox('new_name', web.form.notnull,
                size=25,
                description="New Username"),
            web.form.Button('save', type="submit",
                description="Save"),
            )

    def GET(self):
        if not logged_in():
            raise web.seeother('/login')
        form = self.form()
        return render.settings(form)

    def POST(self):
        form = self.form()
        if form.validates():
            i = web.input()
            # TODO: Track stats of most common settings
            if model.update_user_name(session.cin, session.username, i.new_name) == -1:
                return render.settings(form, warning="Username not available")
            session.username = i.new_name
            raise web.seeother('/settings')

class Repository:
    """
    Sets up storage on the server to save shared folders in the shared repository.
    Additionally auto-manages multiple copies of files.
    """

#TODO: Sort between latest revisions and older ones
#TODO: Figure out method to rename older files
#TODO: Develop search method maybe


    form = web.form.Form(
            web.form.File("repofile", type="file",
                description="File"),
            web.form.Button("upload", type="submit",
                description="Upload")
    )

    def GET(self, cin, fname, is_l):
        if not logged_in():
            raise web.seeother('/login')
        form = self.form()
        resources = (list(set([(i.resourcefname, i.is_latest, datetime.fromtimestamp(i.mod_timestamp)) for i in model.get_client_repo(session.cin)])))
        # If filename has been retrieved with a GET request
        web.debug(fname, cin, is_l)
        if fname == 'succ' and not cin:
            return render.repository(form, resources, 'File upload successful!')
        if fname and cin:
            fpath = REPO_DIR + str(cin) + '/'
            if is_l == 'T':
                fpath += 'latest' + '/' + fname
            else:
                fpath += 'old' + '/' + fname
            web.debug(fpath)
            if ospath.exists(fpath):
                web.debug(fpath)
                resource = file(fpath,'r')
                #TODO: Add download counter/statistic recorder here
                web.header('Content-Type','attachment/octet-stream')
                web.header('Content-transfer-encoding','base64')
                return resource.read()
        else:
            return render.repository(form, resources)

    @csrf_protected
    def POST(self, cin, fname, is_l):
        form = self.form()
        i = web.input(repofile={})
        web.debug(i['repofile'].filename)
        web.debug(i['repofile'])
        if 'repofile' in i:
            copy_num = -1
            filepath = i.repofile.filename.replace('\\','/')
            filename = filepath.split('/')[-1]
            filepath = REPO_DIR + str(session.cin) + '/' + 'latest' + '/' + filename
            old_filepath = REPO_DIR + str(session.cin) + '/' + 'old' + '/' + filename
            base_repo_dir = REPO_DIR + str(session.cin)
            if not ospath.exists(base_repo_dir):
                os.mkdir(base_repo_dir)
            if not ospath.exists(base_repo_dir + '/' + 'latest'):
                os.mkdir(base_repo_dir + '/' + 'latest')
            if os.path.exists(filepath):
                if not ospath.exists(base_repo_dir + '/' + 'old'):
                    os.mkdir(base_repo_dir + '/' + 'old')
                move(filepath, old_filepath)
            outfd = open(filepath,'wb')
            try:
                outfd.write(i.repofile.file.read())
                outfd.close()
                last_rev = model.add_repo_resource(session.cin, filename)
                if last_rev >= 0:
                    new_fn = filename[:filename.find('.')] + str(last_rev) + filename[filename.find('.'):]
                    copy(old_filepath, REPO_DIR + str(session.cin) + '/' + 'old' + '/' + new_fn)
                raise web.seeother('/repository/succ')
            except IOError:
                resources = (list(set([(i.resourcefname, i.is_latest, datetime.fromtimestamp(i.mod_timestamp)) for i in model.get_client_repo(session.cin)])))
                return render.repository(form, resources, "File upload failed")






if __name__ == '__main__':
    app.notfound = notfound
    app.internalerror = web.debugerror
    app.run()
