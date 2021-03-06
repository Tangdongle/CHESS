import web

db = web.database(dbn='mysql', user='tang', pw='d565458520', db='chess')

#User db functions

def add_user(cin, username, password, email, privilege=0):
    """Insert user into database with default 0 privilege level. Checks if CIN exists"""
    if db.select('chess_clients', where="clientID=$cin", vars=locals()):
        if not db.select('chess_users', where="FK_clientID=$cin and username=$username", vars=locals()):
            db.insert('chess_users', FK_clientID=cin, username=username, password=password, email=email, privilege=privilege)
        else:
            return -1
    else:
        return 0

def del_user(cin, userid):
    """Delete a user from UID and CIN"""
    db.delete('chess_users', where="FK_clientID=$cin AND userID=$userid", vars=locals())

def update_user(cin, uid, password, email, privilege):
    """Update a users details"""
    db.update('chess_users', where="FK_clientID=$cin AND userID=$uid", vars=locals(),
            password=password, privilege=privilege, email=email)

def update_user_name(cin, oldname, newname):
    """Change a users name"""
    if db.select('chess_users', where="FK_clientID=$cin and username=$newname", vars=locals()):
        return -1
    else:
        db.update('chess_users', where="FK_clientID=$cin AND username=$oldname",
                vars=locals(), username=newname)
        return 0

def get_users_by_privilege(cin, privilege=0):
    """Return all users in a particular privilege group"""
    return db.select('chess_users', what="userID, FK_clientID, username",  where="FK_clientID=$cin AND privilege=$privilege", order='userID DESC', vars=locals())

def get_user_by_name(cin, username):
    """Return user details based on CIN and username"""
    return db.select('chess_users', where='FK_clientID=$cin AND username=$username', order='username DESC', vars=locals())

def get_user_by_id(cin, uid):
    """Return user details based on CIN and user ID"""
    return db.select('chess_users', where='FK_clientID=$cin AND userID=$uid', order='userID DESC', vars=locals())

def get_user_by_cin(cin):
    """Retrieve all users in aclient group"""
    return db.select('chess_users', where="FK_clientID=$cin", order="FK_clientID ASC", vars=locals())


def get_all_users():
    """Return a list of all users"""
    return db.select('chess_users', what='userID, FK_clientID, username, email, privilege', order='username DESC')

#Client functions

def cin_exists(cin):
    """Check if a client ID exists"""
    c = db.select('chess_clients', where="clientID=$cin", vars=locals())
    return True if c else False

def add_client(cin, cname):
    """Add client ID"""
    db.insert('chess_clients', clientID=cin, clientname=cname)

#Report db functions !!Redundant
#def add_report(username, text, country, state, site):
#    l_id = db.query("INSERT IGNORE INTO chess_locations (country, state, site) VALUES ($country, $state, $site)", vars=locals())
#    if l_id < 1:
#        l_id = db.select('chess_locations', where='country=$country AND state=$state AND site=$site', vars=locals())[0].id
#
#    r_id = db.insert('chess_reports', report_text=text)
#    db.insert('chess_incidents', FK_userid=get_user_by_name(username)[0].id, timestamp=web.SQLLiteral("UNIX_TIMESTAMP()+0"), FK_reportid=r_id, FK_locationid=l_id)
#
#def get_report_by_id(id):
#    return db.select('chess_incidents', where="id=$id", what="FK_userid,FK_locationid,FK_reportid", vars=locals())
#
#def delete_report(id):
#    entries = get_report_by_id(id)[0]
#    db.delete('chess_incidents', where="id=$id", vars=locals())
#    db.delete('chess_reports', where="id=$entries.FK_reportid", vars=locals())
#
#def get_reports():
#    return db.query("SELECT cr.report_text, ci.timestamp, ci.id, cl.country, cl.state, cl.site, cu.username FROM chess_incidents ci LEFT JOIN (chess_reports cr, chess_users cu, chess_locations cl) ON (cr.id=ci.FK_reportid AND cl.id=ci.FK_locationid AND cu.id=ci.FK_userid)")

#Recovery options


def generate_recovery_link(cin, uid, key):
    """Insert key into db and timestamp to account for expiry"""
    db.insert('password_change_requests', FK_clientID=cin, FK_userID=uid, userkey=key, timestamp=web.SQLLiteral("UNIX_TIMESTAMP()+0"))

def delete_recovery_link(cin, uid):
    """Delete recovery entry (ie when time limit expires"""
    db.delete('password_change_requests', where="FK_userid=$userid AND FK_clientID=$cin",vars=locals())

def get_recovery_link_by_id(cin, uid):
    """Reurns recovery data based on user id"""
    return db.select('password_change_requests', where="FK_clientID=$cin AND FK_userID=$uid", vars=locals())

def get_recovery_time(cin, uid,key):
    """Returns recovery entry timestamp based on CIN,UID and the key (typical usage for retrieving timestamp"""
    return db.select('password_change_requests', where="FK_clientID=$cin AND userkey=$key AND FK_userid=$uid", what="timestamp", vars=locals())


#Resources

def get_all_resources(cin):
    """Returns a list of all resource filenames"""
    return db.select('chess_resourcetypes', what='resourcefname',
    where="FK_clientID=cin", order='resourcetype, resourcecat', vars=locals())

def get_all_resources_for_letter(letter):
    """Returns a list of all categories for a given letter"""
    letter = letter + '%'
    return db.select('chess_resourcetypes', what='resourcefname, FK_clientID',
            where="FK_clientID=0 AND resourcefname LIKE $letter", vars=locals(),
            order="resourcefname DESC")

def get_resource_by_category(cin, category):
    """Returns a list of all resources belonging to a given category"""
    return db.select('chess_resourcetypes', what='resourcefname',
            where='resourcecat=$category AND FK_clientID=$cin', vars=locals(), order='resourcefname DESC')

def get_resource_categories():
    """Returns a list of resource categories"""
    return db.select('chess_resourcetypes', what="resourcecat",
            order='resourceID ASC')

def get_resource_by_category_for_letter(cin, category, letter):
    """Return all letters for a given category"""
    letter = letter + "%"
    return db.select('chess_resourcetypes', what="resourcefname, FK_clientID",
            where="resourcecat=$category AND FK_clientID=$cin AND resourcefname LIKE $letter",
            order="resourcefname DESC", vars=locals())

def add_resource(cin, rtype, category, name, priv):
    """Add resource to database"""
    db.insert('chess_resourcetypes', FK_clientID=cin, resourcetype=rtype, resourcecat=category, resourcefname=name, requiredpriv=priv)

def get_client_repo(cin):
    """Get a clients Repo"""
    return db.select('chess_repository', what="resourcefname, is_latest, mod_timestamp",
            where="FK_clientID=$cin", order="repoID DESC",
            vars=locals())

def get_latest_files(cin):
    """Get latest versions of a client's files"""
    return db.select('chess_repository', what="resourcefname",
            where="FK_clientID=$cin AND is_latest=true",
            order="resourcefname DESC", vars=locals())

def add_repo_resource(cin, fname):
    last =  db.select('chess_repository', where="resourcefname=$fname AND is_latest=True", what='repoID', vars=locals())[0]
    if last:
        new_name = fname[:fname.find('.')] + str(last.repoID) + fname[fname.find('.'):]
        db.update('chess_repository', where="resourcefname=$fname AND is_latest=True",
                is_latest=False, resourcefname=new_name, vars=locals())
        db.insert('chess_repository', FK_clientID=cin, is_latest=True, resourcefname=fname, mod_timestamp=web.SQLLiteral("UNIX_TIMESTAMP()+0"))
        return last.repoID
    else:
        db.insert('chess_repository', FK_clientID=cin, is_latest=True, resourcefname=fname, mod_timestamp=web.SQLLiteral("UNIX_TIMESTAMP()+0"))
        return -1


