import web

db = web.database(dbn='mysql', user='tang', pw='d565458520', db='ohms')

def add_user(username, password):
    db.insert('ohms_users', username=username, password=password, privilege=0)

def del_user(username):
    db.delete('ohms_users', where="username=$username", vars=locals())

def update_user(username, password, privilege):
    db.update('ohms_users', where="username=$username", vars=locals(),
            password=password, privilege=privilege)

def get_users_by_privilege(privilege=0):
    return db.select('ohms_users', where="privilege=$privilege", order='username DESC', vars=locals())

def get_user_by_id(userid):
    return db.select('ohm_users', where='userid=$userid', order='userid DESC', vars=locals())

def get_user_by_name(username):
    return db.select('ohms_users', where='username=$username', order='userid DESC', vars=locals())

