#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the Licensfor the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os.path
import jinja2
import re
import random
import string
import hashlib
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PSWD_RE = re.compile(r"^.{3,20}$")
def valid_pswd(passwd):
    return PSWD_RE.match(passwd)

def pswd_match(passwd, repasswd):
    return passwd==repasswd

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

def hash_str(s):
    return hashlib.sha256(s).hexdigest()

# implement the function make_salt() that returns a string of 5 random
# letters use python's random module.
# Note: The string package might be useful here.
def make_salt():
    randStr = ''

    for i in range(1,6):
        randomNum = random.randrange(0,26)
        randChar = string.ascii_lowercase[randomNum]
        randStr = randStr + randChar

    return randStr
    
        
# implement the function make_pw_hash(name, pw) that returns a hashed password 
# of the format: 
# HASH(name + pw + salt),salt
# use sha256

def make_pw_hash(name, pw):
    theSalt = make_salt()
    strToHash = name+pw+theSalt
    return "%s|%s" % (theSalt,hash_str(strToHash))

    
def valid_pw(name, pw, h):
    hArray = h.split('|')
    theHash = hArray[1]
    theSalt = hArray[0]
    if hash_str(name+pw+theSalt)==theHash:
        return True
    return False

def is_username_unique(username):
    #get usernames from the database
    usernames = db.GqlQuery("SELECT * FROM User ORDER BY username ASC")
    #run() returns an iterable to loop through the query
    for user in usernames.run():
        if username == user.username:
            return False
    return True

def username_exists(username):
    #get usernames from the database
    usernames = db.GqlQuery("SELECT * FROM User ORDER BY username ASC")
    for user in usernames.run():
        if username == user.username:
            return True
    return False
    
def passwd_exists(pw):
    #get usernames from the database
    passwords = db.GqlQuery("SELECT * FROM User ORDER BY password ASC")
    for p in passwords.run():
        if pw == p.password:
            return True
    return False

class User(db.Model):
	username = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.redirect('/signup', SignupHandler)

    def render(self, template, **kwargs):
        t = jinja_env.get_template(template)
        self.response.out.write(t.render(kwargs))

class SignupHandler(MainHandler):
   
    def get(self):
        self.render('signup-form.html', username='')

    def post(self):
        errString = dict()
        name = self.request.get('username')
        pw = self.request.get('password')
        email = self.request.get('email')
        
        if not valid_username(self.request.get('username')):
            errString['error_username'] = 'not a valid username'
            
        #check if username is unique
        if not is_username_unique(name):
            errString['error_username'] = 'username not unique'
            
        if not valid_pswd(self.request.get('password')):
            errString['error_password'] = 'That\'s not a valid pasword'
            
        if not pswd_match(self.request.get('password'), self.request.get('verify')):
            errString['error_verify'] = 'Passwords don\'t match'

        if self.request.get('email'):
            if not valid_email(self.request.get('email')):
                errString['error_email']='Invalid email'                               

        if not errString:
            u = User(username=name, password=pw, email=email)
            u.put()
            u_id = str(u.key().id())
            value = make_pw_hash(name, pw)
            self.response.set_cookie('registercookie', value=value, path='/')
            self.redirect('/welcome/%s' % u_id)
        else:
            self.render('signup-form.html',**errString)


class WelcomeHandler(MainHandler):
    def get(self, u_id):
        u = User.get_by_id(int(u_id))
        #get the required info from the cookie
        value=self.request.cookies.get('registercookie')
        name=u.username
        pw = u.password
        theSalt = value.split('|')[0]
        hashStr = value.split('|')[1]
        if valid_pw(name, pw, value):
            self.response.out.write('Welcome, ' + name)
        else:
            self.redirect('/signup')

class LoginHandler(MainHandler):
    def get(self):
        self.render('login_form.html', username='')

    def post(self):
        errString = dict()
        nameenterd = self.request.get('username')
        pwenterd = self.request.get('password')
        if not username_exists(nameenterd):
            errString['error_username'] = 'user does not exist'

        if not passwd_exists(pwenterd):
            errString['error_password'] = 'password does not exist'

        if not errString:
            value = make_pw_hash(nameenterd, pwenterd)
            self.response.set_cookie('registercookie', value=value, path='/')
            q = db.GqlQuery("SELECT * FROM User WHERE username='%s'" % nameenterd)
            #for e in q.run():
                #u_id = e.id
            #q = User.query(User.username == nameenterd)
            for u in q.run():
                u_id = u.key().id()
            self.redirect('/welcome/%s' % u_id)
        else:
            self.render('login_form.html', **errString)

class LogoutHandler(MainHandler):
    def get(self):
        self.response.delete_cookie('registercookie', path='/')
        self.redirect('/signup')

    def post(self):
        self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler),
    ('/welcome/([0-9]+)', WelcomeHandler),
    ('/login' , LoginHandler),
    ('/logout', LogoutHandler)
], debug=True)
