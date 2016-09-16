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
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import re
import random
import string
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.EmailProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainHandler(Handler):
	def get(self):
		# self.render("index.html")
		self.response.headers['Content-Type'] = 'text/plain'
		visits = 0
		visit_cookie_str = self.request.cookies.get('visits')
		if visit_cookie_str:
			cookie_val = check_secure_val(visit_cookie_str)
			if cookie_val:
				visits = int(cookie_val)
		visits += 1
		new_cookie_val = make_secure_val(str(visits))

		self.response.headers.add_header('Set-Cookie','visits=%s' % new_cookie_val)

		if visits > 10000:
			self.write("You are the best ever!")
		else:
			self.write("You've been here %s times!" % visits)

# Sign up logic
class SignUpHandler(Handler):
	def get(self):
		self.render("minor_hw/sign-up.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		if check_submission(username, password, verify, email):
			# User passed all validations; add user and send cookies
			password_secured = user_register(username, password, email)
			self.response.headers['Content-Type'] = 'text/plain'
			self.response.headers.add_header('Set-Cookie',str('u=%s' % username))
			self.response.headers.add_header('Set-Cookie',str('p=%s' % password_secured))
			self.response.write('Welcome, ' + username + "!")
		else:
			self.render("minor_hw/sign-up.html", username_error = check_username(username),
												password_error = check_password(password),
												verify_error = check_verify(password, verify),
												email_error = check_email(email),
												username = username,
												email=email
												)

def user_register(username, password, email):
	password_secured = make_pw_hash(username, password)
	if email:
		u = Users(username = username, password = password_secured, email = email)
	else:
		u = Users(username = username, password = password_secured)
	u.put()
	return password_secured

def existsUsername(username):
	q = Users.all()
	q.filter("username = ", username)

	return q.get()

def check_submission(username, password, verify, email):
	if check_username(username) == "" and check_password(password) == "" and check_verify(password, verify) == "" and check_email(email) == "":
		return True
	else:
		return False

def check_username(username):
	if not exists_username(username):
		return "Username is a required field."
	elif not valid_username(username):
		return "Username must be 3-20 characters, using letters and numbers."
	elif existsUsername(username):
		return "Username already in use."
	else: 
		return ""

def check_password(password):
	if not exists_password(password):
		return  "Password is a required field."
	elif not valid_password(password):
		return "That is not a valid password."
	else:
		return ""

def check_verify(password, verify):
	if password and not matches_password(password, verify):
		return "Your passwords didn't match."
	else:
		return ""

def check_email(email):
	if email and not valid_email(email):
		return "That is not a valid email."
	else:
		return ""

def exists_username(username):
	return len(username) > 0

def exists_password(password):
	return len(password) > 0

def matches_password(password, verify):
	return password == verify

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE=re.compile(r"^.{3,20}$")
EMAIL_RE=re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
	return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def hash_str(s):
	return hmac.new('89frheojco;d94&', s, hashlib.sha1).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def make_salt():
	return ''.join(random.choice(string.ascii_letters) for x in range(5))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

app = webapp2.WSGIApplication([('/sign-up', SignUpHandler),
								],
								debug=True)
