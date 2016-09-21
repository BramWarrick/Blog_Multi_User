#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#		http://www.apache.org/licenses/LICENSE-2.0
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
import string
import random
import hashlib
import hmac

from blog_entities import *
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

# Document flow:
# Security helper functions
# Handlers
#	Registration
#	Login
# 	Logout

# Security helper functions
def hash_str(s):
	return hmac.new('89frheojco;d94&', s, hashlib.sha1).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

# Handlers 

# General Handler, base of all subsequent handlers
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and Users.by_id(int(uid))

# Currently not in use, due to testing guidelines. Plan to re-activate
class SignInHandler(Handler):
	def get(self):
		self.redirect("/blog/registration")

# Registration logic
class RegistrationHandler(Handler):
	def get(self):
		self.render("blog/registration.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		if check_submission(username, password, verify, email):
			# User passed all validations; add user and send cookies
			u = Users.register(username, password, email)
			u.put()

			self.login(u)
			self.redirect('/blog')

		else:
			self.render("blog/registration.html", username_error = isAllowedUsername(username),
											password_error = isAllowedPassword(password),
											verify_error = matchesPasswordVerify(password,verify),
											email_error = isRegExEmail(email),
											username = username,
											email = email
											)

# Registration - helper function
def check_submission(username, password, verify, email):
	if isAllowedUsername(username) == "" and isAllowedPassword(password) == "" and matchesPasswordVerify(password, verify) == "" and isRegExEmail(email) == "":
		return True
	else:
		return False

# Registration - User validations with error messages
def isAllowedUsername(username):
	if not filledUsername(username):
		return "Username is a required field."
	elif not isRegExUsername(username):
		return "Username must be 3-20 characters, using letters and numbers."
	elif existsUsername(username):
		return "Username already in use."
	else: 
		return ""

def filledUsername(username):
	return len(username) > 0

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def isRegExUsername(username):
	return USER_RE.match(username)

def existsUsername(username):
	q = Users.all()
	q.filter("username = ", username)

	return q.get()

# Registration - Password validations with error messages
def isAllowedPassword(password):
	if not filledPassword(password):
		return  "Password is a required field."
	elif not isRegExPassword(password):
		return "That is not a valid password."
	else:
		return ""

def filledPassword(password):
	return len(password) > 0

PASSWORD_RE=re.compile(r"^.{3,20}$")
def isRegExPassword(password):
	return PASSWORD_RE.match(password)

# Registration - Password Verification with error message is not a match
def matchesPasswordVerify(password, verify):
	if password and not password == verify:
		return "Your passwords didn't match."
	else:
		return ""

# Registration - Email validation with error message if needed
EMAIL_RE=re.compile(r"^[\S]+@[\S]+.[\S]+$")
def isRegExEmail(email):
	if email and not validEmail(email):
		return "That is not a valid email."
	else:
		return ""

def validEmail(email):
	return EMAIL_RE.match(email)

# Login logic
class LoginHandler(Handler):
	def get(self):
		self.render("blog/login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = Users.login(username, password)
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			self.render("blog/login.html", login_error = "Invalid login"
											# username = username,
											)

class LogoutHandler(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog')

app = webapp2.WSGIApplication([('/sign-up', RegistrationHandler),
								('/signin', RegistrationHandler),
								('/sign-in', RegistrationHandler),
								('/blog/sign-up', RegistrationHandler),
								('/blog/signin', RegistrationHandler),
								('/blog/sign-in', RegistrationHandler),
								('/blog/registration', RegistrationHandler),
								('/login', LoginHandler),
								('/blog/login', LoginHandler),
								('/blog/logout', LogoutHandler),
								],
								debug=True)
