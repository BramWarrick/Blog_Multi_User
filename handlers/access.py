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


from google.appengine.ext import db

# Datastore tables are defined on the blog_entities module
from blog_entities import *

# Jinja set up
template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
											'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)


# Security helper functions - obvious and from homework
def hash_str(s):
	return hmac.new('89frheojco;d94&', s, hashlib.sha1).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

######################
#####            #####
#####  Handlers  #####
#####            #####
######################

# General Handler, base of all subsequent handlers
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		""" Allows shortcut command of self.write

		Makes debugging much, much easier
		"""
		self.response.out.write(*a, **kw)

	def render_string(self, template, **params):
		""" Retrieves html file and converts to string
		"""
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		""" Allows shortcut command of self.render

		Makes code read much cleaner. Less visual clutter.
		"""
		self.write(self.render_string(template, **kw))

	def set_secure_cookie(self, name, val):
		""" Sets cookie on the users machine
		
		Args:
			name: name to give cookie on browser
			val: value to assign to cookie
		"""
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		""" Reads cookie and returns the base value - if secure

		Arg:
			name: name of the cookie, if present on user's browser
		"""
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		""" Sets cookie with name of 'user_id' and value of hashed user_id

		Arg:
			user: user entity for the user logging in
		"""
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		""" Wipes cookie from user's browser, logging them out."""
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and Users.by_id(int(uid))

#####  Blog specific handlers

# Currently not in use, due to testing guidelines. Plan to re-activate
class SignInHandler(Handler):
	def get(self):
		self.redirect("/blog/registration")

# Registration logic
class RegistrationHandler(Handler):
	""" Hanldes all registration related functions"""
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
			# Unsuccessful registration attempt, provide instructive error(s)
			self.render("blog/registration.html", 
						username_error = is_allowed_username(username),
						password_error = is_allowed_password(password),
						verify_error = matches_password_verify(password,
																verify),
						email_error = is_allowed_email(email),
						username = username,
						email = email
						)

# Registration - helper function
def check_submission(username, password, verify, email):
	""" If all validations return empty strings, returns True"""
	if is_allowed_username(username) == "" 
		and is_allowed_password(password) == "" 
		and matches_password_verify(password, verify) == "" 
		and is_allowed_email(email) == "":
		
		return True
	else:
		return False

# Registration - User validations with error messages
def is_allowed_username(username):
	""" Returns appropriate error message for username, or empty if clean"""
	if not is_filled_username(username):
		return "Username is a required field."
	elif not is_regex_username(username):
		return "Username must be 3-20 characters, using letters or numbers."
	elif is_numeric_username(username):
		return "Username must contain at least one letter."
	elif exists_username(username):
		return "Username already in use."
	else: 
		return ""

# Registration - User helper functions
def is_filled_username(username):
	return len(username) > 0

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def is_regex_username(username):
	return USER_RE.match(username)

def is_numeric_username(username):
	return username.isdigit()

def exists_username(username):
	return Users.by_name(username)

# Registration - Password validations with error messages
def is_allowed_password(password):
	""" Returns appropriate error message for password, or empty if clean"""
	if not is_filled_password(password):
		return  "Password is a required field."
	elif not is_regex_password(password):
		return "That is not a valid password."
	else:
		return ""

def is_filled_password(password):
	return len(password) > 0

PASSWORD_RE=re.compile(r"^.{3,20}$")
def is_regex_password(password):
	return PASSWORD_RE.match(password)

# Registration - Password Verification with error message is not a match
def matches_password_verify(password, verify):
	""" Returns appropriate error message for pw verify, or empty if clean"""
	if password and not password == verify:
		return "Your passwords didn't match."
	else:
		return ""

# Registration - Email validation with error message if needed
def is_allowed_email(email):
	""" Returns appropriate error message for email, or empty if clean"""
	if email and not is_regex_email(email):
		return "That is not a valid email."
	else:
		return ""

EMAIL_RE=re.compile(r"^[\S]+@[\S]+.[\S]+$")
def is_regex_email(email):
	return EMAIL_RE.match(email)

# Login logic
class LoginHandler(Handler):
	""" Handles all log in functinality, validations and cookie placement"""
	def get(self):
		self.render("blog/login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		# Confirm valid login
		u = Users.login(username, password)
		if u:
			# Log user in and redirect to root directory
			self.login(u)
			self.redirect('/blog')
		else:
			# Unsuccessful log in, provide error
			self.render("blog/login.html", login_error = "Invalid login"
											# username = username,
											)

class LogoutHandler(Handler):
	""" Wipes user cookie, logging hem out"""
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
