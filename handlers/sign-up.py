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
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

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
    		self.response.write('Welcome, ' + username + "!")
    	else:
	    	self.render("minor_hw/sign-up.html", username_error = check_username(username),
	    								password_error = check_password(password),
	    								verify_error = check_verify(password, verify),
	    								email_error = check_email(email),
	    								username = username,
	    								email=email
	    								)

def check_submission(username, password, verify, email):
	if check_username(username) == "" and check_password(password) == "" and check_verify(password, verify) == "" and check_email(email) == "":
		return True
	else:
		return False

def check_username(username):
	if not exists_username(username):
		return "Username is a required field"
	elif not valid_username(username):
		return "That's not a valid username"
	else: 
		return ""

def check_password(password):
	if not exists_password(password):
		return  "Password is a required field"
	elif not valid_password(password):
		return "That is not a valid password"
	else:
		return ""

def check_verify(password, verify):
	if password and not matches_password(password, verify):
		return "Your passwords didn't match"
	else:
		return ""

def check_email(email):
	if email and not valid_email(email):
		return "That is not a valid email"
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

app = webapp2.WSGIApplication([('/sign-up', SignUpHandler),
								],
								debug=True)
