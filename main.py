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

template_dir = os.path.join(os.path.dirname(__file__),'templates')

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

def hash_str(s):
	return hmac.new('89frheojco;d94&', s, hashlib.sha1).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

# class BoilerPlateHandler(Handler):
#     def get(self):
#         self.response.write('Hello world!')

class MainHandler(Handler):
	def get(self):
		self.render("index.html")
		# self.response.headers['Content-Type'] = 'text/plain'
		# visits = 0
		# visit_cookie_str = self.request.cookies.get('visits')
		# if visit_cookie_str:
		# 	cookie_val = check_secure_val(visit_cookie_str)
		# 	if cookie_val:
		# 		visits = int(cookie_val)
		# visits += 1
		# new_cookie_val = make_secure_val(str(visits))

		# self.response.headers.add_header('Set-Cookie','visits=%s' % new_cookie_val)

		# if visits > 10000:
		# 	self.write("You are the best ever!")
		# else:
		# 	self.write("You've been here %s times!" % visits)

class Rot13Handler(Handler):
	def get(self):
		self.render("minor_hw/rot13.html")

	def post(self):
		output = self.request.get("text")
		output = rot13(output)
		self.render("minor_hw/rot13.html", rot13 = output)

# ROT13 logic
def rot13(string):
	output = ""
	for index in range (0, len(string)):
		output += new_rot_value(string[index])
	return output

def new_rot_value(string):
	if string.isalpha() or string.isdigit():
		return rotOffset(string)
	else:
		return string

def rotOffset(string):
	if string.isdigit():
		return getRotValue(string, 48, 57, 5)
	elif string.islower():
		return getRotValue(string, 97, 122, 13)
	else:
		return getRotValue(string, 65, 90, 13)
	return

def getRotValue(string, min_ord, max_ord, increment):
	val = ord(string) + increment
	offset = max_ord - min_ord + 1
	if val > max_ord:
		val -= offset
	return chr(val)

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
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
	return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

# Ascii related logic
class AsciiChanHandler(Handler):
	def render_ascii(self, title="", art="", error=""):
		arts = db.GqlQuery("SELECT * FROM Art "
							"ORDER BY created DESC ")
		self.render("minor_hw/asciichan.html", title=title, art=art, error=error, arts = arts)

	def get(self):
		# self.response.write('Hello world!')
		self.render_ascii()

	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art:
			a = Art(title = title, art = art)
			a.put()

			self.redirect("/asciichan")
		else:
			error = "We need both a title and some artwork!"
			self.render_ascii(title = title,
								art = art,
								error = error)

class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

# Blog related logic
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(Handler):
	def render_blog(self, blog="", error=""):
		entries = db.GqlQuery("SELECT * FROM Entries "
							 "ORDER BY created DESC "
							)
		self.render("/blog/blog.html", entries = entries, error=error)

	def get(self):
		self.render_blog()

class SingleEntry(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Entries', int(post_id))
        entry = db.get(key)

        if not entry:
            self.error(404)
            return

        self.render("SingleEntry.html", entry = entry)

class BlogNewPostHandler(Handler):
	def render_newpost(self, blog="", error=""):
		self.render("/blog/new_entry.html", subject = "", content = "", error = "")

	def get(self):
		# self.response.write('Hello world!')
		self.render_newpost()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			e = Entries(subject = subject, content = content)
			e.put()

			self.redirect('/blog/%s' % str(e.key().id()))
		else:
			error = "Please provide both a subject and some content"
			self.render_newpost(subject = subject,
							content = content,
							error = error)

class Entries(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("/blog/entry.html", entry = self)

app = webapp2.WSGIApplication([('/', MainHandler),
								('/rot13', Rot13Handler),
								('/sign-up', SignUpHandler),
								('/asciichan', AsciiChanHandler),
								('/blog',BlogHandler),
								('/blog/([0-9]+)', SingleEntry),
								('/blog/newpost', BlogNewPostHandler)
								],
								debug=True)
