#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	 http://www.apache.org/licenses/LICENSE-2.0
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

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

# class BoilerPlateHandler(Handler):
#	 def get(self):
#		 self.response.write('Hello world!')

class MainHandler(Handler):
	def get(self):
		self.render("index.html")


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
								],
								debug=True)

def main():
    util.run_wsgi_app(application)

# Reference Material -> Will strip for parts later
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