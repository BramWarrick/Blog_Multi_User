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

from blog_entities import *
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

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
	def get(self, username, post_id):
		# self.response.write('Hello World!')
		self.response.write(username + " " + post_id)

		# key = db.Key.from_path('Entries', int(post_id))
		# entry = db.get(key)

		# if not entry:
		# 	self.error(404)
		# 	return

		# self.render("SingleEntry.html", entry = entry)

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

app = webapp2.WSGIApplication([(r'/blog/([0-9]+)/([0-9]+)', SingleEntry),
								(r'/blog/([0-9]+)', SingleEntry),
								# (r'/blog/([a-f0-9]+)', SingleEntry),
								(r'/blog/([a-zA-Z0-9_-]+)/([0-9]+)', SingleEntry),
								('/blog/newpost', BlogNewPostHandler),
								('/blog',BlogHandler)
								],
								debug=True)
