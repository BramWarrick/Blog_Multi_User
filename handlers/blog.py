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

# class RelEnvironment(jinja2.Environment):
# 	"""Override join_path() to enable relative template paths."""
# 	def join_path(self, template, parent):
# 		return os.path.join(os.path.dirname(parent), templates)

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

	def render_string(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_string(template, **kw))

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

class UserBlogHandler(Handler):
	def get(self, username, error=""):
		entries = db.GqlQuery("SELECT * FROM Entries "
							"WHERE user_id = '%s' "
							"ORDER BY created DESC " % Users.by_name(username).key().id()
							)
		self.render("/blog/blog.html", entries = entries, error=error)

class SingleEntryHandler(Handler):
	def get(self, entry_id):
		User = Users.by_hash(self.read_secure_cookie('user_id'))
		if User:
			key = db.Key.from_path('Entries', int(entry_id))
			entry = db.get(key)

			if not entry:
				self.error(404)
				return
			a = Users.by_id(int(entry.user_id))

			self.render("/blog/single_entry.html", entry = entry, author = a.username, user = User)

class BlogNewPostHandler(Handler):
	def render_newpost(self, user, error=""):
		self.render("/blog/new_entry.html", user = user, author = user.username, subject = "", content = "", error = "")

	def get(self):
		User = Users.by_hash(self.read_secure_cookie('user_id'))
		if User:
			self.render_newpost(user = User)
		else:
			self.redirect('/blog/registration')

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		User = Users.by_hash(self.read_secure_cookie('user_id'))
		if User:
			user_id = str(User.key().id())
			if subject and content:
				e = Entries(subject = subject, content = content, user_id = user_id)
				e.put()

				self.redirect('/blog/entry/%s' % str(e.key().id()))
			else:
				error = "Please provide both a subject and some content"
				self.render_newpost(subject = subject,
								content = content,
								error = error)
		else:
			self.redirect('/blog/registration')

class WelcomeHandler(Handler):
	def get(self):
		User = Users.by_hash(self.read_secure_cookie('user_id'))
		if User:
			self.render('/blog/welcome.html', username = User.username)
		else:
			self.redirect('/blog/registration')
		# PageValidation('/blog/welcome.html' ,'/blog/registration' , self.read_secure_cookie('user_id'))

# def PageValidation(page_intended, page_redirect, user_hash = None):
# 	User = Users.by_hash(user_hash)
# 	if User:
# 		self.render(page_intended, username = User.username)
# 	else:
# 		self.redirect(page_redirect)

app = webapp2.WSGIApplication([
								(r'/blog/([a-zA-Z0-9_-]+)/all', UserBlogHandler),
								(r'/blog/entry/([0-9]+)', SingleEntryHandler),
								('/blog/newpost', BlogNewPostHandler),
								('/blog/welcome', WelcomeHandler),
								('/blog',WelcomeHandler),
								],
								debug=True)
