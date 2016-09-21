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
	def get(self, user_id, error=""):
		entries = db.GqlQuery("SELECT * FROM Entries "
							"WHERE user_id = '%s' "
							"ORDER BY created DESC "
							% Users.by_id(int(user_id)).key().id()
							)
		author = Users.by_id(int(user_id))
		user = Users.by_hash(self.read_secure_cookie('user_id'))
		if user:
			self.render("/blog/blog.html",
						entries = entries,
						author = author,
						user = user)
		else:
			self.render("/blog/blog.html",
						entries = entries,
						author = author)

class EntrySingleHandler(Handler):
	def get(self, entry_id):

		key = db.Key.from_path('Entries', int(entry_id))
		entry = db.get(key)

		if entry:
			# self.write(entry.user_id)
			author = Users.by_id(int(entry.user_id))
			user = Users.by_hash(self.read_secure_cookie('user_id'))
			if user:
				self.render("/blog/single_entry.html", 
							entry = entry, 
							author = author, 
							user = user,
							entry_id = entry_id
							)
			else:
				self.render("/blog/single_entry.html", 
							entry = entry, 
							author = author,
							entry_id = entry_id
							)
		else:
			self.write("This entry does not exist or has been removed.")

class EntryNewHandler(Handler):
	def render_entry_admin(self, user, error=""):
		user = Users.by_hash(self.read_secure_cookie('user_id'))
		if user:
			author = user
			self.render("/blog/new_entry.html", 
						author = author,
						user = user,
						subject = "",
						content = ""
						)
		else:
			self.redirect('/blog/registration')

	def get(self):
		user = Users.by_hash(self.read_secure_cookie('user_id'))
		if user:
			self.render_entry_admin(user = user)
		else:
			self.redirect('/blog/registration')

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		user = Users.by_hash(self.read_secure_cookie('user_id'))
		if user:
			user_id = str(user.key().id())
			if subject and content:
				e = Entries(subject = subject,
							content = content,
							user_id = user_id)
				e.put()

				self.redirect('/blog/entry/%s' % str(e.key().id()))
			else:
				error = "Please provide both a subject and some content"
				self.render_entry_admin(subject = subject,
									content = content,
									error = error)
		else:
			self.redirect('/blog/registration')

class EntryReviseHandler(Handler):
	def render_entry_admin(self, user, entry, error=""):
		self.render("/blog/new_entry.html", 
					author = user,
					user = user,
					subject = entry.subject,
					content = entry.content
					)

	def get(self, entry_id):
		key = db.Key.from_path('Entries', int(entry_id))
		entry = db.get(key)

		if entry:
			if entry.user_id == self.read_secure_cookie('user_id'):
				author = Users.by_id(int(entry.user_id))
				if author:
					user = author
					self.render_entry_admin(user = user, entry = entry)
				else:
					self.write("The author of this entry cannot be found.")
			else:
				self.redirect('/blog/registration')
		else:
			self.write("This entry does not exist or has been removed.")


	def post(self, entry_id):
		key = db.Key.from_path('Entries', int(entry_id))
		entry = db.get(key)

		if entry:
			if entry.user_id == self.read_secure_cookie('user_id'):
				author = Users.by_id(int(entry.user_id))
				if author:
					user = author

					subject = self.request.get("subject")
					content = self.request.get("content")
					if subject and content:

						entry.subject= subject
						entry.content = content
						entry.put()

						self.redirect('/blog/entry/%s' % entry_id)
					else:
						error = "Please provide both a subject and some content"
						self.render_entry_admin(subject = subject,
									content = content,
									error = error)
		else:
			self.redirect('/blog/registration')

class EntryRateHandler(Handler):
	def post(self, entry_id):
		user_id = self.read_secure_cookie('user_id')
		rate = self.request.get("like")

		if user_id:
			if rate == "like":
				q = EntryLikes.all()
				q.filter("entry_id =", entry_id)
				q.filter("user_id =", user_id)
				if q.fetch(9) != []:
					self.write("Stub - the user has previously liked this entry. Make an error?")
				else:
					e = EntryLikes(entry_id = entry_id,
									user_id = user_id)
					e.put()
			else:
				self.write("deleting like<br>")
				self.write(entry_id)
				entry = Entries.by_id(int(entry_id))
				self.write(entry)
				# employee = db.get(employee_k)

				# entry.delete()
		# self.write(entry_id)

class EntryLikeHandler(Handler):
	def get(self, entry_id):
		user_id = self.read_secure_cookie('user_id')
		# if user_id:
			# q = EntryLikes.all()
			# q.filter("entry_id=", entry_id)
			# q.filter("user_id=", user.key().id())
			# if q.entry_id:
			# 	self.write("Stub - the user has previously liked this entry. Make an error?")
			# else:
		e = EntryLikes(entry_id = entry_id,
						user_id = user_id)
		e.put()
		# self.write(entry_id)

		# key = db.Key.from_path('Entries', int(entry_id))
		# entry = db.get(key)

		# user = Users.by_hash(self.read_secure_cookie('user_id'))
		# if user:
		# 	self.render('/blog/welcome.html',
		# 				username = user.username)

		# if entry:
		# 	if int(entry.user_id) == check_secure_val(self.read_secure_cookie('user_id')):
		# 		author = Users.by_id(int(entry.user_id))
		# 		if author:
		# 			user = author

		# 			subject = self.request.get("subject")
		# 			content = self.request.get("content")
		# 			if subject and content:
		# 				with client.transaction():

		# 					entry['subject'] = subject
		# 					entry['content'] = content

		# 					entry.put()

		# 				self.redirect('/blog/entry/%s' % entry_id)
		# 			else:
		# 				error = "Please provide both a subject and some content"
		# 				self.render_entry_admin(subject = subject,
		# 							content = content,
		# 							error = error)
		# else:
			# self.redirect('/blog/registration')

class WelcomeHandler(Handler):
	def get(self):
		user = Users.by_hash(self.read_secure_cookie('user_id'))
		if user:
			self.render('/blog/welcome.html',
						username = user.username)
		else:
			self.redirect('/blog/registration')

app = webapp2.WSGIApplication([
								(r'/blog/([a-zA-Z0-9_-]+)/all', UserBlogHandler),
								(r'/blog/entry/([0-9]+)', EntrySingleHandler),
								('/blog/newentry', EntryNewHandler),
								(r'/blog/entry/([0-9]+)/edit', EntryReviseHandler),
								(r'/blog/entry/([0-9]+)/rate', EntryRateHandler),
								(r'/blog/entry/([0-9]+)/like', EntryLikeHandler),
								('/blog/welcome', WelcomeHandler),
								('/blog',WelcomeHandler),
								],
								debug=True)
