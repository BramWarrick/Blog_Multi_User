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
import time

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

class WelcomeHandler(Handler):
	"""Handles landing page behavior

	If user is logged in, show them their blog entries without a need for URL
	Otherwise they are directed to the registration page
	"""

	def get(self):
		"""Loads landing page based on user's signed in status.

		If user is logged in and an approved user, it takes them directly to 
		their blog with no need for a special URL.

		Otherwise they are sent to the Registration screen.
		"""
		user_curr = Users.by_id(self.read_secure_cookie('user_id'))
		if user_curr:
			entries = Entries.by_user_id(user_curr.key().id())
			author = user_curr
			self.render("/blog/entry_loop.html",
						entries = entries,
						author = author,
						user_curr = user_curr)
		else:
			self.redirect('/blog/registration')

class UserBlogHandler(Handler):
	""" Handles all traffic in the format of /blog/(authorname)

	Displays all blog entries in scolling format sorted in reverse 
		chronological order
	"""
	def get(self, author_name):
		"""Loads blog page of author

	    Displays author's webpage, in scrolling entries format.

	    Args:
	        author_name: plaintext author name retrieved from URL
	    """
		author = Users.by_name(author_name)
		entries = Entries.by_user_id(author.key().id())
		user_curr = Users.by_id(self.read_secure_cookie('user_id'))

		self.render("/blog/entry_loop.html",
					entries = entries,
					author = author,
					user_curr = user_curr)

class EntrySingleHandler(Handler):
	""" Renders single blog entry pages - this includes a comments section

	Displays only one entry at a time.
	Handles all traffic in the format /blog/entry/(entry_id)

	Comments section includes the ability to add a comment, handled by POST
	"""
	def get(self, entry_id):
		"""Loads a single entry's webpage.

		If author is signed in the options to edite or comment are displayed.
		If a registered user is signed in, Like, Unlike, and Comments are 
		displayed.

		If no entry with that id is found, an error is shown to user.

	    Args:
	        entry_id: entry's key id, taken from the URL
	    """

	    # If the enty exists, pull the author and comments for rendering.
		entries, author, comments = Entries.by_id_iterable(entry_id)

		if entries:
			# Get user data for HTML logic; displaying correct user options
			user_curr = Users.by_id(self.read_secure_cookie('user_id'))
			comments = Comments.by_entry_id(entry_id)

			self.render("/blog/entry_single.html", 
						entries = entries, 
						author = author, 
						user_curr = user_curr,
						entry_id = entry_id,
						comments = comments
						)
		else:
			message = "This entry does not exist or has been removed."
			self.redirect("/blog")

	def post(self, entry_id):
		"""Receives a user comment and writes to Comments table.

		Retrieves current user and comment's content. Taken with the entry_id, 
		these are written to the Comments table.

		User is then redirected to entry's web page.

		If no entry with that id is found, an error is shown to user. (Entry 
		deleted since comment was started.)

	    Args:
	        entry_id: entry's key id, taken from the URL
	    """
		content = self.request.get("content")
		user_curr_id = self.read_secure_cookie('user_id')
		entries, author, comments = Entries.by_id_iterable(entry_id)

		if content:
			# Data requirement met
			if entries:
				comment_new_write(entry_id, content, user_curr_id)
				user_curr = Users.by_id(self.read_secure_cookie('user_id'))
				time.sleep(5)

				self.render("/blog/entry_single.html", 
							entries = entries, 
							author = author, 
							user_curr = user_curr,
							entry_id = entry_id,
							comments = comments
							)
		else:
			error = "Please provide a comment"
			user_curr = Users.by_id(self.read_secure_cookie('user_id'))
			comments = Comments.by_entry_id(entry_id)
			self.render("/blog/entry_single.html", 
						entries = Entries.by_id_iterable(entry_id), 
						author = user_curr, 
						user_curr = user_curr,
						entry_id = entry_id,
						comments = comments
						)

def comment_new_write(entry_id, content, user_id):
	"""Writes a new comment to the Comments table.

	    Args:
	        entry_id: entry's key id, taken from the URL
	        content: Comment's content - text
	        user_id: id of the person entering the comment
	    """
	c = Comments(entry_id = entry_id,
				content = content,
				user_id = user_id)
	c.put()


class EntryAdminHandler(Handler):
	""" All blog entry administrative functions are here - additions and edits
	"""
	def render_entry_admin(self, user_curr, subject, content, error=""):
		"""Renders the entry administration page. Values may be passed in.

		author and user entities are used in HTML renders for comparison and
		to fill in visual cues on the page (e.g. Author name is displayed 
		prominently in the upper right.)

	    Args:
	        user_curr: user entity for logged in user who is also the author
	        subject: Subject for the blog entry
	        content: content (or body) for the blog entry
	        error: may be used in the event user hasn't met all requirements
	        	for a successful write of the new entry.
	    """
		self.render("/blog/entry_admin.html", 
					author = user_curr,
					user_curr = user_curr,
					subject = subject,
					content = content,
					error = error
					)

	def get(self, entry_id = None):
		"""Retrieves the correct page.

		author and user entities are used in HTML renders for comparison and
		to fill in visual cues on the page (e.g. Author name is displayed 
		prominently in the upper right.)

	    Args:
	    	entry_id: present if entry is being modified.
	    """
		user_curr_id = self.read_secure_cookie('user_id')
		user_curr = Users.by_id(user_curr_id)

		entry = Entries.by_entry_id_if_exists(entry_id)

		if not user_curr_id:
			# They are in an area limited to registered users; redirect
			self.redirect('/blog/registration')
		elif not entry_id:
			# No entry exist yet, render standard page with values
			self.render_entry_admin(user_curr = user_curr,
									subject = "",
									content = ""
									)
		elif entry:
			if entry.user_id == user_curr_id:
				# Entry exists, load page with values filled in
				self.render_entry_admin(user_curr = user_curr,
										subject = entry.subject,
										content = entry.content
										)
			else:
				# They are not the author; redirect
				self.redirect('/blog/registration')
		else:
			message = "This entry does not exist or has been removed."
			self.redirect("/blog")

	def post(self, entry_id = None):
		"""Sends entry data for write to Entries table

		If data criteria are not met, reload page with instructive error.

		If no entry exists:
			and criteria are met, a blog entry is added to the Entries table.
		If entry exists:
			validate user logged in is original author
			and criteria are met, blog entry is updated.

	    Args:
	    	entry_id: present if entry is being modified.
	    """
		subject = self.request.get("subject")
		content = self.request.get("content")
		user_curr_id = self.read_secure_cookie('user_id')
		user_curr = Users.by_id(user_curr_id)

		action = self.request.get("submit")

		if action == "delete":
			entry = Entries.by_entry_id_if_exists(entry_id)
			if entry:
				# Entry exists, is current user the author
				if entry.user_id == user_curr_id:
					entry.delete()
					message = "Entry deleted!"
					time.sleep(5)
					self.redirect("/blog")
				else:
					# Current user is not author
					# If users create more than one account, this is needed
					message = "Action not allowed"
					self.redirect('/blog/registration')
			else:
				message = "Entry does not exist or has been deleted"
				self.redirect("/blog")
		else:	# Submit pressed
		 	if subject and content:
				entry = Entries.by_entry_id_if_exists(entry_id)
				if entry:
					# Entry exists, is current user the author?
					if entry.user_id == user_curr_id:
						authorized_entry_edit(entry, subject, content)
						time.sleep(5)
						self.redirect("/blog/entry/%s" % entry.key().id())
					else:
						# Current user is not author
						# If users create more than one account, this is needed
						self.redirect("/blog/registration")
				else:
					# No entry exists, write new one
					entry_id = entry_new_write(subject, content, user_curr_id)
					time.sleep(5)
					self.redirect("/blog/entry/%s" % entry_id)
			else:
				# Data requirements are not met
				error = "Please provide both a subject and some content"
				self.render_entry_admin(user_curr = user_curr,
										subject = subject,
										content = content,
										error = error)

def authorized_entry_edit(entry, subject, content):
	"""Writes new blog entry to Entries table.

	Entry is the entity to be modified, values are updated.

    Args:
    	entry: the entry being modified is passed in
    	subject: author's modified subject
    	content: author's modified blog content (body)
    """
	entry.subject= subject
	entry.content = content
	entry.put()

def entry_new_write(subject, content, author_id):
	"""Writes new blog entry to Entries table.

	Entry is the entity to be modified, values are updated.

    Args:
    	subject: author's modified subject
    	content: author's modified blog content (body)
    	author_id: user_id for the current user; the author
    """
	e = Entries.new_entry(author_id, subject, content)
	e.put()
	return str(e.key().id())

class EntryRateHandler(Handler):
	""" Handles all logic for user liking and unliking a blog post.
	"""
	def post(self, entry_id):
		"""Modifies liked value for user/entry

		Writes or deletes a user's like to the EntryLikes table
		Redirect's to the blog entry's main page, which will load with comment
			box if user is signed in; allowing easy access to feedback.

	    Args:
	    	entry_id: entry_id of the entry being liked or unliked
	    """
		user_curr = self.read_secure_cookie('user_id')
		rate = self.request.get("like")

		if user_curr:
			if rate == "like":
				# User liked the entry
				entry_like(entry_id, user_curr)
			else:
				# User unliked the blog entry
				# Hotlinks to the page, for vote cheating are punished
				entry_unlike(entry_id, user_curr)

		time.sleep(5)
		self.redirect('/blog/entry/%s' % entry_id)

# Helper functions for Rating Blog Entries
def entry_like(entry_id, user_curr_id):
	"""Adds an entry to the EntryLikes table, if user is not liking a
		previously liked blog entry.

	Validates user hasn't already voted.
	If no vote exists, writes a new like to the EntryLikes table.

    Args:
    	entry_id: entry_id of the entry being liked
    	user_curr_id: user_id of the logged in user
    """
	entry_like = EntryLikes.by_entry_user_id(entry_id, user_curr_id)
	message = ""
	if entry_like:
		message = "You have previously liked this entry."
	elif Entries.by_id(entry_id).user_id == user_curr_id:
		message = "It is pretty spectaular, isn't it?"
		" Unfortunately, you cannot like your own entry."
	else:
		e = EntryLikes(entry_id = entry_id,
						user_id = user_curr_id)
		e.put()
	return message

def entry_unlike(entry_id, user_id):
	entry_like = EntryLikes.by_entry_user_id(entry_id, user_id)
	if entry_like:
		entry_like.delete()

class CommentEditHandler(Handler):
	""" All blog entry administrative functions are here - additions and edits
	"""
	def render_comment_admin(self, user_curr, comment_id, content, error=""):
		"""Renders the entry administration page. Values may be passed in.

		author and user entities are used in HTML renders for comparison and
		to fill in visual cues on the page (e.g. Author name is displayed 
		prominently in the upper right.)

	    Args:
	        user_curr: user entity for logged in user who is also the author
	        subject: Subject for the blog entry
	        content: content (or body) for the blog entry
	        error: may be used in the event user hasn't met all requirements
	        	for a successful write of the new entry.
	    """
		self.render("/blog/comment_admin.html", 
					author = user_curr,
					user_curr = user_curr,
					comment_id = comment_id,
					content = content,
					error = error
					)

	def get(self, comment_id = None):
		"""Retrieves the correct page.

		author and user entities are used in HTML renders for comparison and
		to fill in visual cues on the page (e.g. Author name is displayed 
		prominently in the upper right.)

	    Args:
	    	entry_id: present if entry is being modified.
	    """
		user_curr_id = self.read_secure_cookie('user_id')
		user_curr = Users.by_id(user_curr_id)

		comment = Comments.by_id(comment_id)

		if not user_curr_id:
			# They are in an area limited to registered users; redirect
			self.redirect('/blog/registration')
		elif comment:
			if comment.user_id == user_curr_id:
				# Comment exists, load page with values filled in
				self.render("/blog/comment_admin.html", 
									author = user_curr,
									user_curr = user_curr,
									comment_id = comment_id,
									content = comment.content
									)
			else:
				# They are not the author; redirect
				self.redirect('/blog/registration')
		else:
			message = "This comment does not exist or has been removed."
			self.redirect("/blog")

	def post(self, comment_id = None):
		"""Sends entry data for write to Entries table

		If data criteria are not met, reload page with instructive error.

		If no entry exists:
			and criteria are met, a blog entry is added to the Entries table.
		If entry exists:
			validate user logged in is original author
			and criteria are met, blog entry is updated.

	    Args:
	    	entry_id: present if entry is being modified.
	    """
		content = self.request.get("content")
		user_curr_id = self.read_secure_cookie('user_id')
		user_curr = Users.by_id(user_curr_id)

		action = self.request.get("submit")

		if action == "delete":
			comment = Comments.by_id(comment_id)
			if comment:
				# Entry exists, is current user the author
				if comment.user_id == user_curr_id:
					comment.delete()
					time.sleep(5)
					message = "Comment deleted!"
					self.redirect("/blog")
				else:
					# Current user is not author
					# If users create more than one account, this is needed
					message = "Action not allowed"
					self.redirect('/blog/registration')
			else:
				message = "Entry does not exist or has been deleted"
				self.redirect("/blog")
		else:	# Submit pressed
			if content:
				# Data requirement met
				comment = Comments.by_id(comment_id)
				if comment:
					# Comment exists, is current user the author
					if comment.user_id == user_curr_id:
						authorized_comment_edit(comment, content)
						time.sleep(5)
						self.redirect('/blog/entry/%s' % comment.entry_id)
					else:
						# Current user is not author
						# If users create more than one account, this is needed
						self.redirect('/blog/registration')
				else:
					message = "That comment does not exist or has been deleted."
					self.redirect("/blog")
			else:
				# Data requirements are not met
				error = "Please provide some content"
				self.render_comment_admin(user_curr = user_curr,
										content = content,
										error = error)


def authorized_comment_edit(comment, content):
	"""Writes new blog entry to Entries table.

	Entry is the entity to be modified, values are updated.

    Args:
    	entry: the entry being modified is passed in
    	subject: author's modified subject
    	content: author's modified blog content (body)
    """
	comment.content = content
	comment.put()

app = webapp2.WSGIApplication([
								(r'/blog/([a-zA-Z0-9_-]+)/all', UserBlogHandler),
								(r'/blog/entry/([0-9]+)', EntrySingleHandler),
								('/blog/newentry', EntryAdminHandler),
								(r'/blog/entry/([0-9]+)/edit', EntryAdminHandler),
								(r'/blog/entry/([0-9]+)/rate', EntryRateHandler),
								(r'/blog/comment/([0-9]+)/edit', CommentEditHandler),
								('/blog/welcome', WelcomeHandler),
								('/blog',WelcomeHandler),
								],
								debug=True)
