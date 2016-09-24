import os
import jinja2
import random
import hashlib
import hmac
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

# "Tables" - In GAE, these are Classes
def user_key(group = 'default'):
	return db.Key.from_path('users', group)

class Users(db.Model):
	""" Stores all users of the blog """
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	signature = db.StringProperty()   # Under consideration
	email = db.EmailProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_id(cls, uid):
		""" Returns user entity from user_id

		Arg:
			uid: user_id"""
		if type(uid) is not int and uid:
			uid = int(uid)
			return cls.get_by_id(uid, parent = user_key())

	@classmethod
	def by_name(cls, name):
		""" Returns user entity based on username """
		u = cls.all().filter('username =', name).get()
		return u

	@classmethod
	def register(cls, name, password, email):
		""" Returns the prepared write to the table, requires put()"""
		pw_hash = create_password_hash(name, password)
		if email:
			# GAE would not allow a write of an empty email, 
			# 	this handles that error
			return cls(parent = user_key(),
						username = name,
						password_hash = pw_hash,
						email = email)
		else:
			return cls(parent = user_key(),
						username = name,
						password_hash = pw_hash)				

	@classmethod
	def login(cls, name, pw):
		""" Returns user entity, if exists. Based on username"""
		u = cls.by_name(name)
		if u and is_valid_login(name, pw, u.password_hash):
			return u


##### Users class helper functions - obvious and from homework

def is_valid_login(name, pw, h):
	salt = h.split('|')[1]
	if h == create_password_hash(name, pw, salt):
		return True
	else:
		return False

def create_password_hash(name, pw, salt=None):
	if not salt:
		salt = create_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h, salt)

def create_salt():
	return ''.join(random.choice(string.ascii_letters) for x in range(5))

def entry_key(group = 'default'):
	"""Returns the parent key for entries"""
	return db.Key.from_path('entries', group)

class Entries(db.Model):
	""" Contains all blog entries """
	user_id = db.StringProperty(required = True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def new_entry(cls, user_id, subject, content):
		"""I'd worked in the entry_key logic in the hope it would
		speed responsiveness. I'm doing a lot of refreshing to see that the
		data wrote. Alas...  it does not seem to help."""
		return cls(parent = entry_key(),
						user_id = user_id,
						subject = subject,
						content = content)

	@classmethod
	def by_id(cls, entry_id):
		""" Returns entry entity based on entry_id"""
		if type(entry_id) is not int:
			entry_id = int(entry_id)
		return cls.get_by_id(entry_id, parent = entry_key())

	@classmethod
	def by_id_iterable(cls, entry_id):
		""" Returns entry entity, singular, in iterable form


		Needed for consistency in entry_loop.html
			between full lists and single entries.
		Allows looping and can then pull in the _render values

		Arg:
			entry_id: id for the desired single entry

		Returns:
			entry: a single entry entity
			author: user entity for the author of the entry
			comments: all comments for this blog entry"""
		key = db.Key.from_path('Entries', int(entry_id), parent=entry_key())
		q = cls.all().filter('__key__ =', key).fetch(1)

		if q:
			user_id = Entries.by_id(entry_id).user_id
			author = Users.by_id(user_id)
		else:
			user_id = ""
			author = ""

		comments = Comments.by_entry_id(entry_id)
		return q, author, comments

	@classmethod
	def by_user_id(cls, user_id):
		""" Returns most recent 99 entries for user_id """
		if type(user_id) is not str:
			user_id = str(user_id)
		e = cls.all().filter('user_id =', user_id).order('user_id').order('-created').fetch(99)
		return e

	@classmethod
	def by_entry_id_if_exists(cls, entry_id = None):
		""" Returns entry if both entry_id and entry exist

		This greatly simplified readability in the blog.py file.
		Referenced in more complicated conditionals

		Arg:
			entry_id: intended entry id, may not exist
		Returns:
			entry if entry_id exists and is in Entries table"""
		if entry_id:
			return Entries.by_id(int(entry_id))


	def render(self, user_curr=None, author=None):
		""" Performs replacements and allows values to be passed
		into /blog/entry.html file at runtime

		Args:
			user: user entity for logged in user
			author: user entity for the author of entry(s)"""
		self._render_text = self.content.replace('\n', '<br>')
		self._entry_id = self.key().id()
		self.user_curr = user_curr
		self.author = author
		self._likes = EntryLikes.likes_by_entry_id(self.key().id())
		return render_str("/blog/entry.html", entry = self)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class EntryLikes(db.Model):
	""" Tracks all user user likes of blog entries"""
	entry_id = db.StringProperty(required = True)
	user_id = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_entry_user_id(cls, entry_id, user_curr_id):
		""" Returns EntryLike entity based on combination
			of entry_id and user_id.

		Args:
			entry_id: id for the entry in question
			user_curr_id: current user
		Returns:
			EntryLike entity, if exists"""
		q = db.GqlQuery("SELECT * FROM EntryLikes "
						"WHERE entry_id = '%s' "
						"AND user_id = '%s'"
						% (entry_id, user_curr_id))
		return q.get()

	@classmethod
	def likes_by_entry_id(cls, entry_id):
		if type(entry_id) is not str:
			entry_id = str(entry_id)
		count = cls.all(keys_only=True).filter('entry_id =', entry_id).count()
		return count

class Comments(db.Model):
	""" Contains all user comments, linked to a parent blog entry"""
	entry_id = db.StringProperty(required = True)
	user_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_id(cls, comment_id):
		""" Returns entry entity based on entry_id"""
		if type(comment_id) is not int:
			comment_id = int(comment_id)
		return cls.get_by_id(comment_id)

	@classmethod
	def by_entry_id(cls, entry_id):
		""" Returns all comments for entry_id"""
		if type(entry_id) is not str:
			entry_id = str(entry_id)
		q = cls.all().filter('entry_id =', entry_id).order('created').fetch(99)
		return q

	def render(self):
		""" Performs replacements of strings in /blog/comment.html 
			file at runtime. Also makes comment_id available to html.

		Args:
			user: user entity for logged in user
			author: user entity for the author of entry(s)"""
		self._render_text = self.content.replace('\n', '<br>')
		self._comment_id = self.key().id()
		return render_str("/blog/comment.html", comment = self)