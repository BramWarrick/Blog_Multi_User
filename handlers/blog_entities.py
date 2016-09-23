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
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	signature = db.StringProperty()   # Under consideration
	email = db.EmailProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent = user_key())

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('username =', name).get()
		return u

	@classmethod
	def by_hash(cls, hash):
		if hash:
			uid = hash.split('|')[0]
			uid = int(uid)
			return cls.get_by_id(uid, parent = user_key())

	@classmethod
	def register(cls, name, password, email):
		pw_hash = create_password_hash(name, password)
		if email:
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
		u = cls.by_name(name)
		if u and is_valid_login(name, pw, u.password_hash):
			return u


# Users class helper functions
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

class Entries(db.Model):
	user_id = db.StringProperty(required = True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_id(cls, entry_id):
		return cls.get_by_id(entry_id, parent = None)

	@classmethod
	def by_id_fetch(cls, entry_id):
		key = db.Key.from_path('Entries', int(entry_id))
		q = cls.all().filter('__key__ =', key).fetch(1)
		return q

	def render(self, user=None, author=None):
		self._render_text = self.content.replace('\n', '<br>')
		self._entry_id = self.key().id()
		self.user = user
		self.author = author
		return render_str("/blog/entry.html", entry = self)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class EntryLikes(db.Model):
	entry_id = db.StringProperty(required = True)
	user_id = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_entry_user_id(cls, entry_id, user_id):
		q = db.GqlQuery("SELECT * FROM EntryLikes "
						"WHERE entry_id = '%s' "
						"AND user_id = '%s'"
						% (entry_id, user_id))
		return q.get()

class Comments(db.Model):
	entry_id = db.TextProperty(required = True)
	user_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_entry_id(cls, entry_id):
		q = cls.all().filter('entry_id =', entry_id).get()
		return q

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		self._comment_id = self.key().id()
		return render_str("/blog/comment.html", entry = self)