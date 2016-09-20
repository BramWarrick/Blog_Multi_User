import random
import hashlib
import hmac

from google.appengine.ext import db

# "Tables" - In GAE, these are Classes
def user_key(group = 'default'):
	return db.Key.from_path('users', group)

class Users(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	# tagline = db.StringProperty()   Under consideration
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
	def register(cls, name, password, email):
		pw_hash = createPasswordHash(name, password)
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
		if u and isValidLogin(name, pw, u.password_hash):
			return u


# Users class helper functions
def isValidLogin(name, pw, h):
	salt = h.split('|')[1]
	if h == createPasswordHash(name, pw, salt):
		return True
	else:
		return False

def createPasswordHash(name, pw, salt=None):
	if not salt:
		salt = createSalt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h, salt)

def createSalt():
	return ''.join(random.choice(string.ascii_letters) for x in range(5))

class Entries(db.Model):
	user_id = db.StringProperty(required = True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("entry.html", p = self)

class Comments(db.Model):
	entry_id = db.TextProperty(required = True)
	comment_parent_id = db.TextProperty(required = True)
	user_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
