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

app = webapp2.WSGIApplication([('/', Rot13Handler),
								('/rot13', Rot13Handler),
								],
								debug=True)
