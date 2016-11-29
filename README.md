## File format
Instructions
Files and purpose
Web directories
	Legend
	Files
		Locations and purposes
HTML file nesting
Rationale



## Instructions
`git clone https://github.com/BramWarrick/Bram-FSND-Homework.git`
Add Application to Google App Launcher
	Open Google App Launcher
	File > Add Existing Application
	Set "Parent Directory" to directory used for clone
Run locally on localhost:[port Google App Engine indicates]


## Files and purpose

handlers/blog.py............ primary blog functions
handlers/access.py.......... security functions for blog
handlers/blog_entities.py... all GAE kinds and entities logic
app.yaml.................... directory to app mapping
index.yaml.................. indexes for GAE



## Web directories

## Legend
li....logged in users
lo....logged out users
any...any users

## Files
### In blog.py file
/blog......................... user home (li); registration page (lo)
/blog/newentry................ create a new blog entry (li)
/blog/([a-zA-Z0-9_-]+)/all.... other user's blog (any)
/blog/entry/([0-9]+).......... link to specific blog entry (any)
/blog/entry/([0-9]+)/edit..... link to edit entry (li); reg page (lo)
/blog/entry/([0-9]+)/rate..... used for post only (li)
/blog/comment/([0-9]+)/edit... link to edit comment (li); reg page (lo)

# In access.py file
/blog/registration............ registration page (any)
/blog/login................... login page (any)
/blog/logout.................. logout page, redirects to reg page (any)



### HTML file nesting

base....................... base_layout & base_footer
base_footer................ n/a
base_layout................ n/a
comment.................... used by comment_loop (render from function)
comment_add................ base
comment_admin.............. base, comment_add
comment_loop............... comment
entry...................... used in entry_loop (render from function)
entry_admin................ base
entry_loop................. base, entry as loop, comment as loop
entry_single............... base, entry_loop:1 entry, comments:all, comment_add
login...................... base
registration............... base



### Rationale

#### Code separation

The degree of code all cluttering the page was a bit much.
If I wanted to separate security concerns from regular function,
	Kinds/Entities would need to be imported somewhere. So I created
	three files. Entities, Access (security) and Blog (core functionality).
I feel, in the end, readability is improved.


#### Web structure

I wanted links to be as multipurpose as possible, so a user's main page is
	the same for all users (\blog). To any logged in user, /blog is home and
	/blog/newentry is where they create entries.

Following traditional links works for anyone, logged in or not. Examples are
	blog/entry/(numbers) and blog/(alphanumeric)/all, both of which work the
	same regardless if the user is logged in.

In addition to ensuring a user can only access a entry or comment screen if
	logged in, it is re-validated after they submit. This seems reasonable to
	me since it's common for users to create multiple accounts. Logging out on
	one tab should not result in a post hitting the page under the wrong account.

I created some re-directs so that user experience should have few surprises.

Any user messages (outside of those specific to a field), will appear at the top
	of the screen.

HTML templates were used heavily and I tried to have a single place to change logic
	in all the HTML. Once all that was sorted out, changes became easy.