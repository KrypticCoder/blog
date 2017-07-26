import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'supersecretkeythatshouldbekeptindifferentfile'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

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
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):

    def get(self):
        self.write('Hello, Udacity!')


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Comment(db.Model):
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    comment = db.TextProperty(required=True)

    def username(self):
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class Likes(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def username(self):
        user = User.by_id(self.user_id)
        return user.name


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    num_likes = db.IntegerProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def username(self):
        user = User.by_id(self.user_id)
        return user.name


class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        deleted_post_id = self.request.get('deleted_post_id')
        error = self.request.get('error')
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id,
                    error=error)

    def post(self):
        like_post_id = self.request.get('like_post_id')
        if self.user:
            key = db.Key.from_path(
                'Post', int(like_post_id), parent=blog_key())
            post = db.get(key)
            # Current user should not match the post author
            if self.user.key().id() == post.user_id:
                self.redirect('/?error=You cannot like your own post')
            else:
                # Find all records with matching post_id and user_id
                likes = db.GqlQuery("select * from Likes where post_id = " + 
                                    like_post_id + "and user_id = " + 
                                    str(self.user.key().id()))

                # If the user has not liked the post yet, 
                # there won't be a record
                if likes.count() == 0:
                    like = Likes(parent=blog_key(), user_id=self.user.key().id(),
                                 post_id=int(like_post_id))
                    like.put()
                    post.num_likes += 1
                    post.put()
                    # Redirect to postpage to update the like counter for that
                    # post
                    self.redirect('/blog/' + str(post.key().id()) + '?like=1')
                else:
                    self.redirect('/?error=You have already liked this post')
        else:
            # user needs to sign in
            self.redirect('/login?error=You need to log in to like a post')


class PostPage(BlogHandler):

    def get(self, post_id):
        # If a post was liked , then we know it was from
        # the BlogFront class and redirect back to it
        #
        # A way to update a post method without having to refresh the page
        like = self.request.get('like')
        if like:
            self.redirect('/')

        error = self.request.get("error")
        deleted_comment_id = self.request.get("deleted_comment_id")

        comments = db.GqlQuery(
            "select * from Comment where post_id = " + post_id + "order by created desc")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments,
                    error=error, deleted_comment_id=deleted_comment_id)

    def post(self, post_id):

        if self.user:
            comment = self.request.get('comment')
            if comment:
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id), comment=comment)
                c.put()
                self.redirect('/blog/' + post_id)
            else:
                c = None
                self.redirect('/blog/' + post_id + '?error=Missing comment content')
        else:
            # user needs to sign in
            self.redirect(
                '/login?error=You need to log in to comment on a post')


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):

        cancel = self.request.get("cancel")
        if not self.user or cancel:
            self.redirect('/')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, user_id=self.user.key().id(),
                     num_likes=0)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class DeletePost(BlogHandler):

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # user can delete if they are the author of that post
            if self.user.key().id() == post.user_id:
                post.delete()
                self.redirect('/?deleted_post_id=' + post_id)
            else:
                self.redirect('/?error=You are not the ' +
                              'author of this post')
        else:
            # user needs to sign in
            self.redirect('login?error=You need to log in to delete your post')


class EditPost(BlogHandler):

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if self.user.key().id() == post.user_id:
                self.render('editpost.html', subject=post.subject,
                            content=post.content)
            else:
                self.redirect('/?error=You are not the ' +
                              'author of this post')
        else:
            # user needs to sign in
            self.redirect('login?error=You need to log in to delete your post')

    def post(self, post_id):
        # If user has clicked 'cancel', go back to blog
        cancel = self.request.get("cancel")
        if not self.user or cancel:
            self.redirect('/')
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        # Make sure both subject and content are available
        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "editpost.html", subject=subject, content=content, error=error)


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            comment = db.get(key)
            if comment.user_id == self.user.key().id():
                comment.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/login?error=You need to be logged in to " +
                          "delete your comment!!")


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to to edit this comment")

        else:
            self.redirect("/login?error=You need to be logged in " +
                          "edit your comment")

    def post(self, post_id, comment_id):
        # If user has clicked 'cancel', go back to blog
        cancel = self.request.get("cancel")
        if (not self.user) or cancel:
            self.redirect('/blog/' + str(post_id))
            return

        comment = self.request.get('comment')
        subject = self.request.get('subject')
        content = self.request.get('content')

        if comment:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/' + str(post_id))
        else:
            self.render("editpost.html", subject=subject, comment=comment,
                        error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        login = self.request.get('login')
        if login:
            self.redirect('/login')
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):

    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):

    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        signup = self.request.get('signup')
        if signup:
            self.redirect('/signup')

        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(BlogHandler):

    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
