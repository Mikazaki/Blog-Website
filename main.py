from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask_avatars import Avatars
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import smtplib
import os
from dotenv import load_dotenv
from forms import BlogForm, RegisterForm, LoginForm, CommentForm


app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
Bootstrap5(app)

PASSWORD = os.environ.get("EMAIL_PASSWORD")

ckeditor = CKEditor()
ckeditor.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
db = SQLAlchemy()
db.init_app(app)

avatars = Avatars(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = db.relationship('BlogPost', backref='author')
    comments = db.relationship('Comment', backref='author')


# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403) 
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        
        new_user = User(
            email=email,
            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
            name=form.name.data
        )

        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login',  methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
       
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
        
    return render_template("login.html", logged_in=current_user.is_authenticated, form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, user=current_user, logged_in=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route('/posts/<int:post_id>', methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    requested_post = BlogPost.query.get_or_404(post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():

        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment.data,
            user_id=current_user.id,
            post_id=requested_post.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id)) 
    
    return render_template("post.html", post=requested_post, user=current_user, logged_in=current_user.is_authenticated, form=comment_form)


@app.route('/new-post', methods=["GET", "POST"])
@login_required
def add():
    blog = BlogForm()
    if blog.validate_on_submit():
        new_post = BlogPost(
            title=blog.title.data,
            subtitle=blog.subtitle.data,
            body=blog.body.data,
            img_url=blog.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        
        return redirect(url_for('get_all_posts'))
    return render_template('make-post.html', form = blog, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit(post_id):
    post = BlogPost.query.get_or_404(post_id)
    edit_form = BlogForm(
        title=post.title,
        subtitle=post.subtitle,
        img=post.img_url,
        author=post.author,
        content=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img.data
        post.author = edit_form.author.data
        post.body = edit_form.content.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route('/delete/<int:post_id>')
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get_or_404(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/contact', methods=['POST', 'GET'])
def contact():
    
    if request.method == "POST":
        user = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form['message']
        
        sendemail(user, email, phone, message)
        return render_template("contact.html", sent = True)
    return render_template("contact.html", sent = False)

def sendemail(name, email, phone, message):
    with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=os.environ.get("EMAIL_SEND"), password=PASSWORD)
            connection.sendmail(
                from_addr=os.environ.get("EMAIL_SEND"),
                to_addrs=os.environ.get("EMAIL_RECIEVE"),
                msg=f"Subject: New Message \n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
            )
    

if __name__ == "__main__":
    app.run(debug=False)