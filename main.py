import os

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    current_user,
    logout_user,
)
from forms import CreatePostForm, AddNewUsers, LoginForm, CommentForm
from functools import wraps
from dotenv import load_dotenv
from flask_gravatar import Gravatar

load_dotenv()


def admin_only(function):
    @wraps(function)
    def admin_decorator(*args):
        if current_user.id != 1:
            abort(404, description="Resource not found")
        else:
            return function(*args)

    return admin_decorator


app = Flask(__name__)
# app.config["SECRET_KEY"] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
app.config["SECRET_KEY"] = os.environ.get("SECRET")
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager(app=app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


## CONNECT TO DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


## CONFIGURE TABLES


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False, unique=True)
    posts = relationship("BlogPost", back_populates="author")
    comment = relationship("Comments", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("Users", back_populates="comment")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


@app.route("/")
def get_all_posts():
    posts = BlogPost.query.all()
    print(current_user.is_authenticated)
    return render_template(
        "index.html", all_posts=posts, logged_in=current_user.is_authenticated
    )


@app.route("/register", methods=["POST", "GET"])
def register():
    register_form = AddNewUsers()
    if register_form.validate_on_submit():
        password_user = request.form.get("password")
        password_hashing = generate_password_hash(
            password_user, method="pbkdf2:sha256", salt_length=8
        )
        new_user = Users(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=password_hashing,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)


@app.route("/login", methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    if request.method == "POST":
        email_to_validate = request.form.get("email")
        object_to_validate = db.session.execute(
            db.select(Users).where(Users.email == email_to_validate)
        ).scalar()
        password_fetch = object_to_validate.password
        if login_form.validate_on_submit():
            if check_password_hash(password_fetch, request.form.get("password")):
                print("match")
                login_user(object_to_validate)
                return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    return render_template("post.html", post=requested_post, comment_form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=True)
