import datetime
from functools import wraps

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///home/vaibhav/PycharmProjects/blog3-api-flask/blog.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    blog = db.Column(db.String(500))
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'blog.id', ondelete="CASCADE"), nullable=False)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        print(request.headers)

        if 'X-Access-Token' in request.headers:
            token = request.headers['x-access-token']
            print('token :', token)

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print("data:", data)
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            print("current_user", current_user.username)
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    print("all users")
    print("current  :", current_user)
    if not current_user.admin:
        return jsonify({'message': 'User is Not Admin !! Cannot perform that function!'})

    users = User.query.all()
    print(users)

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'User is Not Admin !! Cannot perform that function!'})

    data = request.get_json()
    print(data)

    hashed_password = generate_password_hash(data['password'], method='sha256')
    print(hashed_password)
    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, admin=False)
    print(new_user)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'User is Not Admin !! Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'User is Not Admin !! Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
            app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/blog', methods=['GET'])
@token_required
def get_all_blog(current_user):
    blogs = Blog.query.filter_by(author=current_user.username).all()
    print(blogs)

    output = []

    for blog in blogs:
        blog_data = {}

        blog_data['id'] = blog.id
        blog_data['title'] = blog.title
        blog_data['blog'] = blog.blog
        blog_data['author'] = blog.author
        output.append(blog_data)

    return jsonify({'Blogs': output})


@app.route('/blog/<blog_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, blog_id):
    blog = Blog.query.filter_by(id=blog_id, author=current_user.username).first()

    if not blog:
        return jsonify({'message': 'No Blog found!'})

    blog_data = {}
    blog_data['id'] = blog.id
    blog_data['title'] = blog.title
    blog_data['blog'] = blog.blog
    blog_data['author'] = blog.author

    return jsonify(blog_data)


@app.route('/blog', methods=['POST'])
@token_required
def create_blog(current_user):
    data = request.get_json()
    print(data)

    new_blog = Blog(title=data['title'], blog=data['blog'], author=current_user.username)
    print(new_blog)
    db.session.add(new_blog)
    db.session.commit()

    return jsonify({'message': "Blog created!"})


@app.route('/blog/<blog_id>', methods=['DELETE'])
@token_required
def delete_blog(current_user, blog_id):
    blog = Blog.query.filter_by(id=blog_id, author=current_user.username).first()

    if not blog:
        return jsonify({'message': 'No Blog found!'})

    db.session.delete(blog)
    db.session.commit()

    return jsonify({'message': 'BLog item deleted!'})


if __name__ == '__main__':
    app.run(debug=True)
