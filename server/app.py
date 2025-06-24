from flask import Flask, request, jsonify, session
from flask_migrate import Migrate
from models import db, bcrypt, User, Recipe

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'

db.init_app(app)
migrate = Migrate(app, db)
bcrypt.init_app(app)

# -------------------
# Signup
# -------------------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    image_url = data.get('image_url')
    bio = data.get('bio')

    try:
        user = User(username=username, image_url=image_url, bio=bio)
        user.password_hash = password  # hashes password
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id

        return jsonify(user.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        # Collect errors, could be from validation or unique constraints
        return jsonify({'errors': str(e)}), 422


# -------------------
# Check Session (Auto-login)
# -------------------
@app.route('/check_session', methods=['GET'])
def check_session():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user = User.query.get(user_id)
    if user:
        return jsonify(user.to_dict()), 200
    else:
        return jsonify({'error': 'User not found'}), 401


# -------------------
# Login
# -------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.authenticate(password):
        session['user_id'] = user.id
        return jsonify(user.to_dict()), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


# -------------------
# Logout
# -------------------
@app.route('/logout', methods=['DELETE'])
def logout():
    if 'user_id' in session:
        session.pop('user_id')
        return '', 204
    else:
        return jsonify({'error': 'Unauthorized'}), 401


# -------------------
# Recipes List & Creation
# -------------------
@app.route('/recipes', methods=['GET', 'POST'])
def recipes():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    if request.method == 'GET':
        all_recipes = Recipe.query.all()
        return jsonify([r.to_dict() for r in all_recipes]), 200

    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes = data.get('minutes_to_complete')

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return jsonify(recipe.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'errors': str(e)}), 422


if __name__ == '__main__':
    app.run(debug=True)
