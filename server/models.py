from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import validates

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    @property
    def password_hash(self):
        raise AttributeError("Password hash is not readable")

    @password_hash.setter
    def password_hash(self, password_plaintext):
        self._password_hash = bcrypt.generate_password_hash(password_plaintext).decode('utf-8')

    def authenticate(self, password_plaintext):
        return bcrypt.check_password_hash(self._password_hash, password_plaintext)

    @validates('username')
    def validate_username(self, key, username):
        if not username or username.strip() == '':
            raise ValueError("Username must be present")
        return username

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'image_url': self.image_url,
            'bio': self.bio
        }


class Recipe(db.Model):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='recipes')

    @validates('title')
    def validate_title(self, key, title):
        if not title or title.strip() == '':
            raise ValueError("Title must be present")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters")
        return instructions

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'instructions': self.instructions,
            'minutes_to_complete': self.minutes_to_complete,
            'user': self.user.to_dict()
        }
