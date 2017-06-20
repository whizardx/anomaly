from datetime import datetime, timedelta
import os
import jwt
import json
from flask import Flask, jsonify, request, g, send_file, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from jwt import DecodeError, ExpiredSignature
from bson import ObjectId
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/Clientinfo'

mongo = PyMongo(app)

app.config.from_object('config')

def create_token(user):
    payload = {'sub': user['_id'], 'iat': datetime.utcnow(),
               'exp': datetime.utcnow() + timedelta(minutes=30)}
    token = jwt.encode(payload, app.config['TOKEN_SECRET'])
    return token.decode('unicode_escape')


def parse_token(req):
    token = req.headers.get('Authorization').split()[1]
    return jwt.decode(token, app.config['TOKEN_SECRET'])


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.headers.get('Authorization'):
            response = jsonify(message='Missing authorization header')
            response.status_code = 401
            return response
        try:
            payload = parse_token(request)
        except DecodeError:
            response = jsonify(message='Token is invalid')
            response.status_code = 401
            return response
        except ExpiredSignature:
            response = jsonify(message='Token has expired')
            response.status_code = 401
            return response

        g.user_id = payload['sub']

        return f(*args, **kwargs)

    return decorated_function


@app.route('/Clientinfo', methods=['GET'])
@login_required
def get_all_frameworks():

    user = mongo.db.users

    foundUser = user.find_one({'_id': ObjectId(g.user_id)})

    if foundUser:
        output = {'name': foundUser['name'],
                  'location': foundUser['location'],
                  'email': foundUser['email']}
    else:
        output = 'No result found'
    return jsonify({'data':'welcome to your profile \n' , 'data': output})


@app.route('/auth/signup', methods=['POST'])
def signup():
    user = mongo.db.users
    name = request.json['name']
    location = request.json['location']
    email = request.json['email']
    password = generate_password_hash(request.json['password'])

    user_id = user.insert({'name': name,
                           'location':location, 
                           'email': email,
                           'password': password})
    new_user = user.find_one({'_id': user_id})

    output = {'_id': str(new_user['_id']),
              'name': new_user['name'],
              'location': new_user['location'],
              'email': new_user['email']}
    token = create_token(output)
    return jsonify({'token': token, 'data': output})


@app.route('/auth/login', methods=['POST'])
def login():
    user = mongo.db.users

    foundUser = user.find_one({'email': request.json['email']})
    if not foundUser or not check_password_hash(foundUser['password'], request.json['password']):
        response = jsonify(message='Wrong Email or Password')
        response.status_code = 401
        return response

    output = {'_id': str(user['_id']),
              'name': user['name'],
              'location': user['location'],
              'email': user['email']}
    token = create_token(output)
    return jsonify({'data': 'you have logged in succesfully', 'token': token})

@app.route('/auth/update', methods=['PUT'])
@login_required
def update():
    
    user = mongo.db.users
    name = request.json['name']
    location = request.json['location']
    email = request.json['email']

    foundUser = user.find_one({'_id': ObjectId(g.user_id)})
    if foundUser:
        user_id = user.update_one({'name': name,
                                   'location':location, 
                                   'email': email})
    else:
        output = 'No result found'

    new_user = user.find_one({'_id': user_id})

    output = {'_id': str(new_user['_id']),
              'name': new_user['name'],
              'location': new_user['location'],
              'email': new_user['email']}
    token = create_token(output)
    return jsonify({'data': 'you have updated your data succesfully', 'token': token})


if __name__ == '__main__':
    app.run(debug=True, port=3003)