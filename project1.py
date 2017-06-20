from datetime import datetime, timedelta
import os
import jwt
import json
import sys
import pandas as pd
from flask import Flask, jsonify, request, g, send_file, redirect, url_for
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from jwt import DecodeError, ExpiredSignature
from bson import ObjectId
from functools import wraps
from flask_restful import Api, Resource
from requests import get, post, put, delete
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/home/debaditya/Music/'

ALLOWED_EXTENSIONS = set(['csv'])

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['MONGO_URI'] = 'mongodb://localhost:27017/clientstore'

mongo = PyMongo(app)

app.config.from_object('config')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        foundUser['_id'] = str(foundUser['_id'])
        foundUser.pop('password', None)
    else:
        foundUser = 'No result found'
    return jsonify({'data':'welcome to your profile \n' , 'data': foundUser})


@app.route('/auth/signup', methods=['POST'])
def signup():
    
    user=mongo.db.users

    data = request.get_json()
    
    if not 'email' in data or not 'password' in data:
        data1 = {"response": "Error in data input"}
        return jsonify(data1)
    else:
        if mongo.db.users.find_one({"email": data['email']}):
            return jsonify({"response": "Client already exists."})
        else:
            data['password'] = generate_password_hash(data['password'])
            user_id=user.insert(data)

    new_user = user.find_one({'_id': user_id})

    output = {'_id': str(new_user['_id']),
              'email':new_user['email']}
    token = create_token(output)
    return jsonify({'token': token, 'data': output})


@app.route('/auth/login', methods=['POST'])
def login():
    user = mongo.db.users
    data = request.get_json()
    foundUser = user.find_one({'email': data['email']})
    if not foundUser or not check_password_hash(foundUser['password'], data['password']):
        response = jsonify(message='Wrong Email or Password')
        response.status_code = 401
        return response

    output = {'_id': str(foundUser['_id']),
              'email': foundUser['email']}
    token = create_token(output)
    return jsonify({'data': 'you have logged in succesfully', 'token': token})

@app.route('/auth/update', methods=['PUT'])
@login_required
def update():
    
    user = mongo.db.users
    data = request.get_json()
    
    if 'password' in data:
        return jsonify({'data': 'Bad request'})
    user.update_one({'_id': ObjectId(g.user_id)},{'$set':data}) 

    return jsonify({'data': 'you have updated your data succesfully'}) 


@app.route('/auth/delete', methods=['DELETE'])
@login_required
def delete_user():
    
    user = mongo.db.users
    
    user.delete_one( { '_id' : ObjectId(g.user_id) } )
    
    return jsonify({'data': 'you have deleted your data succesfully'}) 

@app.route('/addProduct', methods=['POST'])
@login_required
def add_product():
    
    product=mongo.db.products

    data = request.get_json()
    
    if not 'id' in data or not 'name' in data or not 'category' in data:
        return jsonify({"response": "Error in data input"})
    else:
        data['clientId'] = ObjectId(g.user_id)
        addedProduct = product.insert(data)
    
    return jsonify({'data': 'Saved'})

@app.route('/Productfromcsv', methods=['POST'])
@login_required
def upload_content():
    
    if 'filename' not in request.files:
        return 'Bad Request'

    file = request.files['filename']
    
    if file.filename == '':
        return 'No selected file'

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return import_content(filename)
        
    else:
        return 'file not uploaded, allow only csv file ' #+ str(ALLOWED_EXTENSIONS.pop()) + ' file'

def import_content(filename):
    product=mongo.db.products
    # cdir = os.path.dirname(__file__)
    file_res = os.path.join(UPLOAD_FOLDER, filename)
    data = pd.read_csv(file_res)
    data_json = json.loads(data.to_json(orient='records'))
    data['clientId'] = ObjectId(g.user_id)
    Addedproduct = product.insert(data_json)
    return 'file uploaded successfully'

if __name__ == '__main__':
    #filepath = '/home/debaditya/Music'
    app.run(debug=True, port=3000)