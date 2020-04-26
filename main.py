from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import pymongo
import os
import base64

app = Flask(__name__)

m_client = pymongo.MongoClient('mongodb://localhost:27017/')
m_db = m_client['test']
m_col = m_db['users']
key = base64.b64encode(bytes(os.environ['SECRET_KEY'], 'utf8'))
cipher_suite = Fernet(key)


@app.route('/user-management/api/v1/users', methods=['OPTIONS'])
def preflight():
    return create_response({}), 200


@app.route('/user-management/api/v1/users/all', methods=['GET'])
def get_all_users():
    limit = int(request.args.get('limit')) if request.args.get('limit') is not None else 10
    offset = int(request.args.get('offset')) if request.args.get('offset') is not None else 0
    response_payload = list(m_col.find().limit(limit).skip(offset))
    return create_response(response_payload, deleted_keys=['_id', 'password']), 200


@app.route('/user-management/api/v1/users', methods=['GET'])
def get_users():
    input_password = request.headers.get('password')
    m_query = {
        "email": request.headers.get('email'),
        "enabled": True
    }
    result = m_col.find_one(m_query)
    if result is not None:
        result_password = str(cipher_suite.decrypt(result['password']), 'utf8')
        if input_password != result_password:
            response_payload = {
                "error": "Invalid username/password"
            }
        else:
            response_payload = result
            del response_payload['password']
    else:
        response_payload = {
            "error": "Account does not exist"
        }

    return create_response(response_payload), 200


@app.route('/user-management/api/v1/users', methods=['POST'])
def create_user():
    payload = request.json
    m_query = {
        "email": payload['email']
    }
    result = m_col.find_one(m_query)
    if result is not None:
        response_payload = {
            "error": "Account already exists"
        }
    else:
        input_password = payload['password']
        payload['password'] = cipher_suite.encrypt(bytes(input_password, 'utf8'))
        m_col.insert_one(payload)
        response_payload = {}

    return create_response(response_payload), 200


def create_response(response_payload, deleted_keys=['_id']):
    if not isinstance(response_payload, list):
        for k in deleted_keys:
            delete_key(response_payload, k)
    else:
        for response in response_payload:
            for k in deleted_keys:
                delete_key(response, k)

    response = jsonify(response_payload)
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:8080'
    response.headers['Access-Control-Allow-Headers'] = 'email,password,Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
    return response


def delete_key(obj, key_name):
    try:
        del obj[key_name]
    except KeyError:
        pass

