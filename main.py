from flask import Flask, request, jsonify, Response
from cryptography.fernet import Fernet
from waitress import serve
import pymongo
import os
import base64
from functools import wraps

app = Flask(__name__)

m_client = pymongo.MongoClient('mongodb://localhost:27017/')
m_db = m_client['test']
m_col = m_db['users']
key = base64.b64encode(bytes(os.environ['SECRET_KEY'], 'utf8'))
cipher_suite = Fernet(key)
hostname = os.environ['ALLOWED_ORIGIN']


def requires_client_credentials(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not is_authenticated(auth.username, auth.password):
            return unauthorized()
        return func(*args, **kwargs)
    return wrapper


@app.route('/user-management/api/v1/users', methods=['OPTIONS'])
@app.route('/user-management/api/v1/basicInfo', methods=['OPTIONS'])
@app.route('/user-management/api/v1/illnesses', methods=['OPTIONS'])
def preflight():
    print("preflight request")
    return create_response({}), 200


@app.route('/user-management/api/v1/users/all', methods=['GET'])
def get_all_users():
    limit = int(request.args.get('limit')) if request.args.get('limit') is not None else 10
    offset = int(request.args.get('offset')) if request.args.get('offset') is not None else 0
    response_payload = list(m_col.find().limit(limit).skip(offset))
    return create_response(response_payload, deleted_keys=['_id', 'password']), 200


@app.route('/user-management/api/v1/users', methods=['GET'])
@requires_client_credentials
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
        response_payload = {"success": True}

    return create_response(response_payload), 200


@app.route('/user-management/api/v1/basicInfo', methods=['POST'])
def create_basic_info():
    payload = request.json
    m_query = {
        "id": payload['id']
    }
    m_db['basic_info'].update_one(m_query, {
       "$set": payload
    }, upsert=True)
    response_payload = {}

    return create_response(response_payload), 200


@app.route('/user-management/api/v1/illnesses', methods=['POST'])
def create_illnesses():
    payload = request.json
    m_query = {
        "id": payload['id']
    }
    m_db['illnesses'].update_one(m_query, {
       "$set": payload
    }, upsert=True)
    response_payload = {}

    return create_response(response_payload), 200


@app.route('/user-management/api/v1/basicInfo', methods=['GET'])
def get_basic_info():
    m_query = {
        "id": request.args.get('id')
    }
    result = m_db['basic_info'].find_one(m_query)
    if result is not None:
        response_payload = result
    else:
        response_payload = {
            "error": "No record found"
        }

    return create_response(response_payload), 200


@app.route('/user-management/api/v1/illnesses', methods=['GET'])
def get_illnesses():
    m_query = {
        "id": request.args.get('id')
    }
    result = m_db['illnesses'].find_one(m_query)
    if result is not None:
        response_payload = result
    else:
        response_payload = {
            "error": "No record found"
        }

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
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'email,password,Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
    return response


def delete_key(obj, key_name):
    try:
        del obj[key_name]
    except KeyError:
        pass


def unauthorized():
    return Response(status=401)


def is_authenticated(username, password):
    m_query = {
        "client_id": username,
        "client_secret": password
    }
    result = m_db['client_credentials'].find_one(m_query)
    return result is not None


if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
