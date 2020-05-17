from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from waitress import serve
import pymongo
import os
import base64
from functools import wraps

app = Flask(__name__)

m_client = pymongo.MongoClient('mongodb://localhost:27017/')
m_db = m_client['test']
key = base64.b64encode(bytes(os.environ['SECRET_KEY'], 'utf8'))
cipher_suite = Fernet(key)


def requires_client_credentials(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not is_authenticated(auth.username, auth.password):
            return unauthorized()
        return f(*args, **kwargs)
    return wrapper


@app.route('/user-management/api/v1/users', methods=['OPTIONS'])
@app.route('/user-management/api/v1/users/all', methods=['OPTIONS'])
@app.route('/user-management/api/v1/basicInfo', methods=['OPTIONS'])
@app.route('/user-management/api/v1/illnesses', methods=['OPTIONS'])
@app.route('/user-management/api/v1/medications', methods=['OPTIONS'])
@app.route('/user-management/api/v1/vitalSigns', methods=['OPTIONS'])
def preflight():
    return create_response({}), 200


@app.route('/user-management/api/v1/users/all', methods=['GET'])
@requires_client_credentials
def get_all_users():
    limit = int(request.args.get('limit')) if request.args.get('limit') is not None else 10
    offset = int(request.args.get('offset')) if request.args.get('offset') is not None else 0
    response_payload = list(m_db['users'].find().limit(limit).skip(offset))
    return create_response(response_payload, deleted_keys=['_id', 'password']), 200


@app.route('/user-management/api/v1/users', methods=['GET'])
@requires_client_credentials
def get_users():
    input_password = request.headers.get('password')
    m_query = {
        "email": request.headers.get('email'),
        "enabled": True
    }
    result = m_db['users'].find_one(m_query)
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
@requires_client_credentials
def create_user():
    payload = request.json
    m_query = {
        "email": payload['email']
    }
    result = m_db['users'].find_one(m_query)
    if result is not None:
        response_payload = {
            "error": "Account already exists"
        }
    else:
        input_password = payload['password']
        payload['password'] = cipher_suite.encrypt(bytes(input_password, 'utf8'))
        m_db['users'].insert_one(payload)
        response_payload = {"success": True}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/basicInfo', methods=['POST'])
@requires_client_credentials
def create_basic_info():
    update_or_insert_data(request.json, 'basic_info')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/illnesses', methods=['POST'])
@requires_client_credentials
def create_illnesses():
    update_or_insert_data(request.json, 'illnesses')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/medications', methods=['POST'])
@requires_client_credentials
def create_medications():
    update_or_insert_data(request.json, 'medications')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/vitalSigns', methods=['POST'])
@requires_client_credentials
def create_vital_signs():
    update_or_insert_data(request.json, 'vital_signs')
    response_payload = {}
    return create_response(response_payload), 200


def update_or_insert_data(payload, collection):
    m_query = {
        "id": payload['id']
    }
    m_db[collection].update_one(m_query, {
       "$set": payload
    }, upsert=True)


@app.route('/user-management/api/v1/basicInfo', methods=['GET'])
@requires_client_credentials
def get_basic_info():
    response_payload = query_data('basic_info')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/illnesses', methods=['GET'])
@requires_client_credentials
def get_illnesses():
    response_payload = query_data('illnesses')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/medications', methods=['GET'])
@requires_client_credentials
def get_medications():
    response_payload = query_data('medications')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/vitalSigns', methods=['GET'])
@requires_client_credentials
def get_vital_signs():
    response_payload = query_data('vital_signs')
    return create_response(response_payload), 200


def query_data(collection):
    m_query = {
        "id": request.args.get('id')
    }
    result = m_db[collection].find_one(m_query)
    if result is not None:
        response_payload = result
    else:
        response_payload = {
            "error": "No record found"
        }
    return response_payload


def create_response(response_payload, deleted_keys=['_id']):
    if not isinstance(response_payload, list):
        for k in deleted_keys:
            delete_key(response_payload, k)
    else:
        for response in response_payload:
            for k in deleted_keys:
                delete_key(response, k)

    response = jsonify(response_payload)
    response.headers['Access-Control-Allow-Origin'] = os.environ['ALLOWED_ORIGIN']
    response.headers['Access-Control-Allow-Headers'] = 'email,password,Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
    return response


def delete_key(obj, key_name):
    try:
        del obj[key_name]
    except KeyError:
        pass


def unauthorized():
    return create_response({}), 401


def is_authenticated(username, password):
    m_query = {
        "client_id": username,
        "client_secret": password
    }
    result = m_db['client_credentials'].find_one(m_query)
    return result is not None


if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
