from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from jwt import InvalidSignatureError, DecodeError
from waitress import serve
import pymongo
import os
import base64
import jwt
from functools import wraps

app = Flask(__name__)

m_client = pymongo.MongoClient('mongodb://localhost:27017/')
m_db = m_client[os.environ['DB_NAME']]
key = base64.b64encode(bytes(os.environ['SECRET_KEY'], 'utf8'))
cipher_suite = Fernet(key)


def requires_jwt(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            auth = request.headers['JWT']
            jwt.decode(auth, os.environ['SECRET_KEY'], algorithm='HS256')
        except KeyError:
            return unauthorized()
        except InvalidSignatureError:
            return unauthorized()
        except DecodeError:
            return unauthorized()
        return f(*args, **kwargs)
    return wrapper


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
@app.route('/user-management/api/v1/users/photo', methods=['OPTIONS'])
@app.route('/user-management/api/v1/basicInfo', methods=['OPTIONS'])
@app.route('/user-management/api/v1/illnesses', methods=['OPTIONS'])
@app.route('/user-management/api/v1/medications', methods=['OPTIONS'])
@app.route('/user-management/api/v1/vitalSigns', methods=['OPTIONS'])
@app.route('/user-management/api/v1/diet', methods=['OPTIONS'])
@app.route('/user-management/api/v1/others', methods=['OPTIONS'])
def preflight():
    return create_response({}), 200


@app.route('/user-management/api/v1/users/all', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_all_users():
    limit = int(request.args.get('limit')) if request.args.get('limit') is not None else 10
    offset = int(request.args.get('offset')) if request.args.get('offset') is not None else 0
    response_payload = list(m_db['users'].find().limit(limit).skip(offset))
    return create_response(response_payload, deleted_keys=['_id', 'password']), 200


@app.route('/user-management/api/v1/users/photo', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_user_photo():
    m_query = {
        "email": request.args.get('id')
    }
    result = m_db['users'].find_one(m_query)
    if result is not None:
        try:
            response_payload = {
                "picture": result['picture']
            }
        except KeyError:
            response_payload = {
                "picture": None
            }
    else:
        response_payload = {
            "error": "No record found"
        }
    return create_response(response_payload), 200


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
            jwt_payload = {
                "email": response_payload['email'],
                "password": result_password
            }
            access_token = jwt.encode(jwt_payload, os.environ['SECRET_KEY'], algorithm='HS256')
            response_payload['access_token'] = str(access_token, 'UTF-8')
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


@app.route('/user-management/api/v1/users', methods=['PUT'])
@requires_client_credentials
@requires_jwt
def update_user():
    update_user_data(request.json)
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/basicInfo', methods=['POST'])
@requires_client_credentials
@requires_jwt
def create_basic_info():
    update_or_insert_data(request.json, 'basic_info')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/illnesses', methods=['POST'])
@requires_client_credentials
@requires_jwt
def create_illnesses():
    update_or_insert_data(request.json, 'illnesses')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/medications', methods=['POST'])
@requires_client_credentials
@requires_jwt
def create_medications():
    update_or_insert_data(request.json, 'medications')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/vitalSigns', methods=['POST'])
@requires_client_credentials
@requires_jwt
def create_vital_signs():
    update_or_insert_data(request.json, 'vital_signs')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/diet', methods=['POST'])
@requires_client_credentials
@requires_jwt
def create_diet():
    update_or_insert_data(request.json, 'diet')
    response_payload = {}
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/others', methods=['POST'])
@requires_client_credentials
@requires_jwt
def create_other_questions():
    update_or_insert_data(request.json, 'other_questions')
    response_payload = {}
    return create_response(response_payload), 200


def update_or_insert_data(payload, collection):
    m_query = {
        "id": payload['id']
    }
    m_db[collection].update_one(m_query, {
       "$set": payload
    }, upsert=True)


def update_user_data(payload):
    m_query = {
        "email": payload['email']
    }
    m_db['users'].update_one(m_query, {
       "$set": payload
    })


@app.route('/user-management/api/v1/basicInfo', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_basic_info():
    response_payload = query_data('basic_info')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/illnesses', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_illnesses():
    response_payload = query_data('illnesses')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/medications', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_medications():
    response_payload = query_data('medications')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/vitalSigns', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_vital_signs():
    response_payload = query_data('vital_signs')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/diet', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_diet():
    response_payload = query_data('diet')
    return create_response(response_payload), 200


@app.route('/user-management/api/v1/others', methods=['GET'])
@requires_client_credentials
@requires_jwt
def get_other_questions():
    response_payload = query_data('other_questions')
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
    response.headers['Access-Control-Allow-Headers'] = 'email, password, Authorization, JWT, Overwrite, Destination, Content-Type, Depth, User-Agent, Translate, Range, Content-Range, Timeout, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control, Location, Lock-Token, If'
    response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS, POST, PUT'
    response.headers['Access-Control-Max-Age'] = 3600
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
