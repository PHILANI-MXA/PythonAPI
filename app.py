import datetime
from functools import wraps

import jwt
from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisthesecretkey'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        
        if not token:
            return jsonify({'Message': 'Token is missing'}), 403
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'Message': 'Token is invalid'}), 403

        return f(*args, **kwargs)

    return decorated

@app.route('/unprotected')
def unprotected():
    return jsonify({'Message': 'Anyone can view this'})

@app.route('/protected')
@token_required
def protected():
    return jsonify({'Message': 'This is only available for people with valid tokens'})

@app.route('/login')
def login():
    auth = request.authorization

    if auth and auth.password == 'password':
        token =  jwt.encode({'user': auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm = "Login required"'})


if __name__ == '__main__':
    app.run(debug=True)