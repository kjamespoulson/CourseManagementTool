from flask import Flask, request, send_file, jsonify
from google.cloud import storage, datastore
import io
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

##########################################
# SENSITIVE INFORMATION HAS BEEN REMOVED #
##########################################

PHOTO_BUCKET = 'fake_bucket'

app = Flask(__name__)
app.secret_key = 'fake_key'

client = datastore.Client()

USERS = 'users'
COURSES = 'courses'
AVATAR = 'avatar'
STUDENTS = 'students'

CLIENT_ID = 'fake_id'
CLIENT_SECRET = 'fake_secret'
DOMAIN = 'fake_domain'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from
# https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

@app.route('/')
def index():
    return 'Navigate to other endpoints to use this application'\


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if len(content) != 2:
        return {'Error': 'The request body is invalid'}, 400
    elif 'password' not in content or 'username' not in content:
        return {'Error': 'The request body is invalid'}, 400
    else:
        username = content["username"]
        password = content["password"]
        body = {'grant_type': 'password', 'username': username,
                'password': password,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET
                }
        headers = {'content-type': 'application/json'}
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        response_data = r.json()
        id_token = response_data.get('id_token')
        if r.status_code != 200:
            return {'Error': 'Unauthorized'}, 401
        else:
            return {'token': id_token}, 200


@app.route('/' + USERS, methods=['GET'])
def get_users():
    """Allows admin ONLY to get all users"""
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        results = list(query.fetch())
        if results[0]['role'] != 'admin':
            return {'Error': 'You don\'t have permission on this resource'}, 403
        else:
            query = client.query(kind=USERS)
            results = list(query.fetch())
            for r in results:
                r['id'] = r.key.id
                if 'avatar' in r:
                    del r['avatar']
                    del r['avatar_url']
            return results, 200


@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Allows admin to get a user or the user to get themselves"""
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        results = list(query.fetch())
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        # Verify the user exists
        if user is None:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Verify the JWT relates to an admin or the requested user
        user['id'] = user_id
        enrollments_query = client.query(kind=COURSES)
        enrollments_results = list(enrollments_query.fetch())
        if 'avatar' in user:
            del user['avatar']
        if results[0]['role'] == 'admin':
            if user['role'] != 'admin':
                user['courses'] = list()
                for items in enrollments_results:
                    if user_id in items['enrollments']:
                        user['courses'].append(request.host_url + COURSES + '/' + str(items.key.id))
                return user, 200
            else:
                return user, 200
        elif payload['sub'] == user['sub']:
            user['courses'] = list()
            for items in enrollments_results:
                if user_id in items['enrollments']:
                    user['courses'].append(
                    request.host_url + COURSES + '/' + str(items.key.id))
            return user, 200
        # Otherwise, return an error
        else:
            return {'Error': 'You don\'t have permission on this resource'}, 403


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['POST'])
def create_update_avatar(user_id):
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return {'Error': 'The request body is invalid'}, 400
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if payload['sub'] != user['sub']:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        else:
            # Set file_obj to the file sent in the request
            file_obj = request.files['file']
            # If the multipart form data has a part with name 'tag', set the
            # value of the variable 'tag' to the value of 'tag' in the request.
            # Note we are not doing anything with the variable 'tag' in this
            # example, however this illustrates how we can extract data from the
            # multipart form data in addition to the files.
            if 'tag' in request.form:
                tag = request.form['tag']
            # Create a storage client
            storage_client = storage.Client()
            # Get a handle on the bucket
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            # Create a blob object for the bucket with the name of the file
            blob = bucket.blob(file_obj.filename)
            # Position the file_obj to its beginning
            file_obj.seek(0)
            # Upload the file into Cloud Storage
            blob.upload_from_file(file_obj)
            file_path = (request.host_url + USERS + '/' + str(user_id) + '/' +
                         AVATAR)
            user.update({
                'avatar_url': file_path,
                'avatar': file_obj.filename
            })
            client.put(user)
            return {'avatar_url': file_path}, 200


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['GET'])
def get_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if payload['sub'] != user['sub']:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        elif 'avatar' not in user:
            return {'Error': 'Not found'}, 404
        else:
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            # Create a blob with the given file name
            blob = bucket.blob(user['avatar'])
            # Create a file object in memory using Python io package
            file_obj = io.BytesIO()
            # Download the file from Cloud Storage to the file_obj variable
            blob.download_to_file(file_obj)
            # Position the file_obj to its beginning
            file_obj.seek(0)
            # Send the object as a file in the response with the correct MIME type and
            # file name
            return send_file(file_obj, mimetype='image/x-png',
                             download_name=user['avatar'])


@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if payload['sub'] != user['sub']:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        elif 'avatar' not in user:
            return {'Error': 'Not found'}, 404
        else:
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(PHOTO_BUCKET)
            blob = bucket.blob(user['avatar'])
            # Delete the file from Cloud Storage
            blob.delete()
            del user['avatar']
            del user['avatar_url']
            client.put(user)
            return '', 204

@app.route('/' + COURSES, methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        results = list(query.fetch())
        if results[0]['role'] != 'admin':
            return {'Error': 'You don\'t have permission on this resource'}, 403
        else:
            content = request.get_json()
            if len(content) != 5:
                return {'Error': 'The request body is invalid'}, 400
            instructor_key = client.key(USERS, int(content['instructor_id']))
            instructor = client.get(key=instructor_key)
            if instructor is None:
                return {'Error': 'The request body is invalid'}, 400
            elif instructor['role'] != 'instructor':
                return {'Error': 'The request body is invalid'}, 400
            else:
                new_course = datastore.entity.Entity(key=client.key(COURSES))
                new_course.update({
                    'subject': content['subject'],
                    'number': content['number'],
                    'title': content['title'],
                    'term': content['term'],
                    'instructor_id': content['instructor_id'],
                    'enrollments': list()
                })
                client.put(new_course)
                course_key = client.key(COURSES, new_course.key.id)
                course = client.get(key=course_key)
                course['id'] = course.key.id
                course['self'] = (request.host_url + COURSES + '/' +
                                  str(course['id']))
                del course['enrollments']
                return jsonify(course), 201


@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():
    my_offset = request.args.get('offset')
    my_limit = request.args.get('limit')
    print(my_limit)
    print(my_offset)
    if my_offset is None:
        query = client.query(kind=COURSES)
        query.order = ['subject']
        results = list(query.fetch())
        for r in results:
            r['id'] = r.key.id
            r['self'] = (request.host_url + COURSES + '/' + str(r['id']))
        return {'courses': results}, 200
    else:
        query = client.query(kind=COURSES)
        query.order = ['subject']
        query_iter = query.fetch(limit=int(my_limit), offset=int(my_offset))
        pages = query_iter.pages
        courses = list(next(pages))
        for c in courses:
            c['id'] = c.key.id
            c['self'] = request.host_url + COURSES + '/' + str(c['id'])
            del c['enrollments']
        my_next = (request.host_url + COURSES + '?limit=' + my_limit +
                   '&offset=' + str(int(my_limit) + int(my_offset)))
        return {'courses': courses, 'next': my_next}, 200


@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if course is None:
        return {'Error': 'Not found'}, 404
    else:
        course['id'] = course.key.id
        course['self'] = request.host_url + COURSES + '/' + str(course['id'])
        del course['enrollments']
        return course, 200

@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        # Validate the course exists
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Validate an admin made the request
        admin_query = client.query(kind=USERS)
        admin_query.add_filter('sub', '=', payload['sub'])
        admin = list(admin_query.fetch())
        if admin[0]['role'] != 'admin':
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Check attributes
        content = request.get_json()
        updated_course = {}
        if 'instructor_id' in content:
            instructor_key = client.key(USERS, content['instructor_id'])
            instructor = client.get(key=instructor_key)
            if instructor is None:
                return {'Error': 'The request body is invalid'}, 400
            if instructor['role'] != 'instructor':
                return {'Error': 'The request body is invalid'}, 400
            else:
                updated_course['instructor_id'] = content['instructor_id']
        if 'subject' in content:
            updated_course['subject'] = content['subject']
        if 'number' in content:
            updated_course['number'] = content['number']
        if 'title' in content:
            updated_course['title'] = content['title']
        if 'term' in content:
            updated_course['term'] = content['term']
        course.update(updated_course)
        client.put(course)
        course['id'] = course.key.id
        course['self'] = request.host_url + COURSES + '/' + str(course['id'])
        del course['enrollments']
        return course, 200


@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        admin_query = client.query(kind=USERS)
        admin_query.add_filter('sub', '=', payload['sub'])
        admin = list(admin_query.fetch())
        if admin[0]['role'] != 'admin':
            return {'Error': 'You don\'t have permission on this resource'}, 403
        client.delete(course_key)
        return '', 204


@app.route('/' + COURSES + '/<int:course_id>/' + STUDENTS, methods=['PATCH'])
def update_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Validate a student did not make the request
        student_query = client.query(kind=USERS)
        student_query.add_filter('sub', '=', payload['sub'])
        student = list(student_query.fetch())
        if student[0]['role'] == 'student':
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Weed out instructors that are not teaching the course
        if student[0]['role'] == 'instructor' and course['instructor_id'] != student[0].key.id:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        content = request.get_json()
        valid = check_enrollment_validity(content)
        if valid is False:
            return {'Error': 'Enrollment data is invalid'}, 409
        else:
            for items in content['add']:
                if items not in course['enrollments']:
                    course['enrollments'].append(items)
            for items in content['remove']:
                if items in course['enrollments']:
                    course['enrollments'].remove(items)
            client.put(course)
        return '', 200

def check_enrollment_validity(content):
    add_set = set(content['add'])
    remove_set = set(content['remove'])
    if add_set & remove_set != set():
        return False
    list_content = [list(add_set), list(remove_set)]
    for items in list_content:
        for students in items:
            student_key = client.key(USERS, students)
            student = client.get(key=student_key)
            if student is None:
                return False
            elif student['role'] != 'student':
                return False
    return True

@app.route('/' + COURSES + '/<int:course_id>/' + STUDENTS, methods=['GET'])
def get_enrollments(course_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {'Error': 'Unauthorized'}, 401
    else:
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Validate a student did not make the request
        student_query = client.query(kind=USERS)
        student_query.add_filter('sub', '=', payload['sub'])
        student = list(student_query.fetch())
        if student[0]['role'] == 'student':
            return {'Error': 'You don\'t have permission on this resource'}, 403
        # Weed out instructors that are not teaching the course
        if student[0]['role'] == 'instructor' and course['instructor_id'] != student[0].key.id:
            return {'Error': 'You don\'t have permission on this resource'}, 403
        else:
            return course['enrollments'], 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)
