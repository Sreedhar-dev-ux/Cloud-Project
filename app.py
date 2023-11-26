from flask import Flask, request, redirect, render_template, make_response, flash
import jwt
from google.cloud import datastore, storage
from decouple import config
import os
import hashlib
from datetime import timedelta


app = Flask(__name__)
JWT_SECRET_KEY = config('JWT_SECRET_KEY')
BUCKET_NAME = config('BUCKET_NAME')

GOOGLE_APPLICATION_CREDENTIALS = os.environ.get('GOOGLE_APPLICATION')
with open('google-credentials.json', 'w') as outfile:
    outfile.write(GOOGLE_APPLICATION_CREDENTIALS)

storage_client = storage.Client.from_service_account_json(
    'google-credentials.json')
client = datastore.Client.from_service_account_json(
    'google-credentials.json')

# client = datastore.Client()
# bucket = storage.Client().bucket(BUCKET_NAME)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['png', 'jpg', 'jpeg', 'gif']


def get_jwt(email):
    return jwt.encode({'email': email}, JWT_SECRET_KEY, algorithm='HS256')


def get_user(email):
    query = client.query(kind='User')
    query.add_filter('email', '=', email)
    return list(query.fetch())


def add_user(email, password):
    key = client.key('User')
    entity = datastore.Entity(key)
    entity.update({
        'email': email,
        'password': password
    })
    client.put(entity)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)
        if user:
            message = 'email already exists!'
        else:
            add_user(email, password)
            return redirect('/login')
    return render_template('signup.html', message=message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)
        if user and user[0]['password'] == password:
            response = make_response(redirect('/'))
            response.set_cookie('jwt', get_jwt(email))
            return response
        message = 'Invalid email or password!'
    return render_template('login.html', message=message)


@app.route('/')
def index():
    jwt_cookie = request.cookies.get('jwt')
    if jwt_cookie:
        try:
            decoded = jwt.decode(
                jwt_cookie, JWT_SECRET_KEY, algorithms=['HS256'])
            email = decoded.get('email')
        except:
            return redirect('/login')

        query = client.query(kind='Image')
        query.add_filter('user', '=', email)
        images = list(query.fetch())
        for image in images:
            image['image_type'] = image.get('image_type', 'Unknown')
            image['image_size'] = image.get('image_size', 0)
            image_size_kb = image['image_size'] / 1024
            image_size_mb = image_size_kb / 1024
            if image_size_mb > 1:
                image['image_size'] = f"{round(image_size_mb, 2)} MB"
            else:
                image['image_size'] = f"{round(image_size_kb, 2)} KB"
            # check if display_name is key
            if 'display_name' not in image:
                image['display_name'] = image['filename']

        image_urls = [{"url": image["url"], "name": image["filename"], 'display_name': image['display_name'], "image_type": image["image_type"], 'image_size': image['image_size']}
                      for image in images]
        return render_template('index.html', images=image_urls)

    return redirect('/login')


@app.route('/upload', methods=['GET', 'POST'])
def upload_files():
    if request.method == 'POST':
        jwt_cookie = request.cookies.get('jwt')
        try:
            decoded = jwt.decode(
                jwt_cookie, JWT_SECRET_KEY, algorithms=['HS256'])
            email = decoded.get('email')
        except jwt.ExpiredSignatureError:
            return redirect('/login')

        files = request.files.getlist('images')
        if not files:
            flash('No image selected!', 'error')
            return redirect(request.url)

        for file in files:
            if file and allowed_file(file.filename):
                if file.content_length > 4 * 1024 * 1024:
                    flash('Image is too large (max 4MB).', 'error')
                    continue

                hash_filename = hashlib.sha256(os.urandom(64)).hexdigest()
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                clean_filename = file.filename.split('.')[0].lower()
                new_filename = clean_filename.replace(' ', '_')
                new_filename = new_filename.replace('-', '_')
                new_filename = new_filename + '.' + file_extension
                storage_filename = f"{hash_filename}.{file_extension}"

                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(storage_filename)
                blob.upload_from_string(
                    file.read(), content_type=file.content_type)
                # blob.make_public()

                image_entity = datastore.Entity(key=client.key('Image'))
                image_type = file.content_type.split('/')[-1] or 'unknown'

                image_entity.update({
                    'user': email,
                    'filename': storage_filename,
                    'display_name': new_filename,
                    'url': '/bucket/' + storage_filename,
                    'image_type': image_type,
                    'image_size': blob.size
                })
                client.put(image_entity)
            else:
                flash('Invalid file format.', 'error')
                continue

        return redirect('/')
    else:
        return render_template('index.html')


def generate_signed_url(object_name):
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(object_name)
    signed_url = blob.generate_signed_url(
        expiration=timedelta(minutes=30))
    return signed_url


@app.route('/bucket/<image_id>')
def serve_image(image_id):
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(image_id)
    image_data = blob.download_as_bytes()
    return make_response(image_data)


@app.route('/image/<filename>')
def get_image(filename):
    blob = storage.Blob(filename, bucket)
    image_data = blob.download_as_bytes()
    return make_response(image_data)


@app.route('/download/<filename>')
def download_image(filename):
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(filename)
    image_data = blob.download_as_bytes()
    return make_response(image_data)


@app.route('/logout', methods=['GET', 'POST'])
def custom_logout():
    response = make_response(redirect('/login'))
    response.set_cookie('jwt', '', expires=0)
    return response


@app.route('/delete_image/<filename>')
def delete_image(filename):
    jwt_cookie = request.cookies.get('jwt')
    if jwt_cookie:
        try:
            decoded = jwt.decode(
                jwt_cookie, JWT_SECRET_KEY, algorithms=['HS256'])
            email = decoded.get('email')
        except jwt.ExpiredSignatureError:
            return redirect('/login')

        # Delete image from bucket
        bucket = storage_client.bucket(BUCKET_NAME)
        blob = bucket.blob(filename)
        blob.delete()

        # Delete image reference from datastore
        query = client.query(kind='Image')
        query.add_filter('filename', '=', filename)
        query.add_filter('user', '=', email)
        results = list(query.fetch())

        if results:
            for result in results:
                client.delete(result.key)

        return redirect('/')
    else:
        return redirect('/login')


@app.route('/view_image/<filename>')
def view_image(filename):
    jwt_cookie = request.cookies.get('jwt')
    if jwt_cookie:
        try:
            decoded = jwt.decode(
                jwt_cookie, JWT_SECRET_KEY, algorithms=['HS256'])
            email = decoded.get('email')
        except jwt.ExpiredSignatureError:
            return redirect('/login')

        query = client.query(kind='Image')
        query.add_filter('filename', '=', filename)
        query.add_filter('user', '=', email)
        result = list(query.fetch())

        if result:
            image = result[0]
            image_size_kb = image['image_size'] / 1024
            image_size_mb = image_size_kb / 1024
            print(image)
            if image_size_mb > 1:
                image['image_size'] = f"{round(image_size_mb, 2)} MB"
            else:
                image['image_size'] = f"{round(image_size_kb, 2)} KB"

            if 'display_name' not in image:
                image['display_name'] = image['filename']
            return render_template('view.html', image=image)
        else:
            return 'Image not found', 404
    else:
        return redirect('/login')


@app.errorhandler(404)
def custom_404(error):
    print(error)
    return render_template('404.html')


@app.errorhandler(500)
def custom_500(error):
    print(error)
    return render_template('500.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
