# myapp/views.py
from decouple import config
from django.views.decorators.csrf import requires_csrf_token
from django.shortcuts import render, redirect
from django.core.files.storage import default_storage
from django.http import FileResponse
from .models import User, Image
from google.cloud import datastore, storage
from django.views.decorators.csrf import csrf_exempt
import jwt
import os
JWT_SECRET_KEY = config('JWT_SECRET_KEY')
BUCKET_NAME = config('BUCKET_NAME')


client = datastore.Client()
bucket = storage.Client().bucket(BUCKET_NAME)


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


@csrf_exempt
def signup(request):
    message = ''
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = get_user(email)
        if user:
            message = 'email already exists!'
        else:
            add_user(email, password)
            return redirect('login')
    return render(request, 'signup.html', {'message': message})


@csrf_exempt
def login(request):
    message = ''
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = get_user(email)
        if user and user[0]['password'] == password:
            response = redirect('index')
            response.set_cookie('jwt', get_jwt(email))
            return response
        message = 'Invalid email or password!'
    return render(request, 'login.html', {'message': message})


def index(request):
    jwt_cookie = request.COOKIES.get('jwt')
    if jwt_cookie:
        try:
            decoded = jwt.decode(
                jwt_cookie, JWT_SECRET_KEY, algorithms=['HS256'])
            email = decoded.get('email')
        except:
            return redirect('login')

        query = client.query(kind='Image')
        query.add_filter('user', '=', email)
        images = list(query.fetch())
        for image in images:
            if 'image_type' not in image:
                image['image_type'] = 'Unknown'
            if 'image_size' not in image:
                image['image_size'] = 0
            image_size_kb = image['image_size'] / 1024
            image_size_mb = image_size_kb / 1024
            if image_size_mb>1:
                image['image_size']=f"{round(image_size_mb, 2)} MB"
            else:
                image['image_size'] = f"{round(image_size_kb, 2)} KB"
        image_urls = [{"url": image['url'], "name": image["filename"], "image_type": image["image_type"], 'image_size': image['image_size']}
                      for image in images]
        return render(request, 'index.html', {'images': image_urls})

    return redirect('login')


@csrf_exempt
def upload_files(request):
    if request.method == 'POST' and 'images' in request.FILES:
        files = request.FILES.getlist('images')
        jwt_cookie = request.COOKIES.get('jwt')
        try:
            decoded = jwt.decode(
                jwt_cookie, JWT_SECRET_KEY, algorithms=['HS256'])
            email = decoded.get('email')
        except jwt.ExpiredSignatureError:
            return redirect('login')

        for file in files:
            if file:
                filename = file.name
                blob = bucket.blob(filename)
                blob.upload_from_string(
                    file.read(),
                    content_type=file.content_type
                )
                blob.make_public()

                image_entity = datastore.Entity(key=client.key('Image'))
                image_type = file.content_type.split('.')[-1]
                if (image_type == None or len(image_type) == 0):
                    image_type = 'unknown'
                    
                image_entity.update({
                    'user': email,
                    'filename': filename,
                    'url': blob.public_url,
                    'image_type': image_type,
                    'image_size': blob.size
                })
                client.put(image_entity)

        return render(request, 'success.html')

    return redirect('index')


def get_image(request, filename):
    blob = storage.Blob(filename, bucket)
    image_data = blob.download_as_bytes()
    return FileResponse(image_data, as_attachment=True, filename=filename)


def download_image(request, filename):
    blob = storage.Blob(filename, bucket)
    image_data = blob.download_as_bytes()
    return FileResponse(image_data, as_attachment=True, filename=filename)

def custom_logout(request):
    response = redirect('/login/')
    response.set_cookie('jwt', '@@@')
    return response
