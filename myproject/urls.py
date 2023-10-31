# myapp/urls.py

from django.urls import path
from django.contrib.auth.views import LogoutView
from myapp import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('login/', views.login, name='login'),
    path('', views.index, name='index'),
    path('upload/', views.upload_files, name='upload_files'),
    path('image/<str:filename>/', views.get_image, name='get_image'),
    path('download/<str:filename>/', views.download_image, name='download_image'),
    path('logout/', views.custom_logout, name='logout'),
]
