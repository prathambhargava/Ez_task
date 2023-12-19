from django.contrib import admin
from django.urls import path
from .views import *

urlpatterns = [
    path('', LoginView.as_view(),name='Login'),
    path('UploadFileView', UploadFileView.as_view(),name='upload'),
    path('signup', SignupView.as_view(),name='sign'),
    path('verifyemail', VerifyEmailView.as_view(),name='verify'),
    path('login', LoginView.as_view(),name='login'),
    path('download', DownloadFileView.as_view(),name='download'), 
    path('list', ListFilesView.as_view(),name='list'), 
    path('generateurl', GenerateDownloadURLView.as_view(),name='generate'),  
    
]