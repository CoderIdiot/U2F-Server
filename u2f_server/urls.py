from django.conf.urls import url
from django.http import JsonResponse
from . import views

urlpatterns = [
    url(r'enroll', views.enroll),
	url(r'com_register', views.com_register),
	url(r'sign', views.sign),
	url(r'com_auth', views.com_auth),
]

