from django.conf.urls import url
from django.http import JsonResponse
from . import views

urlpatterns = [
	url(r'testApp1', views.testView1),
	url(r'testApp2', views.testView2)
]

