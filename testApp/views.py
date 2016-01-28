from django.shortcuts import render
from django.http import JsonResponse
from M2Crypto import Rand,  EC
from hashlib import sha256
from base64 import urlsafe_b64decode, urlsafe_b64encode


from models import User

# Create your views here.
def testView1(request):
	user = User.objects.create(userName='andy', challenge='1234567890')
	user.save()
	return JsonResponse({'result':'test'})
	
	
def testView2(request):
	user = User.objects.get(userName='HaiChiang')
	print user.userName
	print user.challenge
	return JsonResponse({'result':'test'})