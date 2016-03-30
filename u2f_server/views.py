from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from M2Crypto import Rand,  EC, X509, EVP, RSA, ASN1
from hashlib import sha256
from base64 import urlsafe_b64decode, urlsafe_b64encode

import os, json
from models import User
from utils import getClientIp

#debug
import types

# generate an enroll challenge
def gen_enroll_challenge():
	enrollRequest = {}
	
	enrollRequest['signrequest'] = []
	Rand.rand_seed(os.urandom(1024))
	challenge = urlsafe_b64encode(Rand.rand_bytes(32))
	enrollRequest['registerRequests'] = [{'challenge': 'mLkHCmQZGbZEXefhWByeKo5zTFldYLIZFRGeHdvTFBc=', 
				'version': 'U2F_V2', 'appId': 'http://localhost:8000'}]
	
	return enrollRequest, challenge

#
# URL processing function
#

def enroll(request):
	print 'LOG:enroll -------------- from ' +  getClientIp(request)
	
	enrollRequest, challenge = gen_enroll_challenge()
	
	#create a new user
	User.objects.filter(userName='HaiChiang').delete()
	user = User.objects.create(userName='HaiChiang', challenge=challenge)
	user.save()
	
	return JsonResponse(enrollRequest)

def com_register(request):
	print 'LOG:com_register -------------- from ' +  getClientIp(request)
	
	#the user HaiChiang is fixed in the database
	user = User.objects.get(userName='HaiChiang')
	print 'LOG:com_register --------------' +  user.challenge
	
	result = 0
	##check the client response
	if request.method == 'POST':
		data = json.loads(request.body)
		
		#
		#processing clientdata
		#
		
		#convert the clientdata to a dict structure
		clientdata = urlsafe_b64decode(data['clientData'].encode('utf-8'))
		clientdata_dict = eval(clientdata)
 		print 'LOG:clientData ------------- ' + clientdata
	
		
		#check the challenge
		#to do 
		if clientdata_dict['challenge'] != user.challenge.encode('utf-8'):
			#print 'LOG:challenge ------------- ' + clientdata_dict['challenge']
			#print type(clientdata_dict['challenge']), type(user.challenge.encode('utf-8'))
			pass
			
			#return HttpResponse(result)
		else:
			pass
		
		#check the origin
		#to do 
		if clientdata_dict['origin'] != 'http://xxxx':
			print 'LOG:origin ------------- ' + clientdata_dict['origin']
			pass
			
			#return HttpResponse(result)
		else:
			pass
		
		#check the types
		if clientdata_dict['typ'] != 'navigator.id.finishEnrollment':
			pass
			
			#return HttpResponse(result)
		else:
			pass
			
		
		#	
		#check the registrationdata
		#
		registrationdata =  urlsafe_b64decode(data['registrationData'].encode('utf-8'))
		
		
		#check the reserved byte 0x05
		if registrationdata[0:1].encode('hex') == '05':
			print 'LOG: ------------- 0x05 reserved byte checked'
		
			
		registrationdata = registrationdata[1:]
		#get the public key & store
		public_key = registrationdata[:65]
		print 'LOG:public key ------------- ' + public_key.encode('hex')
		#to do: store
		
		
		#get the key_handle & store
		registrationdata = registrationdata[65:]
		key_handle_len = registrationdata[:1]
		print 'LOG:key handle len ---------' + key_handle_len.encode('hex')
		key_handle = registrationdata[1:65]
		print 'LOG:key handle ----------' + key_handle.encode('hex')
		
		
		#get the attestation cert
		registrationdata = registrationdata[65:]
		cert = X509.load_cert_der_string(registrationdata)
		print 'LOG:attestation cert ----------' + registrationdata[:len(cert.as_der())].encode('hex')

		
		#get the signature & verify it
		registrationdata = registrationdata[len(cert.as_der()):]
		sig = registrationdata
		print 'LOG:signature ----------' + sig.encode('hex')
		
		h0 = sha256()
		h0.update('http://localhost:8000')
		app_para = h0.digest()
		print 'LOG:app_para --------' + app_para.encode('hex')
		 
		h1 = sha256()
		h1.update(str(clientdata))
		print type(str(clientdata)), str(clientdata)
		challen_para = h1.digest()
		print 'LOG:cha_para --------' + challen_para.encode('hex')
		
		
		msg = chr(0x00) + app_para + challen_para + key_handle + public_key


		# print len(app_para), len(challen_para), len(key_handle), len(public_key)

		
		puk = cert.get_pubkey()
		puk.reset_context('sha256')
		puk.verify_init()
		puk.verify_update(msg)
		result = puk.verify_final(sig)
		print result		
		
		
	User.objects.filter(userName='HaiChiang').delete()
	return HttpResponse(result)
	
def sign(request):
	#to do
	print 'LOG:sign -------------- from ' +  getClientIp(request)

	signRequest = {}
	
	key_handle = 'abc'
	Rand.rand_seed(os.urandom(1024))
	challenge = urlsafe_b64encode(Rand.rand_bytes(32))
	signRequest['signRequests'] = [{'challenge': 'mLkHCmQZGbZEXefhWByeKo5zTFldYLIZFRGeHdvTFBc=', 
				'version': 'U2F_V2', 'appId': 'http://localhost:8000', 'keyhanle': key_handle}]
				
	signRequest['registerRequests'] = []

	return JsonResponse(signRequest)

def com_auth(request):
	#to do 
	print 'LOG:com_auth -------------- from ' +  getClientIp(request)
	
	result = 0
	if request.method == 'POST':
		data = json.loads(request.body)
		
		#
		#processing keyhanle
		#
		keyhanle = urlsafe_b64decode(data['keyhanle'].encode('utf-8'))
 		print 'LOG:key_handle ------------- ' + key_handle
		 
		
		#
		#processing clientdata
		#
		
		#convert the clientdata to a dict structure
		clientdata = urlsafe_b64decode(data['clientData'].encode('utf-8'))
		clientdata_dict = eval(clientdata)
 		print 'LOG:clientData ------------- ' + clientdata
		 
		#
		#processing signature
		#
		signature = urlsafe_b64decode(data['signature'].encode('utf-8'))
		print 'LOG:signature ------------- ' + signature
		
	
	return HttpResponse(result)



