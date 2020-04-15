from flask import Flask, request, session, url_for, redirect, abort, g, flash, _app_ctx_stack
import json
from base64 import b64encode
# PyCrypto package
from Crypto.Cipher import AES, DES, DES3, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
#from Crypto.Util.Padding import pad, unpad

from math import log
def bytes_needed(n):
	if n == 0:
		return 1
	return int(log(n, 256)) + 1

app = Flask(__name__)

game_started = False
clients = []
game_data = {}

public_key = "AAAAAAA"

#Possible methods: None, AES, DES, DES3, Blowfish, RSA, DSA
method = "None"

# Generate RSA key-pair
RSA_key_pair = RSA.generate(2048)
RSA_key_data = {}
RSA_key_data['n'] = list(RSA_key_pair.n.to_bytes(bytes_needed(RSA_key_pair.n), 'big'))
RSA_key_data['e'] = list(RSA_key_pair.e.to_bytes(bytes_needed(RSA_key_pair.e), 'big'))

RSA_key_data['d'] = list(RSA_key_pair.d.to_bytes(bytes_needed(RSA_key_pair.d), 'big'))
RSA_key_data['p'] = list(RSA_key_pair.p.to_bytes(bytes_needed(RSA_key_pair.p), 'big'))
RSA_key_data['q'] = list(RSA_key_pair.q.to_bytes(bytes_needed(RSA_key_pair.q), 'big'))
RSA_key_data['u'] = list(RSA_key_pair.u.to_bytes(bytes_needed(RSA_key_pair.u), 'big'))

RSA_decrypter = PKCS1_OAEP.new(RSA_key_pair)

message = b64encode(b'Test message')
#cipher = PKCS1_OAEP.new(RSA_key_pair)
ciphertext = RSA_decrypter.encrypt(message)
#print(ciphertext)
#plain = cipher.decrypt(ciphertext)

#print(message)
#print(ciphertext)
#print(plain)

#key_AES = b'AAAAAAAAAAAAAAAA'
#aes_cipher = AES.new(key_AES, AES.MODE_CBC) #automatically generates iv
#aes_iv = b64encode(aes_cipher.iv).decode('utf-8')

def gege_encrypt(plaintext):
	pass

def gege_decrypt(ciphertext):
	pass

def encrypt(plaintext):
	if method == "AES":
		ct_bytes = aes_cipher.encrypt(pad(plaintext, AES.block_size))
		ct = b64encode(ct_bytes).decode('utf-8')
		return ct
	elif method == "DES":
		return plaintext
	elif method == "DES3":
		return plaintext
	elif method == "Blowfish":
		return plaintext
	elif method == "RSA":
		return RSA.encrypt(plaintext)
	else:
		return plaintext

def decrypt(ciphertext):
	if method == "AES":
		return ciphertext
	elif method == "DES":
		return ciphertext
	elif method == "DES3":
		return ciphertext
	elif method == "Blowfish":
		return ciphertext
	elif method == "RSA":
		return ciphertext
	else:
		return ciphertext

@app.route('/publicKey')
def get_public_key():
	return json.dumps(RSA_key_data)

@app.route('/privateKeys', methods=['POST'])
def get_private_keys():
	pass

@app.route('/attemptStart', methods=['POST'])
def establish_connection():
	if request.form['PlayerID'] not in clients:
		clients.append(request.form['PlayerID'])
	if len(clients) > 1:
		return 'go'
	return 'wait'

@app.route('/com', methods=['POST'])
def main_communicate():
	data = json.loads(decrypt(request.form['data']))['data']
	if authenticate(data):
		for entry in data:
			game_data[entry['name']] = entry
	return encrypt(json.dumps({'data':list(game_data.values())}))

@app.route('/testEncryption', methods=['POST'])
def test_encryption():
	data = bytes(json.loads(request.form['test'])['data'])
	print(data)
	print(RSA_decrypter.decrypt(data))

@app.route('/getExample')
def get_example():
	return ciphertext