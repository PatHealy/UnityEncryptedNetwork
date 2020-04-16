from flask import Flask, request, session, url_for, redirect, abort, g, flash, _app_ctx_stack
import json
from base64 import b64encode
# PyCrypto package
from Crypto.Cipher import AES, DES, DES3, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Util.py3compat import *

from math import log

CHUNK_SIZE = 128

def bytes_needed(n):
	if n == 0:
		return 1
	return int(log(n, 256)) + 1

app = Flask(__name__)

game_started = False
clients = []
game_data = {}
players = {}
valid_moves = {1:['Player'], 2:['CPU']}

# Pad and unpad function taken from PyCrypto repository. For some reason they aren't included in the released package
def pad(data_to_pad, block_size, style='pkcs7'):
	padding_len = block_size-len(data_to_pad)%block_size
	if style == 'pkcs7':
		padding = bchr(padding_len)*padding_len
	elif style == 'x923':
		padding = bchr(0)*(padding_len-1) + bchr(padding_len)
	elif style == 'iso7816':
		padding = bchr(128) + bchr(0)*(padding_len-1)
	else:
		raise ValueError("Unknown padding style")
	return data_to_pad + padding

def unpad(padded_data, block_size, style='pkcs7'):
	pdata_len = len(padded_data)
	if pdata_len % block_size:
		raise ValueError("Input data is not padded")
	if style in ('pkcs7', 'x923'):
		padding_len = bord(padded_data[-1])
		if padding_len<1 or padding_len>min(block_size, pdata_len):
			raise ValueError("Padding is incorrect.")
		if style == 'pkcs7':
			if padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
				raise ValueError("PKCS#7 padding is incorrect.")
		else:
			if padded_data[-padding_len:-1]!=bchr(0)*(padding_len-1):
				raise ValueError("ANSI X.923 padding is incorrect.")
	elif style == 'iso7816':
		padding_len = pdata_len - padded_data.rfind(bchr(128))
		if padding_len<1 or padding_len>min(block_size, pdata_len):
			raise ValueError("Padding is incorrect.")
		if padding_len>1 and padded_data[1-padding_len:]!=bchr(0)*(padding_len-1):
			raise ValueError("ISO 7816-4 padding is incorrect.")
	else:
		raise ValueError("Unknown padding style")
	return padded_data[:-padding_len]

# Generate RSA key-pair
RSA_key_pair = RSA.generate(2048)
RSA_key_data = {}
RSA_key_data['n'] = list(RSA_key_pair.n.to_bytes(bytes_needed(RSA_key_pair.n), 'big'))
RSA_key_data['e'] = list(RSA_key_pair.e.to_bytes(bytes_needed(RSA_key_pair.e), 'big'))

RSA_cipher = PKCS1_OAEP.new(RSA_key_pair)

#RSA_large_pair = RSA.generate(8192)
#RSA_large_key_data = {}
#RSA_large_key_data['n'] = list(RSA_large_pair.n.to_bytes(bytes_needed(RSA_large_pair.n), 'big'))
#RSA_large_key_data['e'] = list(RSA_large_pair.e.to_bytes(bytes_needed(RSA_large_pair.e), 'big'))

#RSA_large_cipher = PKCS1_OAEP.new(RSA_large_pair)

#message = b64encode(b'Test message')
#cipher = PKCS1_OAEP.new(RSA_key_pair)
#ciphertext = RSA_decrypter.encrypt(message)
#print(ciphertext)
#plain = cipher.decrypt(ciphertext)

#print(message)
#print(ciphertext)
#print(plain)

key_AES = b'AAAAAAAAAAAAAAAA'
iv_aes = Random.new().read(16)

key_DES = b'AAAAAAAA'
iv_des = Random.new().read(DES.block_size)
#des_cipher = DES.new(key_DES, DES.MODE_CBC, iv_des)
#plaintext = pad(b'sona si latine loqueris', 16)
#msg = des_cipher.encrypt(plaintext)
#cipher2 = DES.new(key_DES, DES.MODE_CBC, iv_des)
#print(unpad(cipher2.decrypt(msg),16))

key_DES3 = b'AAAAAAAAAAAAAAAA'
iv_des3 = Random.new().read(DES3.block_size)
#des3_cipher = DES3.new(key_DES3, DES3.MODE_CBC, iv_des3)
#plaintext = pad(b'sona si latine loqueris', 16)
#msg = des3_cipher.encrypt(plaintext)
#cipher2 = DES3.new(key_DES3, DES3.MODE_CBC, iv_des3)
#print(unpad(cipher2.decrypt(msg),16))

key_blowfish = b'An arbitrarily long key'
iv_blowfish = Random.new().read(Blowfish.block_size)
#blowfish_cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
#plaintext = b'docendo discimus '
#msg = cipher.encrypt(pad(plaintext, 8))
#cipher2 = Blowfish.new(key, Blowfish.MODE_CBC, iv)
#plain = unpad(cipher2.decrypt(msg), 8)
#print(plain)


private_keys = {
	'AES': {'key': list(key_AES), 'iv': list(iv_aes)},
	'DES': {'key': list(key_DES), 'iv': list(iv_des)},
	'DES3': {'key': list(key_DES3), 'iv': list(iv_des3)},
	'Blowfish': {'key': list(key_blowfish), 'iv': list(iv_blowfish)},
	'None': {'key': list(b'na'), 'iv': list(b'na')},
	'RSA': {'key': list(b'na'), 'iv': list(b'na')}
}

def chunk_string(plaintext, chunk_size):
	return [plaintext[i:i+chunk_size] for i in range(0, len(plaintext), chunk_size)]

def unchunk(chunks):
	unchunked = ""
	for chunk in chunks:
		unchunked = unchunked + chunk
	return unchunked

def encrypt(plaintext, playerNum):
	method = players[playerNum]['method']

	if method == "AES":
		encrypted = list(players[playerNum]['cipher'].encrypt(pad(bytes(plaintext, 'utf-8'), 16)))
		return {'datas': [{'data': encrypted}]}
	elif method == "DES":
		return plaintext
	elif method == "DES3":
		return plaintext
	elif method == "Blowfish":
		return plaintext
	elif method == "RSA":
		return RSA_encrypt(plaintext, players[playerNum]['RSA'])
	else:
		encrypted = list(bytes(plaintext, 'utf-8'))
		return {'datas': [{'data': encrypted}]}

def decrypt(ciphertext, playerNum):
	method = players[playerNum]['method']
	data = ciphertext['datas'][0]['data']

	if method == "AES":
		decrypted = unpad(players[playerNum]['cipher'].decrypt(bytes(data)), 16).decode('utf-8')
		return decrypted
	elif method == "DES":
		return ciphertext
	elif method == "DES3":
		return ciphertext
	elif method == "Blowfish":
		return ciphertext
	elif method == "RSA":
		return RSA_decrypt(ciphertext)
	else:
		return bytes(data).decode('utf-8')

def RSA_encrypt(plaintext, cipher):
	chunked = chunk_string(plaintext, CHUNK_SIZE)
	ciphertext_blocks = []

	for chunk in chunked:
		block = {'data': list(cipher.encrypt(bytes(chunk, 'utf-8')))}
		ciphertext_blocks.append(block)

	return {'datas':ciphertext_blocks}

def RSA_decrypt(ciphertext_blocks):
	chunked = []

	for block in ciphertext_blocks['datas']:
		chunked.append(RSA_cipher.decrypt(bytes(block['data'])).decode('utf-8'))

	return unchunk(chunked)

@app.route('/publicKey')
def get_public_key():
	return json.dumps(RSA_key_data)

@app.route('/privateKeys', methods=['POST'])
def get_private_keys():
	data = RSA_decrypt(json.loads(request.form['data']))
	clientData = json.loads(data)

	playerNum = clientData['playerNum']
	playerMethod = clientData['method']
	playerE = int.from_bytes(clientData['e'], byteorder='big', signed=False)
	playerN = int.from_bytes(clientData['n'], byteorder='big', signed=False)

	player_dict = {}
	player_dict['method'] = playerMethod
	player_dict['RSA'] = PKCS1_OAEP.new(RSA.construct((playerN, playerE)))

	if playerMethod == 'AES':
		player_dict['cipher'] = AES.new(key_AES, AES.MODE_ECB)
	elif playerMethod == 'DES':
		player_dict['out_cipher'] = DES.new(key_DES, DES.MODE_CBC, iv_des)
		player_dict['in_cipher'] = DES.new(key_DES, DES.MODE_CBC, iv_des)
	elif playerMethod == 'DES3':
		player_dict['out_cipher'] = DES3.new(key_DES3, DES3.MODE_CBC, iv_des3)
		player_dict['in_cipher'] = DES3.new(key_DES3, DES3.MODE_CBC, iv_des3)
	elif playerMethod == 'Blowfish':
		player_dict['out_cipher'] = Blowfish.new(key_blowfish, Blowfish.MODE_CBC, iv_blowfish)
		player_dict['in_cipher'] = Blowfish.new(key_blowfish, Blowfish.MODE_CBC, iv_blowfish)

	players[playerNum] = player_dict

	encrypted_message = RSA_encrypt(json.dumps(private_keys[playerMethod]), players[playerNum]['RSA'])

	return json.dumps(encrypted_message)

@app.route('/attemptStart', methods=['POST'])
def establish_connection():
	if request.form['PlayerID'] not in clients:
		clients.append(request.form['PlayerID'])
	if len(clients) > 0:
		return 'go'
	return 'wait'

@app.route('/com', methods=['POST'])
def main_communicate():
	player_number = json.loads(request.form['data'])['playerNum']

	data = json.loads(decrypt(json.loads(request.form['data']), player_number))['data']

	for entry in data:
		if entry['name'] in valid_moves[player_number]:
			game_data[entry['name']] = entry
		else:
			print("Attempted cheat")

	return encrypt(json.dumps(game_data), player_number)

@app.route('/testEncryption', methods=['POST'])
def test_encryption():
	data = bytes(json.loads(request.form['test'])['data'])
	print(RSA_decrypter.decrypt(data).decode('utf-8'))
	return ""

@app.route('/getExample')
def get_example():
	return ciphertext


