from flask import Flask, request, session, url_for, redirect, abort, g, flash, _app_ctx_stack
import json

app = Flask(__name__)

game_started = False
clients = []
game_data = {}

@app.route('/')
def home_page():
	return 'hello'

@app.route('/attemptStart', methods=['POST'])
def establish_connection():
	if request.form['PlayerID'] not in clients:
		clients.append(request.form['PlayerID'])
	if len(clients) > 1:
		return 'go'
	return 'wait'

@app.route('/com', methods=['POST'])
def main_communicate():
	data = json.loads(request.form['data'])['data']
	for entry in data:
		game_data[entry['name']] = entry
	return json.dumps({'data':list(game_data.values())})