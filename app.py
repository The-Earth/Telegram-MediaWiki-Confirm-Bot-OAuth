# -*- coding: utf-8 -*-
#
# This file is originated from the Toolforge Flask + OAuth WSGI tutorial
# <https://wikitech.wikimedia.org/wiki/Help:Toolforge/My_first_Flask_OAuth_tool>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import flask
from flask import Flask, request
import mwoauth
import json
import os


app = Flask(__name__)
config = json.load(open('config.json', 'r', encoding='utf-8'))
app.secret_key = os.urandom(16)


@app.get('/')
def index():
    return flask.make_response('Restart your authentication at the Telegram bot you were using.', 400)


@app.get('/auth')
def auth():
    consumer_token = mwoauth.ConsumerToken(
        config['oauth_consumer_token'], config['oauth_secret_token']
    )
    telegram_id = request.args.get('id', default='0', type=str)
    if telegram_id == '0':
        return flask.make_response('Restart your authentication at the Telegram bot you were using.', 400)

    try:
        redirect, request_token = mwoauth.initiate(
            config['oauth_mwurl'], consumer_token)
    except Exception:
        app.logger.exception('OAuth initiate failed, contact operator.')
        return flask.make_response('OAuth initiate failed, contact operator.', 500)
    else:
        flask.session['request_token'] = dict(zip(
            request_token._fields, request_token))
        flask.session['telegram_id'] = telegram_id
        return flask.redirect(redirect)


@app.get('/callback')
def oauth_callback():
    """OAuth handshake callback."""
    if 'request_token' not in flask.session or 'telegram_id' not in flask.session:
        flask.flash('OAuth callback failed. Are cookies disabled?')
        return flask.make_response('OAuth callback failed. Are cookies disabled?', 400)

    consumer_token = mwoauth.ConsumerToken(
        config['oauth_consumer_token'], config['oauth_secret_token']
    )

    try:
        access_token = mwoauth.complete(
            config['oauth_mwurl'],
            consumer_token,
            mwoauth.RequestToken(**flask.session['request_token']),
            request.query_string)

        identity = mwoauth.identify(
            config['oauth_mwurl'], consumer_token, access_token)
    except Exception:
        app.logger.exception('OAuth authentication failed')
        return flask.make_response('OAuth authentication failed', 400)
    else:
        flask.session['access_token'] = dict(zip(
            access_token._fields, access_token))
        flask.session['username'] = identity['username']

        if os.path.isfile(config['record']):
            record = json.load(open(config['record'], 'r', encoding='utf-8'))
        else:
            record = {}

        telegram_id = flask.session['telegram_id']
        record[telegram_id] = identity['sub']   # wikimedia user id
        to_delete = [key for key in record if record[key] == identity['sub'] and key != telegram_id]
        for key in to_delete:
            del record[key]

        json.dump(record, open(config['record'], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        return f'OAuth callback succeeded. You may close this window now.'


@app.post('/query')
def query():
    """
    Expected post data: {'query_key': 'xxx', 'telegram_id': '123456'}
    Expected response data: {'ok': True, 'telegram_id': '123456', 'username': 'yyyyyy'}
    or {'ok': False, 'message': 'What's wrong.'}
    """
    if not request.json:
        return flask.make_response({}, 403)
    if type(request.json) is not dict:
        return flask.make_response({}, 403)
    if 'query_key' not in request.json:
        return flask.make_response({}, 403)
    if request.json['query_key'] != config['query_key']:
        return flask.make_response({}, 403)

    if 'telegram_id' not in request.json:
        return flask.make_response({'ok': False, 'message': 'No Telegram id given'}, 400)

    record = json.load(open(config['record'], 'r', encoding='utf-8'))
    if request.json['telegram_id'] in record:
        return {'ok': True, 'telegram_id': request.json['telegram_id'], 'mw_id': record[request.json['telegram_id']]}
    else:
        return flask.make_response({'ok': False, 'message': f'No record found for {request.json["telegram_id"]}.'}, 404)
