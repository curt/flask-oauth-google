from flask import Flask, redirect, url_for, session, render_template, json
from flask_oauth import OAuth

# app constants
SECRET_KEY = 'create a secret key'
DEBUG = True

# google oauth constants
GOOGLE_CLIENT_ID = 'get this from google'
GOOGLE_CLIENT_SECRET = 'get this from google'
REDIRECT_URI = '/oauth2callback'

# app initialize
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY

# oauth initialize
oauth = OAuth()
google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)
 
@app.route('/')
def index():
    data = None
    access_token = session.get('access_token')
    if access_token is not None:
        from urllib2 import Request, urlopen, HTTPError
    
        access_token = access_token[0]
        headers = {'Authorization': 'OAuth ' + access_token}
        req = Request('https://www.googleapis.com/oauth2/v2/userinfo',
                      None, headers)
        try:
            res = urlopen(req)
            data = json.load(res)
        except HTTPError, e:
            if e.code == 401:
                session.pop('access_token', None)
    return render_template('index.html', data = data)

@app.route('/signin')
def signin():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)
 
@app.route('/signout')
def signout():
    session.pop('access_token', None)
    return redirect(url_for('index'))
 
@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('index'))

@google.tokengetter
def get_access_token():
    return session.get('access_token')

# app run
if __name__ == '__main__':
    app.run()
