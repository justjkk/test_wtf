from flask import Flask, request, render_template, jsonify
from flask.ext.wtf import Form as WTForm
# from flask.ext.wtf.csrf import CsrfProtect
from wtforms import TextField
from wtforms.validators import Required

import pickle
from datetime import timedelta
from uuid import uuid4
from redis import Redis
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin


class RedisSession(CallbackDict, SessionMixin):

    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False


class RedisSessionInterface(SessionInterface):
    serializer = pickle
    session_class = RedisSession

    def __init__(self, redis=None, prefix='session:'):
        if redis is None:
            redis = Redis()
        self.redis = redis
        self.prefix = prefix

    def generate_sid(self):
        return str(uuid4())

    def get_redis_expiration_time(self, app, session):
        if session.permanent:
            return app.permanent_session_lifetime
        return timedelta(days=1)

    def open_session(self, app, request):
        sid = request.headers.get('X-Auth-Token')
        if not sid:
            sid = request.cookies.get(app.session_cookie_name)
            request.session_header = False
        else:
            request.session_header = True
        if not sid:
            sid = self.generate_sid()
            return self.session_class(sid=sid, new=True)
        val = self.redis.get(self.prefix + sid)
        if val is not None:
            data = self.serializer.loads(val)
            return self.session_class(data, sid=sid)
        return self.session_class(sid=sid, new=True)

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        if not session:
            self.redis.delete(self.prefix + session.sid)
            if session.modified:
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain)
            return
        redis_exp = self.get_redis_expiration_time(app, session)
        cookie_exp = self.get_expiration_time(app, session)
        val = self.serializer.dumps(dict(session))
        self.redis.setex(self.prefix + session.sid, val,
                         int(redis_exp.total_seconds()))
        response.set_cookie(app.session_cookie_name, session.sid,
                            expires=cookie_exp, httponly=True,
                            domain=domain)


class Form(WTForm):
    def __init__(self, *args, **kwargs):
        if 'csrf_enabled' not in kwargs:
            kwargs['csrf_enabled'] = not request.session_header
        super(Form, self).__init__(*args, **kwargs)


class NameForm(Form):
    name = TextField('name')


app = Flask(__name__)
app.secret_key = 'ksjdflksdfjsdhfsdfsd'
app.session_interface = RedisSessionInterface()
# app.config['WTF_CSRF_ENABLED'] = False

# CsrfProtect(app)


def request_wants_json():
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
        request.accept_mimetypes[best] > \
        request.accept_mimetypes['text/html']


@app.route("/", methods=['GET', 'POST'])
def route():
    print request.headers
    form = NameForm(request.form)

    if form.validate_on_submit():
        if request_wants_json():
            return jsonify({'message': 'Hello ' + form.name.data + '!'})
        else:
            return render_template('hello.html', form=form,
                                   name=form.name.data)
    if form.errors:
        if request_wants_json():
            return jsonify(form.errors), 400
        else:
            return render_template('hello.html', form=form), 400

    if request_wants_json():
        return jsonify({'name': form.name.data})
    else:
        return render_template('hello.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
