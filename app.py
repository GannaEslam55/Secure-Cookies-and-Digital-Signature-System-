from flask import Flask, request, make_response
import hmac
import hashlib
import time

app = Flask(__name__)

# السر الخاص بالـ HMAC
SECRET_KEY = b'my_super_secret_key'  # خلي المفتاح ده على السيرفر بس

# صفحة login بسيطة
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # مثال للتجربة: user/password
    if username == 'user' and password == 'password':
        role = 'admin'
        expires = int(time.time()) + 60*5  # 5 دقائق

        # إنشاء الـ cookie payload
        cookie_payload = f"{username}|{role}|{expires}"

        # إنشاء الـ HMAC
        mac = hmac.new(SECRET_KEY, cookie_payload.encode(), hashlib.sha256).hexdigest()

        # إعداد response
        resp = make_response(f"Logged in! Cookie set for {username}")
        resp.set_cookie('auth_cookie', cookie_payload)
        resp.set_cookie('auth_mac', mac)
        return resp
    else:
        return "Invalid credentials!", 401

# صفحة محمية
@app.route('/protected')
def protected():
    cookie_payload = request.cookies.get('auth_cookie')
    cookie_mac = request.cookies.get('auth_mac')

    if not cookie_payload or not cookie_mac:
        return "No cookie, access denied!", 403

    # إعادة حساب الـ HMAC
    expected_mac = hmac.new(SECRET_KEY, cookie_payload.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_mac, cookie_mac):
        return "Tampering detected! Access denied!", 403

    return f"Access granted! Cookie payload: {cookie_payload}"

@app.route('/')
def home():
    return "Server is running 🚀"
@app.route('/login_form')
def login_form():
    return '''
    <form method="POST" action="/login">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    '''
if __name__ == '__main__':
    app.run(debug=True)