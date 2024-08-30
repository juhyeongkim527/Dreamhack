#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"

users = {
    'guest': 'guest',
    'admin': FLAG
}

session_storage = {}


def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        print(str(e))
        # return str(e)
        return False
    driver.quit()
    return True


def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not an admin"}')


@app.route("/vuln")
def vuln():
    param = request.args.get("param", "").lower()  # 이용자가 입력한 param 파라미터를 소문자로 변경
    xss_filter = ["frame", "script", "on"]  # 세 가지 필터링 키워드
    for _ in xss_filter:
        param = param.replace(_, "*")  # 이용자가 입력한 값 중에 필터링 키워드가 있는 경우, '*'로 치환
    return param


@app.route("/flag", methods=["GET", "POST"])  # flag 페이지 라우팅 (GET, POST 요청을 모두 받음)
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param", "")
        session_id = os.urandom(16).hex()  # 무작위 세션 ID 생성 후 16진수 문자열로 변환

        session_storage[session_id] = 'admin'  # 세션 ID를 키로 사용하여 'admin' 값을 session_storage 딕셔너리에 저장

        if not check_csrf(param, {"name": "sessionid", "value": session_id}):  # CSRF 토큰 (세션 ID)이 유효한지 확인
            return '<script>alert("wrong??");history.go(-1);</script>'
        return '<script>alert("good");history.go(-1);</script>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    elif request.method == 'POST':
        username = request.form.get('username')  # POST 요청의 form 데이터에서 'username'을 가져옴
        password = request.form.get('password')  # POST 요청의 form 데이터에서 'password'를 가져옴

        try:
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'  # 사용자가 존재하지 않는 경우 경고를 표시하고 이전 페이지로 이동

        if pw == password:
            resp = make_response(redirect(url_for('index')))
            session_id = os.urandom(8).hex()  # 무작위 세션 ID를 생성하고 16진수 문자열로 변환
            session_storage[session_id] = username  # 세션 ID를 키로 사용하여 현재 사용자를 'session_storage'에 저장
            resp.set_cookie('sessionid', session_id)  # 생성된 세션 ID를 쿠키로 설정하여 사용자에게 전달
            return resp    # 로그인이 성공한 경우 리디렉션 응답을 반환

        return '<script>alert("wrong password");history.go(-1);</script>'  # 비밀번호가 일치하지 않는 경우 경고를 표시 후 이전 페이지로 이동


@app.route("/change_password")
def change_password():
    pw = request.args.get("pw", "")
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')  # 세션 ID가 유효하지 않거나 세션을 찾을 수 없는 경우

    users[username] = pw  # 세션에 연결된 사용자의 비밀번호를 'pw'로 변경
    return 'Done'


app.run(host="0.0.0.0", port=8000)

# <img src="/change_password?pw=admin>