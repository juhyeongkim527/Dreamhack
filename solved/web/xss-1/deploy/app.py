#!/usr/bin/python3
from flask import Flask, request, render_template
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
        # return str(e)
        return False
    driver.quit()
    return True


def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")  # 이용자가 입력한 vuln 인자를 가져옴 : URL에서 `"param"` 문자열의 값을 찾고, 없으면 `""` 공백을 저장
    return param  # 이용자의 입력값을 화면 상에 표시 : HTML 엔티티 코드로 변환하지 않음


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route("/memo")  # memo 페이지 라우팅
def memo():  # memo 함수 선언
    global memo_text  # 메모를 전역변수로 참조
    text = request.args.get("memo", "")  # 이용자가 전송한 memo 입력값을 가져옴
    memo_text += text + "\n"  # 이용자가 전송한 memo 입력값을 memo_text에 추가
    # 사이트에 기록된 memo_text를 화면에 출력 : render_templete으로 HTML 엔티티 코드로 변환
    return render_template("memo.html", memo=memo_text)


app.run(host="0.0.0.0", port=8000)
