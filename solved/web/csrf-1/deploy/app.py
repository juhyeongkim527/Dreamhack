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
    cookie.update({"domain": "127.0.0.1"})  # 관리자 쿠키가 적용되는 범위를 127.0.0.1로 제한되도록 설정
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()  # 크롬 옵션을 사용하도록 설정
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)  # 크롬 브라우저 옵션 설정
        driver = webdriver.Chrome(service=service, options=options)  # 셀레늄에서 크롬 브라우저 사용
        driver.implicitly_wait(3)   # 크롬 로딩타임을 위한 타임아웃 3초 설정
        driver.set_page_load_timeout(3)  # 페이지가 오픈되는 타임아웃 시간 3초 설정
        driver.get("http://127.0.0.1:8000/")    # 관리자가 CSRF-1 문제 사이트 접속
        driver.add_cookie(cookie)   # 관리자 쿠키 적용
        driver.get(url)  # 인자로 전달된 url에 접속
    except Exception as e:
        driver.quit()   # 셀레늄 종료
        print(str(e))
        # return str(e)
        return False    # 접속 중 오류가 발생하면 비정상 종료 처리
    driver.quit()   # 셀레늄 종료
    return True  # 정상 종료 처리


def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"  # 로컬 URL 설정
    return read_url(url, cookie)  # URL 방문


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vuln")  # vuln 페이지 라우팅 (이용자가 /vuln 페이지에 접근시 아래 코드 실행)
def vuln():
    param = request.args.get("param", "").lower()   # 이용자가 입력한 param 파라미터를 소문자로 변경
    xss_filter = ["frame", "script", "on"]  # 세 가지 필터링 키워드
    for _ in xss_filter:
        param = param.replace(_, "*")   # 이용자가 입력한 값 중에 필터링 키워드가 있는 경우, '*'로 치환
    return param    # 이용자의 입력 값을 화면 상에 표시


@app.route("/flag", methods=["GET", "POST"])    # flag 페이지 라우팅 (GET, POST 요청을 모두 받음)
def flag():
    if request.method == "GET":  # 이용자의 요청이 GET 메소드인 경우
        return render_template("flag.html")  # 이용자에게 링크를 입력받는 화면을 출력
    elif request.method == "POST":  # 이용자의 요청이 POST 메소드인 경우
        param = request.form.get("param", "")   # param 파라미터를 가져온 후,
        if not check_csrf(param):   # 관리자에게 접속 요청 (check_csrf 함수)
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route('/memo')  # memo 페이지 라우팅
def memo():  # memo 함수 선언
    global memo_text  # 메모를 전역변수로 참조
    text = request.args.get('memo', '')  # 이용자가 전송한 memo 입력값을 가져옴
    memo_text += text + '\n'  # 메모의 마지막에 새 줄 삽입 후 메모에 기록
    return render_template('memo.html', memo=memo_text)  # 사이트에 기록된 메모를 화면에 출력


@app.route('/admin/notice_flag')  # notice_flag 페이지 라우팅
def admin_notice_flag():
    global memo_text  # 메모를 전역변수로 참조
    if request.remote_addr != '127.0.0.1':  # 이용자의 IP가 로컬호스트가 아닌 경우
        return 'Access Denied'  # 접근 제한
    if request.args.get('userid', '') != 'admin':  # userid 파라미터가 admin이 아닌 경우
        return 'Access Denied 2'  # 접근 제한
    memo_text += f'[Notice] flag is {FLAG}\n'  # 위의 조건을 만족한 경우 메모에 FLAG 기록
    return 'Ok'  # Ok 반환


app.run(host="0.0.0.0", port=8000)
