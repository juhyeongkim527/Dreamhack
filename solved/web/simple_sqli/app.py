#!/usr/bin/python3
from flask import Flask, request, render_template, g
import sqlite3
import os
import binascii

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

DATABASE = "database.db"  # 데이터베이스 파일명을 database.db로 설정
if os.path.exists(DATABASE) == False:  # 데이터베이스 파일이 존재하지 않는 경우,
    db = sqlite3.connect(DATABASE)  # 데이터베이스 파일 생성 및 연결
    db.execute('create table users(userid char(100), userpassword char(100));')  # users 테이블 생성
    # users 테이블에 guest와 admin 계정(row) 생성
    db.execute(
        f'insert into users(userid, userpassword) values ("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
    db.commit()  # 쿼리 실행 확정
    db.close()  # DB 연결 종료


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def query_db(query, one=True):  # query_db 함수 선언
    cur = get_db().execute(query)  # 연결된 데이터베이스에 쿼리문을 질의
    rv = cur.fetchall()  # 쿼리문 내용을 받아오기
    cur.close()  # 데이터베이스 연결 종료
    return (rv[0] if rv else None) if one else rv  # 쿼리문 질의 내용에 대한 결과를 반환


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def index():
    return render_template('index.html')


# Login 기능에 대해 GET과 POST HTTP 요청을 받아 처리함
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 이용자가 GET 메소드의 요청을 전달한 경우,
    if request.method == 'GET':
        return render_template('login.html')  # 이용자에게 ID/PW를 요청받는 화면을 출력
    # POST 요청을 전달한 경우
    else:
        userid = request.form.get('userid')  # 이용자의 입력값인 userid를 받은 뒤,
        userpassword = request.form.get('userpassword')  # 이용자의 입력값인 userpassword를 받고
        # users 테이블에서 이용자가 입력한 userid와 userpassword가 일치하는 회원 정보를 불러옴
        res = query_db(
            f'select * from users where userid="{userid}" and userpassword="{userpassword}"'
        )

        if res:  # 쿼리 결과가 존재하는 경우
            userid = res[0]  # 로그인할 계정을 해당 쿼리 결과의 결과에서 불러와 사용

            if userid == 'admin':  # 이 때, 로그인 계정이 관리자 계정인 경우
                return f'hello {userid} flag is {FLAG}'  # flag를 출력

            # 관리자 계정이 아닌 경우, 웰컴 메시지만 출력
            return f'<script>alert("hello {userid}");history.go(-1);</script>'

        # 일치하는 회원 정보가 없는 경우 로그인 실패 메시지 출력
        return '<script>alert("wrong");history.go(-1);</script>'


app.run(host='0.0.0.0', port=8000)
