#!/usr/bin/env python3
from flask import Flask, request
import os

app = Flask(__name__)


@app.route('/', methods=['GET'])  # GET 만 등록되어있는데, 어떻게 else에서 다른 메소드로 요청이 오는지?
def index():
    cmd = request.args.get('cmd', '')
    if not cmd:
        return "?cmd=[cmd]"

    if request.method == 'GET':
        ''
    else:
        os.system(cmd)
    return cmd


app.run(host='0.0.0.0', port=8000)
