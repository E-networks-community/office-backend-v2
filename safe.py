import requests

url = "https://api.sandbox.safehavenmfb.com/oauth2/token"

payload = {
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_id": "b98e002d27a231b19338cbb80e8a65c3",
    "client_assertion": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJzdWIiOiJiOThlMDAyZDI3YTIzMWIxOTMzOGNiYjgwZThhNjVjMyIsImF1ZCI6Imh0dHBzOi8vYXBpLnNhbmRib3guc2FmZWhhdmVubWZiLmNvbS8iLCJpYXQiOjE3MjI0MzIzOTQsImV4cCI6IjE3MjMyOTYyNDgifQ.PiFBhJAhPKNviSGIBAzzEhnE7rUSVmB0PnYJCKaLQ91GHDzSTZ1UG3asDbfWUdx6uJYz2nv47WSgFBbiHLQ2EjO91qvOZGCMNIbK9WGzUch0tWSxRJTd8V9UjZszdhkte7o59AU5q1MMJ0uvEyXJoTkROOf03ze2L3tkYJUepwM"
}
headers = {
    "accept": "application/json",
    "content-type": "application/json"
}

response = requests.post(url, json=payload, headers=headers)

print(response.text)    