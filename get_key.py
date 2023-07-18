from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import requests
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Step 1: Open Chrome and save the cookies
chrome_options = Options()
chrome_options.add_argument("--headless")  # To run Chrome in headless mode
driver = webdriver.Chrome(options=chrome_options)

driver.get("https://localhost:3443")
cookies = driver.get_cookies()

# Step 2: Send POST request to login and get the authentication cookies and headers
login_url = "https://localhost:3443/api/v1/me/login"
payload = {
    "email": "admin@admin.com",
    "password": "3b612c75a7b5048a435fb6ec81e52ff92d6d795a8b5a9c17070f6a63c97a53b2", #MD5 Hashed Password (To get this, open acunetix in browser and intercept the login request)
    "logout_previous": True,
    "remember_me": True
}
response = requests.post(login_url, json=payload, cookies=cookies, verify=False)

auth_cookies = response.cookies
x_auth_header = response.headers.get("X-Auth")

# Step 3: Send POST request to get the API key
api_key_url = "https://localhost:3443/api/v1/me/credentials/api-key"
headers = {"X-Auth": x_auth_header}
response = requests.post(api_key_url, json={}, cookies=auth_cookies, headers=headers, verify=False)

# Step 4: Extract the api_key value
api_key = response.json()["api_key"]

# Step 5: Show the api_key in the terminal
print(api_key)

# Close the browser
driver.quit()
