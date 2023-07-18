# acunetix-api [unofficial]
Acunetix unofficial API with report generation and Slack notification capabilities. [Requires Acunetix License]

Note: Change ```slack_token``` and ```slack_channel``` in start.py before running the script. The generated report will be sent to your Slack channel.

# prerequisites
```
pip3 install slack_sdk
pip3 install selenium
```
# Usage

General Usage
```
python3 start.py --api_key ACUNETIX_API_KEY_HERE --target http://testphp.vulnweb.com
```
To generate Acunetix API Key:

```
python3 get_key.py
```

To generate Acunetix API Key & Start full scan on the provided URL:
```
export API_KEY=$(python3 get_key.py) && python3 start.py --api_key $API_KEY --target http://testphp.vulnweb.com
```

To generate Acunetix API Key & Start 20 parallel scans on the provided URL (Requires https://github.com/shenwei356/rush):
```
export API_KEY=$(python3 get_key.py) && cat input_urls.txt | rush -j20 'python3 start.py --api_key $API_KEY --target {}'
```


