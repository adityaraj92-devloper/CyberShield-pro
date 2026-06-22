import requests

def check_xss(domain):

    payload = "<script>alert('XSS')</script>"

    try:

        url = "https://" + domain + "?search=" + payload

        response = requests.get(
            url,
            timeout=5
        )

        if payload in response.text:
            return "⚠️ Possible XSS"

        return "✅ Safe"

    except:
        return "Unknown"