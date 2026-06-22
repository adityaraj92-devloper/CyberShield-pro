import requests

def check_sqli(domain):

    try:

        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1'
        ]

        for payload in payloads:

            url = f"https://{domain}?id={payload}"

            response = requests.get(
                url,
                timeout=5
            )

            errors = [
                "sql syntax",
                "mysql",
                "sqlite",
                "postgresql",
                "oracle",
                "database error"
            ]

            for error in errors:

                if error.lower() in response.text.lower():

                    return "❌ Vulnerable"

        return "✅ Safe"

    except:
        print("SQL ERROR =",e)
        return "⚠️ Unknown"