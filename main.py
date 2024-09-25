import requests
import json


def load_waf_signatures(file_path="waf_signatures.json"):
    with open(file_path, 'r') as file:
        return json.load(file)

payloads = ["' OR 1=1 --", "<script>alert(1)</script>", "../../../etc/passwd", "UNION SELECT"]
special_headers = ["x-waf", "x-security", "server", "x-powered-by", "x-secure-response"]


def ensure_http(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def detect_waf(url, waf_signatures):
    url = ensure_http(url)

    try:
        response = requests.get(url)
        headers = response.headers
        detected_waf = False

        for waf, signature in waf_signatures.items():
            if signature.lower() in str(headers).lower():
                print(f"WAF Detected: {waf}")
                detected_waf = True
                return waf

        for header in special_headers:
            if any(header in key.lower() for key in headers.keys()):
                print(f"Possible WAF Detected: {header} present in headers")
                detected_waf = True

        for payload in payloads:
            test_url = url + f"?q={payload}"
            test_response = requests.get(test_url)
            if test_response.status_code in [403, 406, 503]:
                print(f"WAF might be blocking this request with payload: {payload}")
                detected_waf = True
                break
            if "block" in test_response.text.lower() or "forbidden" in test_response.text.lower():
                print(f"Potential WAF Block Detected in response for payload: {payload}")
                detected_waf = True
                break

        if not detected_waf:
            print("No WAF detected")
        return None
    except Exception as e:
        print(f"Error occurred: {e}")


def main():
    waf_signatures = load_waf_signatures()

    while True:
        user_url = input("Enter the URL of the website to scan: ")
        detect_waf(user_url, waf_signatures)

        again = input("Would you like to make a new scan? (y/n): ").strip().lower()
        if again != 'y':
            print("Exiting the program...")
            break


if __name__ == "__main__":
    main()