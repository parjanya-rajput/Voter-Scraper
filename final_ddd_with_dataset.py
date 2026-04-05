import requests
import ddddocr
import base64
import time
import json
import csv
import os
import random
import logging
import argparse
from typing import Optional
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

#python final_ddd_updated.py --input-csv voters_raipur.csv --start-row 1 --end-row 100

# Silence ddddocr
os.environ['COMMON_SAFE_ASCII'] = '1'
logging.getLogger('ddddocr').setLevel(logging.ERROR)
ocr = ddddocr.DdddOcr(
    ocr=False,              # typical if you're doing text captcha classification
    det=False,
    show_ad=False,
    import_onnx_path=r"captcha_voter_final.onnx",
    charsets_path=r"charsets.json"
)

# --- DATASET CONFIG ---
DATASET_DIR = "captcha_dataset_refined"
IMAGES_DIR = os.path.join(DATASET_DIR, "images")
LABELS_FILE = os.path.join(DATASET_DIR, "labels.txt")
os.makedirs(IMAGES_DIR, exist_ok=True)

# --- LOGGING SETUP ---
processing_logger = logging.getLogger("ProcessingLogger")
processing_logger.setLevel(logging.INFO)
processing_logger.propagate = False

processing_file_handler = logging.FileHandler("processing_errors.log", encoding='utf-8')
processing_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
processing_logger.addHandler(processing_file_handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
processing_logger.addHandler(console_handler)

# --- CONFIGURATION ---
INPUT_CSV = r"P:\Data Collection\voters_raipur.csv"
START_ROW = 1
END_ROW = None
FAILED_CSV = "failed_epics.csv"

URL_HOME = "https://electoralsearch.eci.gov.in/"
URL_CAPTCHA = "https://gateway-voters.eci.gov.in/api/v1/captcha-service/generateCaptcha"
URL_DETAILS = "https://gateway-voters.eci.gov.in/api/v1/elastic/search-by-epic-from-national-display-v1"

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-GB,en;q=0.6",
    "Content-Type": "application/json",
    "Origin": "https://electoralsearch.eci.gov.in",
    "Referer": "https://electoralsearch.eci.gov.in/",
    "applicationname": "ELECTORAL-SEARCH",
    "appname": "ELECTORAL-SEARCH",
    "channelidobo": "ELECTORAL-SEARCH",
    "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
    "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Brave";v="146"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"'
}

UA_LIST = [
    "Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36 Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
]

AO_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArb7++BxL/YN8OIln+6FL9Gnw5DNmQ/VFZXss+J+TuQyJc891JbqbijxYQNEin2c2u+CnpXpoGQ/1gUSzDMJeNS3sNSlIUykp2dt7xIm/cmV4sZ/c769vCxVRosMfRaZJnBAah+m1X26lEhnOo0wpAB9Txr8RIyBe6h7PiQWykeJeh6UacOBBX28kgkq7+vJhW8HgB38lt32XRocznRYwS9LqR7ZweFmQhTr1+EGrqiEKCOCxMYgHR2SQckb96hZ9kWzfzeun4bUO5oXKJciLkiS1IgKieADEvYLgu129ZIpn1H+8H+8ikNNVETqEDDMtqcQcQmWppJvcWHaXAs+f8QIDAQAB"


# --- NEW FUNCTION ---
def save_captcha_dataset(captcha_b64: str, label: str):
    try:
        img_bytes = base64.b64decode(captcha_b64)

        filename = f"{int(time.time()*1000)}_{random.randint(1000,9999)}.jpg"
        filepath = os.path.join(IMAGES_DIR, filename)

        with open(filepath, "wb") as f:
            f.write(img_bytes)

        with open(LABELS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{filename}\t{label}\n")

    except Exception as e:
        processing_logger.error(f"Dataset save failed: {e}")


def encrypt_payload(plain_payload: dict) -> dict:
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    payload_bytes = json.dumps(plain_payload, separators=(',', ':')).encode('utf-8')

    ciphertext, tag = cipher_aes.encrypt_and_digest(payload_bytes)

    encrypted_payload_bytes = ciphertext + tag
    encrypted_payload_b64 = base64.b64encode(encrypted_payload_bytes).decode('utf-8')

    public_key_der = base64.b64decode(AO_PUBLIC_KEY)
    rsa_key = RSA.import_key(public_key_der)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256.new())

    encrypted_key_bytes = cipher_rsa.encrypt(aes_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')

    return {
        "encryptedPayload": encrypted_payload_b64,
        "encryptedKey": encrypted_key_b64,
        "iv": base64.b64encode(iv).decode('utf-8')
    }


def save_to_csv(data: dict, filename="voter_data.csv"):
    file_exists = os.path.isfile(filename)

    with open(filename, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)


def log_failed_epic(epNo: str, reason: str):
    file_exists = os.path.isfile(FAILED_CSV)
    with open(FAILED_CSV, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["epic_number", "failure_reason"])
        writer.writerow([epNo, reason])


def log_processing_issue(epNo: str, reason: str):
    processing_logger.warning(f"EPIC {epNo} - {reason}")
    print(f"EPIC {epNo} - {reason}")


def new_session():
    s = requests.Session()
    s.get(URL_HOME, headers=HEADERS, timeout=10)
    return s


def is_english_alnum(s):
    return all(c.isascii() and c.isalnum() for c in s)


def extract_voter_data(epNo: str, state_code: str, max_retries: int = 5):
    session = new_session()

    attempt = 0
    while attempt < max_retries:
        try:
            resp = session.get(URL_CAPTCHA, headers=HEADERS, timeout=10)
            if resp.status_code != 200:
                processing_logger.warning(f"EPIC {epNo} - Attempt {attempt}: Captcha fetch failed")
                time.sleep(1)
                continue

            captcha_data = resp.json()
            ocr_attempts = 0
            captcha_text = ""

            while ocr_attempts < 5:
                try:
                    text = ocr.classification(base64.b64decode(captcha_data["captcha"]))
                    captcha_text = text

                    if text and is_english_alnum(text) and len(text) == 6:
                        break

                except Exception as e:
                    processing_logger.error(f"OCR error: {e}")
                    print(f"OCR error: {e}")

                ocr_attempts += 1

            if not (captcha_text and is_english_alnum(captcha_text) and len(captcha_text) == 6):
                continue

            plain_payload = {
                "captchaData": captcha_text,
                "captchaId": captcha_data["id"],
                "epicNumber": epNo,
                "isPortal": "true",
                "securityKey": "na",
                "stateCd": state_code
            }

            secure_payload = encrypt_payload(plain_payload)

            headers = {
                **HEADERS,
                "User-Agent": random.choice(UA_LIST)
            }

            details_resp = session.post(URL_DETAILS, json=secure_payload, headers=headers, timeout=15)

            if details_resp.status_code == 200:
                save_captcha_dataset(captcha_data["captcha"], captcha_text)
                results = details_resp.json()
                if results and len(results) > 0:
                    voter_info = results[0].get("content", {})
                    save_to_csv(voter_info)
                    processing_logger.info(f"EPIC {epNo} - Success: Extracted data for {voter_info.get('fullName')}")
                    return True, "Success"
                else:
                    return False, "Record not found"

            elif details_resp.status_code == 429:
                session = new_session()
                time.sleep(2)
                continue

            attempt += 1

        except Exception as e:
            processing_logger.error(f"Exception: {e}")

    return False, "Max retries exceeded"


def load_epics_from_csv(input_csv: str, start_row: int = 1, end_row: Optional[int] = None):
    epics_to_process = []

    with open(input_csv, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            if i < start_row:
                continue
            if end_row is not None and i > end_row:
                break
            epic = row.get("epic_number", "").strip()
            if epic:
                epics_to_process.append(epic)

    return epics_to_process


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv", default=INPUT_CSV)
    parser.add_argument("--start-row", type=int, default=START_ROW)
    parser.add_argument("--end-row", type=int, default=END_ROW)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    epics_to_process = load_epics_from_csv(args.input_csv, args.start_row, args.end_row)

    for epic in epics_to_process:
        success, reason = extract_voter_data(epic, "S28")

        if not success:
            if reason == "Record not found":
                log_failed_epic(epic, "Incorrect epic number")
            else:
                log_processing_issue(epic, reason)