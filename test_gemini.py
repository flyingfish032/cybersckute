from dotenv import load_dotenv
load_dotenv()
import os
from google import genai

key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=key)

# Test with correct model name format
models_to_try = [
    "models/gemini-2.0-flash-lite",
    "models/gemini-2.0-flash",
    "models/gemini-2.5-flash",
]

for m in models_to_try:
    try:
        response = client.models.generate_content(model=m, contents="Say hello in one word.")
        print(f"SUCCESS with {m}: {response.text.strip()}")
        break
    except Exception as e:
        err = str(e)
        if "429" in err:
            print(f"QUOTA EXHAUSTED: {m}")
        elif "404" in err:
            print(f"NOT FOUND: {m}")
        else:
            print(f"ERROR ({m}): {type(e).__name__}: {err[:200]}")
