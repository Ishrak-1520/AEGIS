import os
import sys
from dotenv import load_dotenv
import openai

# 1. Load the API Key
load_dotenv()
api_key = os.getenv("SIFT_API_KEY")

print(f"--- API Connection Test ---")

if not api_key:
    print("❌ ERROR: SIFT_API_KEY is missing in your .env file.")
    sys.exit(1)

print(f"✅ API Key found: {api_key[:5]}...{api_key[-4:]}")

# 2. Configure the Client (This is likely where the error is)
# TRY THESE URLs IF THE FIRST ONE FAILS:
# Option A: "https://api.longcat.chat/v1" (Current)
# Option B: "https://api.longcat.chat"      (Try removing /v1)
# Option C: "https://longcat.chat/api/v1"   (Common alternative)
BASE_URL = "https://api.longcat.chat/v1" 

print(f"📡 Connecting to: {BASE_URL}...")

client = openai.OpenAI(
    base_url=BASE_URL,
    api_key=api_key
)

# 3. Send a Test Message
try:
    response = client.chat.completions.create(
        model="claude-3-5-sonnet-20240620",  # Ensure this model name is correct for your provider
        messages=[
            {"role": "user", "content": "Hello, are you working?"}
        ]
    )
    
    print("\n✅ SUCCESS! Connection Established.")
    print(f"🤖 AI Response: {response.choices[0].message.content}")

except openai.APIConnectionError as e:
    print("\n❌ CONNECTION ERROR: The server could not be reached.")
    print(f"   Details: {e}")
    print("   -> Check your internet connection.")
    print("   -> Check if the BASE_URL is correct.")

except openai.AuthenticationError as e:
    print("\n❌ AUTH ERROR: Your API Key is rejected.")
    print("   -> Check if your key in .env is correct.")

except openai.NotFoundError as e:
    print("\n❌ 404 NOT FOUND: The URL is incorrect.")
    print(f"   Current URL: {BASE_URL}")
    print("   -> Try removing '/v1' from the end of the URL.")
    print("   -> Check the documentation for the correct API Endpoint.")

except Exception as e:
    print(f"\n❌ UNEXPECTED ERROR: {e}")