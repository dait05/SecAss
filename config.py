import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROXY_URL = os.getenv("LLM_PROXY_URL", "https://litellm-dev.ai.levelinfinite.com/chat/completions")
LLM_API_KEY = os.getenv("LLM_API_KEY", "sk-BEd3poE1HoQjbGnmgYlbDQ")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-5")
