import os
import json
import uuid
import time
import base64
import sys
import inspect
import secrets
from loguru import logger
from pathlib import Path
import requests # Used by StatsigIDGenerator and image upload
from bs4 import BeautifulSoup # Used by StatsigIDGenerator
import struct # Used by StatsigIDGenerator
import hashlib # Used by StatsigIDGenerator
import random # Used by StatsigIDGenerator

from flask import Flask, request as flask_request, Response, jsonify, stream_with_context, render_template, redirect, session
from curl_cffi import requests as curl_requests
from werkzeug.middleware.proxy_fix import ProxyFix

# --- StatsigIDGenerator Class (Integrated) ---
class StatsigIDGenerator:
    def __init__(self):
        self.base_timestamp = 1682924400 # May 1st, 2023 07:00:00 UTC

    def get_meta_content(self, proxy_options_for_requests=None):
        """获取或生成 48 字节的 meta content, using provided proxy for requests library"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
            # Use standard 'requests' library here, applying proxy if provided
            effective_proxies = None
            if proxy_options_for_requests and "proxies" in proxy_options_for_requests: # Check for standard requests proxy format
                effective_proxies = proxy_options_for_requests["proxies"]
            
            response = requests.get('https://grok.com', headers=headers, timeout=5, proxies=effective_proxies)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                meta_tag = soup.find('meta', {'name': 'grok-site-verification'})
                if meta_tag and meta_tag.get('content'):
                    decoded = base64.b64decode(meta_tag['content'])
                    if len(decoded) >= 48:
                        logger.info("Successfully fetched and used meta_content from grok.com.", "StatsigGenerator")
                        return decoded[:48]
                else:
                    logger.warning("grok-site-verification meta tag not found or no content.", "StatsigGenerator")
            else:
                logger.warning(f"Failed to fetch from grok.com, status: {response.status_code}", "StatsigGenerator")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Exception fetching meta content from grok.com: {e}", "StatsigGenerator")
        except Exception as e: # Catch other potential errors like BeautifulSoup issues
            logger.warning(f"Unexpected error processing meta content from grok.com: {e}", "StatsigGenerator")

        logger.info("Using random fallback for meta_content.", "StatsigGenerator")
        meta = bytearray(48)
        for i in range(48):
            if i < 16: meta[i] = random.randint(0x20, 0x7E)
            elif i < 32: meta[i] = random.randint(0x80, 0xFF)
            else: meta[i] = random.randint(0x00, 0xFF)
        return bytes(meta)

    def generate_fingerprint_hash(self, method, pathname, timestamp_val):
        base_string = f"{method}!{pathname}!{timestamp_val}"
        fingerprint_components = [
            "screen:2560x1440", "colorDepth:24", "pixelRatio:2", "timezone:-480",
            "language:zh-CN", "platform:MacIntel", "hardwareConcurrency:8",
            "deviceMemory:8", "webgl:Apple M1", "canvas:true", "audio:true"
        ]
        full_string = base_string + ''.join(fingerprint_components)
        hash_obj = hashlib.sha256(full_string.encode('utf-8'))
        hash_bytes = hash_obj.digest()
        return hash_bytes[:16]

    def generate_id(self, method="POST", pathname="/rest/app-chat/conversations/new", proxy_options_for_requests=None):
        meta_content = self.get_meta_content(proxy_options_for_requests=proxy_options_for_requests)
        current_timestamp = int(time.time())
        relative_timestamp_val = current_timestamp - self.base_timestamp
        timestamp_bytes = struct.pack('<I', relative_timestamp_val)

        hash_bytes = self.generate_fingerprint_hash(method, pathname, relative_timestamp_val)
        fixed_byte = b'\x03'
        combined = meta_content + timestamp_bytes + hash_bytes + fixed_byte

        if len(combined) != 69:
            logger.error(f"Internal error: Combined length is {len(combined)}, expected 69.", "StatsigGenerator")
            # Fallback or raise error - for now, let it proceed and potentially fail b64 or be caught by server
            # This should ideally not happen if logic is correct.

        xor_key_val = random.randint(0x10, 0xFF)
        encrypted = bytes([b ^ xor_key_val for b in combined])
        final_data = bytes([xor_key_val]) + encrypted
        
        if len(final_data) != 70:
             logger.error(f"Internal error: Final data length is {len(final_data)}, expected 70.", "StatsigGenerator")
             # Fallback for critical error
             return "ERROR_GENERATING_STATSIG_ID_UNEXPECTED_LENGTH"

        statsig_id = base64.b64encode(final_data).decode('utf-8')
        return statsig_id
# --- End StatsigIDGenerator Class ---


class Logger:
    def __init__(self, level="INFO", colorize=True, format=None):
        logger.remove()
        if format is None:
            format = (
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{extra[filename]}</cyan>:<cyan>{extra[function]}</cyan>:<cyan>{extra[lineno]}</cyan> | "
                "<level>{message}</level>"
            )
        logger.add(
            sys.stderr,
            level=level,
            format=format,
            colorize=colorize,
            backtrace=True,
            diagnose=True
        )
        self.logger = logger

    def _get_caller_info(self):
        frame = inspect.currentframe()
        try:
            # Go back 2 frames to get the caller of info/error/warning/debug
            # For request_logger, it's called directly, so f_back is enough
            # For other methods, they are called by instance methods, so f_back.f_back
            caller_frame = frame.f_back.f_back if frame.f_back and frame.f_back.f_back else frame.f_back
            if caller_frame:
                full_path = caller_frame.f_code.co_filename
                function = caller_frame.f_code.co_name
                lineno = caller_frame.f_lineno
                filename = os.path.basename(full_path)
                return {
                    'filename': filename,
                    'function': function,
                    'lineno': lineno
                }
            return {'filename': 'unknown', 'function': 'unknown', 'lineno': 0}
        finally:
            del frame


    def info(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"[{source}] {message}")

    def error(self, message, source="API"):
        caller_info = self._get_caller_info()
        if isinstance(message, Exception):
            self.logger.bind(**caller_info).exception(f"[{source}] {str(message)}")
        else:
            self.logger.bind(**caller_info).error(f"[{source}] {message}")

    def warning(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).warning(f"[{source}] {message}")

    def debug(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).debug(f"[{source}] {message}")

    async def request_logger(self, req): # Changed from 'request' to 'req'
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"请求: {req.method} {req.path}", "Request")

logger = Logger(level="INFO")
statsig_id_generator = StatsigIDGenerator() # Global instance

DATA_DIR = Path("/data")
if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

CONFIG = {
    "MODELS": {
        'grok-2': 'grok-latest',
        'grok-2-imageGen': 'grok-latest',
        'grok-2-search': 'grok-latest',
        "grok-3": "grok-3",
        "grok-3-search": "grok-3",
        "grok-3-imageGen": "grok-3",
        "grok-3-deepsearch": "grok-3",
        "grok-3-deepersearch": "grok-3",
        "grok-3-reasoning": "grok-3"
    },
    "API": {
        "IS_TEMP_CONVERSATION": os.environ.get("IS_TEMP_CONVERSATION", "true").lower() == "true",
        "IS_CUSTOM_SSO": os.environ.get("IS_CUSTOM_SSO", "false").lower() == "true",
        "BASE_URL": "https://grok.com",
        "API_KEY": os.environ.get("API_KEY", "sk-123456"),
        "SIGNATURE_COOKIE": None,
        "PICGO_KEY": os.environ.get("PICGO_KEY") or None,
        "TUMY_KEY": os.environ.get("TUMY_KEY") or None,
        "RETRY_TIME": 1000,
        "PROXY": os.environ.get("PROXY") or None
    },
    "ADMIN": {
        "MANAGER_SWITCH": os.environ.get("MANAGER_SWITCH") or None,
        "PASSWORD": os.environ.get("ADMINPASSWORD") or None
    },
    "SERVER": {
        "COOKIE": None,
        "CF_CLEARANCE":os.environ.get("CF_CLEARANCE") or None,
        "PORT": int(os.environ.get("PORT", 5200))
    },
    "RETRY": {
        "RETRYSWITCH": False, # This seems unused, MAX_ATTEMPTS is used directly
        "MAX_ATTEMPTS": 2
    },
    "TOKEN_STATUS_FILE": str(DATA_DIR / "token_status.json"),
    "SHOW_THINKING": os.environ.get("SHOW_THINKING", "false").lower() == "true", # Default false
    "IS_THINKING": False,
    "IS_IMG_GEN": False,
    "IS_IMG_GEN2": False,
    "ISSHOW_SEARCH_RESULTS": os.environ.get("ISSHOW_SEARCH_RESULTS", "true").lower() == "true"
}

DEFAULT_HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Content-Type': 'text/plain;charset=UTF-8', # For Grok payload
    'Connection': 'keep-alive',
    'Origin': CONFIG["API"]["BASE_URL"],
    'Referer': f'{CONFIG["API"]["BASE_URL"]}/chat',
    'Priority': 'u=1, i',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36', # Example, can be varied
    'Sec-Ch-Ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"macOS"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Baggage': 'sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c,sentry-trace_id=4f035527429547c9874968a38831e2a7,sentry-sample_rate=1,sentry-transaction=%2Fchat%2F%5B%5B...chatId%5D%5D,sentry-sampled=true' # Example
}

class AuthTokenManager:
    def __init__(self):
        self.token_model_map = {}
        self.expired_tokens = set()
        self.token_status_map = {}
        self.model_config = {
            # Using a default config, actual model names from CONFIG["MODELS"] will be used
            "grok-2": {"RequestFrequency": 30, "ExpirationTime": 1 * 60 * 60 * 1000},
            "grok-3": {"RequestFrequency": 20, "ExpirationTime": 2 * 60 * 60 * 1000},
            "grok-3-deepsearch": {"RequestFrequency": 10, "ExpirationTime": 24 * 60 * 60 * 1000},
            "grok-3-deepersearch": {"RequestFrequency": 3, "ExpirationTime": 24 * 60 * 60 * 1000},
            "grok-3-reasoning": {"RequestFrequency": 10, "ExpirationTime": 24 * 60 * 60 * 1000}
        }
        self.token_reset_switch = False
        # self.token_reset_timer = None # This variable is not used
        self.load_token_status()

    def save_token_status(self):
        try:
            with open(CONFIG["TOKEN_STATUS_FILE"], 'w', encoding='utf-8') as f:
                json.dump(self.token_status_map, f, indent=2, ensure_ascii=False)
            logger.info("令牌状态已保存到配置文件", "TokenManager")
        except Exception as error:
            logger.error(f"保存令牌状态失败: {error}", "TokenManager")

    def load_token_status(self):
        try:
            token_status_file = Path(CONFIG["TOKEN_STATUS_FILE"])
            if token_status_file.exists():
                with open(token_status_file, 'r', encoding='utf-8') as f:
                    self.token_status_map = json.load(f)
                logger.info("已从配置文件加载令牌状态", "TokenManager")
        except Exception as error:
            logger.error(f"加载令牌状态失败: {error}", "TokenManager")
            self.token_status_map = {} # Initialize if loading fails

    def add_token(self, token_cookie_str, is_initialization=False):
        try:
            sso_part = token_cookie_str.split("sso=")[1]
            sso = sso_part.split(";")[0]
        except IndexError:
            logger.error(f"无法从 '{token_cookie_str}' 中解析SSO值", "TokenManager")
            return

        for model_key in self.model_config.keys(): # Iterate over known model types
            if model_key not in self.token_model_map:
                self.token_model_map[model_key] = []
            if sso not in self.token_status_map:
                self.token_status_map[sso] = {}

            # Check if this exact token string already exists for this model type
            existing_token_entry = next((entry for entry in self.token_model_map[model_key] if entry["token"] == token_cookie_str), None)
            if not existing_token_entry:
                self.token_model_map[model_key].append({
                    "token": token_cookie_str,
                    "RequestCount": 0,
                    "AddedTime": int(time.time() * 1000),
                    "StartCallTime": None
                })
                logger.debug(f"Token {sso[:10]}... added for model type {model_key}", "TokenManager")

            # Initialize status for this SSO and model type if not present
            if model_key not in self.token_status_map[sso]:
                self.token_status_map[sso][model_key] = {
                    "isValid": True,
                    "invalidatedTime": None,
                    "totalRequestCount": 0 # This refers to total requests made with this sso for this model type
                }
        if not is_initialization:
            self.save_token_status()

    def set_token(self, token_cookie_str): # Used for IS_CUSTOM_SSO
        try:
            sso_part = token_cookie_str.split("sso=")[1]
            sso = sso_part.split(";")[0]
        except IndexError:
            logger.error(f"无法从 '{token_cookie_str}' 中解析SSO值 (set_token)", "TokenManager")
            return

        # For custom SSO, this token applies to all models it might be used with
        # The structure of token_model_map might need slight rethinking if a single custom SSO token
        # should have separate rate limits per model type it's used with.
        # For now, assume it's a generic token that will be applied.
        temp_added_time = int(time.time() * 1000)
        self.token_model_map = {} # Clear existing tokens for custom SSO mode
        for model_key in self.model_config.keys():
             self.token_model_map[model_key] = [{
                "token": token_cookie_str,
                "RequestCount": 0, # Reset count when new custom SSO is set
                "AddedTime": temp_added_time,
                "StartCallTime": None
            }]
        
        self.token_status_map[sso] = {} # Reset status for this SSO
        for model_key in self.model_config.keys():
            self.token_status_map[sso][model_key] = {
                "isValid": True,
                "invalidatedTime": None,
                "totalRequestCount": 0
            }
        logger.info(f"Custom SSO token set: {sso[:10]}...", "TokenManager")


    def delete_token(self, token_cookie_str):
        try:
            sso_part = token_cookie_str.split("sso=")[1]
            sso = sso_part.split(";")[0]
        except IndexError:
            logger.error(f"无法从 '{token_cookie_str}' 中解析SSO值 (delete_token)", "TokenManager")
            return False

        deleted_from_any_model = False
        for model_key in self.token_model_map:
            initial_len = len(self.token_model_map[model_key])
            self.token_model_map[model_key] = [entry for entry in self.token_model_map[model_key] if entry["token"] != token_cookie_str]
            if len(self.token_model_map[model_key]) < initial_len:
                deleted_from_any_model = True
        
        if sso in self.token_status_map:
            del self.token_status_map[sso]
            logger.info(f"SSO status for {sso[:10]}... removed.", "TokenManager")

        if deleted_from_any_model:
            self.save_token_status()
            logger.info(f"令牌已成功移除: {sso[:10]}...", "TokenManager")
            return True
        else:
            logger.warning(f"尝试删除令牌 {sso[:10]}... 但未在任何模型中找到。", "TokenManager")
            return False


    def reduce_token_request_count(self, model_id, count): # model_id is like 'grok-2-search'
        normalized_model_type = self.normalize_model_name(model_id) # e.g., 'grok-2'
        
        if normalized_model_type not in self.token_model_map:
            logger.error(f"模型类型 {normalized_model_type} (来自 {model_id}) 不在 token_model_map 中", "TokenManager")
            return False
        if not self.token_model_map[normalized_model_type]:
            logger.error(f"模型类型 {normalized_model_type} 没有可用的token", "TokenManager")
            return False

        token_entry = self.token_model_map[normalized_model_type][0] # Assuming we always use the first token
        
        original_req_count = token_entry["RequestCount"]
        token_entry["RequestCount"] = max(0, original_req_count - count)
        reduction_amount = original_req_count - token_entry["RequestCount"]

        if reduction_amount > 0:
            try:
                sso = token_entry["token"].split("sso=")[1].split(";")[0]
                if sso in self.token_status_map and normalized_model_type in self.token_status_map[sso]:
                    self.token_status_map[sso][normalized_model_type]["totalRequestCount"] = \
                        max(0, self.token_status_map[sso][normalized_model_type]["totalRequestCount"] - reduction_amount)
                    logger.info(f"减少了 token {sso[:10]}... (模型 {normalized_model_type}) 的请求次数 {reduction_amount}次.", "TokenManager")
                    self.save_token_status() # Save changes
            except IndexError:
                 logger.error(f"无法从 token_entry 解析SSO值: {token_entry.get('token')}", "TokenManager")
            return True
        return False


    def get_next_token_for_model(self, model_id, is_return_only=False): # model_id is like 'grok-2-search'
        normalized_model_type = self.normalize_model_name(model_id) # e.g., 'grok-2'

        if normalized_model_type not in self.token_model_map or not self.token_model_map[normalized_model_type]:
            logger.warning(f"模型 {model_id} (类型 {normalized_model_type}) 无可用令牌池。", "TokenManager")
            return None
        
        tokens_for_model_type = self.token_model_map[normalized_model_type]
        if not tokens_for_model_type:
            logger.warning(f"模型 {model_id} (类型 {normalized_model_type}) 令牌池为空。", "TokenManager")
            return None

        # Simple strategy: use the first token in the list.
        # Could be extended to round-robin or other strategies.
        token_entry = tokens_for_model_type[0]
        
        if is_return_only:
            return token_entry["token"]

        sso = ""
        try:
            sso = token_entry["token"].split("sso=")[1].split(";")[0]
        except IndexError:
            logger.error(f"无法从token_entry解析SSO: {token_entry.get('token')}", "TokenManager")
            # This token is malformed, should probably remove it
            self.remove_token_from_model(normalized_model_type, token_entry["token"])
            return self.get_next_token_for_model(model_id, is_return_only) # Try again

        model_specific_config = self.model_config.get(normalized_model_type, {"RequestFrequency": 10, "ExpirationTime": 3600000})


        if token_entry["StartCallTime"] is None: # First use or after reset
            token_entry["StartCallTime"] = int(time.time() * 1000)
        
        if not self.token_reset_switch: # Start background reset thread if not already started
            self.start_token_reset_process()
            self.token_reset_switch = True

        token_entry["RequestCount"] += 1
        
        # Update total request count for this SSO and model type
        if sso and sso in self.token_status_map and normalized_model_type in self.token_status_map[sso]:
            self.token_status_map[sso][normalized_model_type]["totalRequestCount"] += 1
        else:
            logger.warning(f"SSO {sso} or model type {normalized_model_type} not in token_status_map for count update.", "TokenManager")


        # Check if token exceeded its frequency limit
        if token_entry["RequestCount"] >= model_specific_config["RequestFrequency"]:
            logger.info(f"令牌 {sso[:10]}... (模型 {normalized_model_type}) 已达请求上限 {model_specific_config['RequestFrequency']}。移至过期列表。", "TokenManager")
            self.remove_token_from_model(normalized_model_type, token_entry["token"]) # This moves it to expired_tokens
            if sso and sso in self.token_status_map and normalized_model_type in self.token_status_map[sso]:
                 self.token_status_map[sso][normalized_model_type]["isValid"] = False
                 self.token_status_map[sso][normalized_model_type]["invalidatedTime"] = int(time.time() * 1000)
            self.save_token_status()
            return self.get_next_token_for_model(model_id, is_return_only) # Recursively get the next one

        self.save_token_status() # Save after successful retrieval and count update
        return token_entry["token"]


    def remove_token_from_model(self, normalized_model_type, token_cookie_str):
        if normalized_model_type not in self.token_model_map:
            logger.error(f"尝试移除token时模型类型 {normalized_model_type} 不存在", "TokenManager")
            return False
        
        model_tokens = self.token_model_map[normalized_model_type]
        token_found = False
        for i, entry in enumerate(model_tokens):
            if entry["token"] == token_cookie_str:
                removed_token_entry = model_tokens.pop(i)
                self.expired_tokens.add((
                    removed_token_entry["token"],
                    normalized_model_type, # Store the normalized model type
                    int(time.time() * 1000) # Expiration time
                ))
                token_found = True
                break
        
        if token_found:
            logger.info(f"模型 {normalized_model_type} 的令牌 {token_cookie_str[:20]}... 已成功移除并加入过期列表。", "TokenManager")
            if not self.token_reset_switch: # Ensure reset process is running
                self.start_token_reset_process()
                self.token_reset_switch = True
            return True
        else:
            logger.warning(f"在模型 {normalized_model_type} 中未找到要移除的 token: {token_cookie_str[:20]}...", "TokenManager")
            return False

    def get_expired_tokens(self): # Not directly used by external callers but for internal state
        return list(self.expired_tokens)

    def normalize_model_name(self, model_id): # e.g. 'grok-2-search' -> 'grok-2'
        parts = model_id.split('-')
        if len(parts) >= 2 and parts[0] == 'grok':
            # Specific handling for deepsearch and reasoning which might have their own token pools/limits
            if "deepsearch" in model_id: return "grok-3-deepsearch" # Or map to grok-3 if they share
            if "deepersearch" in model_id: return "grok-3-deepersearch"
            if "reasoning" in model_id: return "grok-3-reasoning"
            return f"{parts[0]}-{parts[1]}" # e.g. grok-2, grok-3
        return model_id # Fallback if not matching 'grok-X' pattern

    def get_token_count_for_model(self, model_id):
        normalized_model_type = self.normalize_model_name(model_id)
        return len(self.token_model_map.get(normalized_model_type, []))

    def get_remaining_token_request_capacity(self): # Per model type
        remaining_capacity_map = {}
        for model_type, tokens in self.token_model_map.items():
            if not tokens:
                remaining_capacity_map[model_type] = 0
                continue
            
            model_specific_config = self.model_config.get(model_type, {"RequestFrequency": 10})
            model_request_frequency = model_specific_config["RequestFrequency"]
            
            total_possible_requests = len(tokens) * model_request_frequency
            current_used_requests = sum(token_entry.get("RequestCount", 0) for token_entry in tokens)
            
            remaining_capacity_map[model_type] = max(0, total_possible_requests - current_used_requests)
        return remaining_capacity_map

    # get_token_array_for_model - seems unused, can remove or keep if planned for future
    
    def start_token_reset_process(self):
        if self.token_reset_switch: # Prevent multiple threads if already started
            return

        def reset_expired_tokens_task():
            logger.info("令牌重置线程开始运行。", "TokenManagerThread")
            while True:
                now = int(time.time() * 1000)
                tokens_to_re_add = []
                
                current_expired_copy = list(self.expired_tokens) # Iterate over a copy
                for token_info_tuple in current_expired_copy:
                    token_str, model_type_expired, expired_at_timestamp = token_info_tuple
                    
                    model_specific_config = self.model_config.get(model_type_expired, {"ExpirationTime": 3600000})
                    token_validity_duration = model_specific_config["ExpirationTime"]

                    if now - expired_at_timestamp >= token_validity_duration:
                        tokens_to_re_add.append(token_info_tuple)
                
                if tokens_to_re_add:
                    logger.info(f"准备重新添加 {len(tokens_to_re_add)} 个过期令牌。", "TokenManagerThread")

                for token_str_to_readd, model_type_to_readd_to, _ in tokens_to_re_add:
                    # Add back to the primary pool for that model type
                    if model_type_to_readd_to not in self.token_model_map:
                        self.token_model_map[model_type_to_readd_to] = []
                    
                    # Avoid re-adding if it somehow already exists (e.g., manual add)
                    if not any(entry["token"] == token_str_to_readd for entry in self.token_model_map[model_type_to_readd_to]):
                        self.token_model_map[model_type_to_readd_to].append({
                            "token": token_str_to_readd,
                            "RequestCount": 0,
                            "AddedTime": now, # Re-added time
                            "StartCallTime": None # Reset StartCallTime
                        })
                        logger.info(f"令牌 {token_str_to_readd[:20]}... 已重新添加到模型 {model_type_to_readd_to} 的池中。", "TokenManagerThread")
                        
                        # Update status in token_status_map
                        try:
                            sso = token_str_to_readd.split("sso=")[1].split(";")[0]
                            if sso in self.token_status_map and model_type_to_readd_to in self.token_status_map[sso]:
                                self.token_status_map[sso][model_type_to_readd_to]["isValid"] = True
                                self.token_status_map[sso][model_type_to_readd_to]["invalidatedTime"] = None
                                # totalRequestCount for an SSO on a model is cumulative, maybe don't reset unless new SSO period
                                # For now, let's reset its RequestCount in token_model_map, and server can decide if that means totalRequestCount resets
                        except IndexError:
                            logger.error(f"无法从 token_str_to_readd 解析SSO: {token_str_to_readd}", "TokenManagerThread")

                    self.expired_tokens.discard((token_str_to_readd, model_type_to_readd_to, _)) # Remove by finding the exact tuple (or re-create it)
                    # A bit tricky if timestamp changed, better to rebuild the set
                
                # Rebuild expired_tokens set without the re-added ones
                new_expired_tokens = set()
                for t_info in self.expired_tokens:
                    is_re_added = False
                    for re_added_token_str, _, _ in tokens_to_re_add:
                        if t_info[0] == re_added_token_str: # Check only token string for re-addition
                            is_re_added = True
                            break
                    if not is_re_added:
                        new_expired_tokens.add(t_info)
                self.expired_tokens = new_expired_tokens


                # Also reset RequestCount for tokens in the main pool if their StartCallTime has expired
                for model_type_pool, tokens_in_pool in self.token_model_map.items():
                    model_specific_config_pool = self.model_config.get(model_type_pool, {"ExpirationTime": 3600000})
                    token_validity_duration_pool = model_specific_config_pool["ExpirationTime"]
                    for token_entry_in_pool in tokens_in_pool:
                        if token_entry_in_pool.get("StartCallTime"):
                            if now - token_entry_in_pool["StartCallTime"] >= token_validity_duration_pool:
                                logger.info(f"令牌 {token_entry_in_pool['token'][:20]}... (模型 {model_type_pool}) 的 StartCallTime 已过期，重置其 RequestCount。", "TokenManagerThread")
                                token_entry_in_pool["RequestCount"] = 0
                                token_entry_in_pool["StartCallTime"] = None # Reset for next cycle
                                # Also update its status in token_status_map if necessary
                                try:
                                    sso = token_entry_in_pool["token"].split("sso=")[1].split(";")[0]
                                    if sso in self.token_status_map and model_type_pool in self.token_status_map[sso]:
                                        self.token_status_map[sso][model_type_pool]["isValid"] = True # Mark as valid again
                                        self.token_status_map[sso][model_type_pool]["invalidatedTime"] = None
                                except IndexError:
                                     logger.error(f"无法从 token_entry_in_pool 解析SSO: {token_entry_in_pool.get('token')}", "TokenManagerThread")


                if tokens_to_re_add: # Only save if changes were made
                    self.save_token_status()
                
                time.sleep(60 * 5) # Check every 5 minutes, for example
        
        import threading
        timer_thread = threading.Thread(target=reset_expired_tokens_task, daemon=True)
        timer_thread.start()
        self.token_reset_switch = True # Mark as started
        logger.info("令牌自动重置和刷新线程已启动。", "TokenManager")


    def get_all_tokens(self): # Returns a list of unique token strings
        all_tokens_set = set()
        for model_tokens_list in self.token_model_map.values():
            for entry in model_tokens_list:
                all_tokens_set.add(entry["token"])
        return list(all_tokens_set)

    # get_current_token - seems unused and similar to get_next_token_for_model with is_return_only=True

    def get_token_status_map(self): # For API exposure
        return self.token_status_map

class Utils:
    @staticmethod
    def organize_search_results(search_results):
        if not search_results or 'results' not in search_results:
            return ''
        results = search_results['results']
        formatted_results = []
        for index, result in enumerate(results):
            title = result.get('title', '未知标题')
            url = result.get('url', '#')
            preview = result.get('preview', '无预览内容')
            formatted_result = f"\r\n<details><summary>资料[{index}]: {title}</summary>\r\n{preview}\r\n\n[Link]({url})\r\n</details>"
            formatted_results.append(formatted_result)
        return '\n\n'.join(formatted_results)

    @staticmethod
    def create_auth_headers(model, is_return=False):
        # This is for the main SSO cookie for the 'Cookie' header
        return token_manager.get_next_token_for_model(model, is_return)

    @staticmethod
    def get_dynamic_statsig_id(method="POST", pathname="/rest/app-chat/conversations/new"):
        """
        Generates the dynamic x-statsig-id using the local generator.
        Passes proxy settings to the generator for its internal HTTP request.
        """
        try:
            # Get proxy options once
            proxy_opts = Utils.get_proxy_options() # This returns a dict suitable for curl_cffi or requests
            
            # The statsig_id_generator.get_meta_content needs proxy in 'requests' lib format
            # Utils.get_proxy_options currently returns 'proxy' for SOCKS (curl_cffi) and 'proxies' for HTTP/S (requests)
            statsig_id = statsig_id_generator.generate_id(method=method, pathname=pathname, proxy_options_for_requests=proxy_opts)
            if statsig_id and "ERROR" not in statsig_id:
                logger.info(f"Successfully generated x-statsig-id: ...{statsig_id[-10:]}", "Utils")
                return statsig_id
            else:
                logger.error(f"Failed to generate valid x-statsig-id. Received: {statsig_id}", "Utils")
                # Fallback or raise critical error
                # For now, return a placeholder or None, upstream should handle
                return f"fallback-statsig-id-{uuid.uuid4()}" # Placeholder
        except Exception as e:
            logger.error(f"Error generating x-statsig-id: {e}", "Utils", exc_info=True)
            return f"error-statsig-id-{uuid.uuid4()}" # Placeholder

    @staticmethod
    def get_proxy_options():
        proxy = CONFIG["API"]["PROXY"]
        proxy_options_dict = {} # Renamed to avoid conflict with 'proxy' variable
        if proxy:
            logger.info(f"使用代理: {proxy}", "Utils")
            if proxy.startswith("socks5://"):
                proxy_options_dict["proxy"] = proxy # For curl_cffi
                if '@' in proxy:
                    try:
                        auth_part = proxy.split('@')[0].split('://')[1]
                        if ':' in auth_part:
                            username, password = auth_part.split(':', 1)
                            proxy_options_dict["proxy_auth"] = (username, password)
                    except Exception as e:
                        logger.error(f"解析SOCKS代理凭证失败: {e}", "Utils")
            else: # HTTP/HTTPS proxy
                proxy_options_dict["proxies"] = {"http": proxy, "https": proxy} # For standard 'requests' and curl_cffi
        return proxy_options_dict

class GrokApiClient:
    def __init__(self, model_id_from_request): # e.g. 'grok-2-search'
        if model_id_from_request not in CONFIG["MODELS"]:
            raise ValueError(f"不支持的模型: {model_id_from_request}")
        self.grok_internal_model_name = CONFIG["MODELS"][model_id_from_request] # e.g. 'grok-latest', 'grok-3'

    def process_message_content(self, content):
        if isinstance(content, str):
            return content
        # Could add handling for other types if necessary, e.g. list of text parts
        return None # Or empty string, depending on how Grok expects it

    def get_image_type(self, base64_string):
        # ... (content identical to your provided code, no changes needed here)
        mime_type = 'image/jpeg'
        if 'data:image' in base64_string:
            import re
            matches = re.search(r'data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,', base64_string)
            if matches:
                mime_type = matches.group(1)
        extension = mime_type.split('/')[1] if '/' in mime_type else 'jpg'
        file_name = f"image.{extension}"
        return {"mimeType": mime_type, "fileName": file_name}


    def upload_base64_file(self, message_content, model_id_context): # model_id_context for cookie generation
        try:
            message_base64 = base64.b64encode(message_content.encode('utf-8')).decode('utf-8')
            upload_data = {
                "fileName": "message.txt",
                "fileMimeType": "text/plain",
                "content": message_base64
            }
            logger.info("发送文字文件上传请求", "GrokAPIClient")
            
            # Cookie for this specific request
            sso_cookie_part = Utils.create_auth_headers(model_id_context, True)
            if not sso_cookie_part:
                 raise ValueError(f"无法为模型 {model_id_context} 获取SSO Cookie (upload_base64_file)")
            
            current_request_cookie = sso_cookie_part
            if CONFIG['SERVER']['CF_CLEARANCE']:
                current_request_cookie = f"{sso_cookie_part};{CONFIG['SERVER']['CF_CLEARANCE']}"

            proxy_options = Utils.get_proxy_options()
            
            # --- Dynamic Headers for this request ---
            upload_file_pathname = "/rest/app-chat/upload-file"
            current_statsig_id = Utils.get_dynamic_statsig_id(method="POST", pathname=upload_file_pathname)
            current_xai_request_id = str(uuid.uuid4())
            
            request_headers = {
                **DEFAULT_HEADERS,
                "Cookie": current_request_cookie,
                "x-statsig-id": current_statsig_id,
                "x-xai-request-id": current_xai_request_id
            }
            # --- End Dynamic Headers ---

            response = curl_requests.post(
                f"{CONFIG['API']['BASE_URL']}{upload_file_pathname}",
                headers=request_headers,
                json=upload_data, # curl_cffi uses json parameter for JSON body
                impersonate="chrome133a", # Ensure this is a valid and up-to-date impersonation string
                **proxy_options # Spread the dict: proxy=proxy_options.get("proxy"), proxy_auth=proxy_options.get("proxy_auth"), proxies=proxy_options.get("proxies")
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"上传文件成功: {result.get('fileMetadataId')}", "GrokAPIClient")
                return result.get("fileMetadataId", "")
            else:
                logger.error(f"上传文件失败, 状态码: {response.status_code}, 响应: {response.text[:200]}", "GrokAPIClient")
                raise Exception(f"上传文件失败, 状态码: {response.status_code}")
        except Exception as error:
            logger.error(f"上传文件过程中发生错误: {error}", "GrokAPIClient", exc_info=True)
            raise # Re-raise the caught exception

    def upload_base64_image(self, base64_data, model_id_context): # model_id_context for cookie
        # The URL for image upload is typically fixed for Grok's /api/rpc endpoint
        image_upload_url = f"{CONFIG['API']['BASE_URL']}/api/rpc" # Fixed URL for this RPC call
        image_upload_pathname = "/api/rpc" # Pathname for statsig

        try:
            image_buffer = base64_data
            if 'data:image' in base64_data: # Strip prefix if present
                image_buffer = base64_data.split(',', 1)[1]
            
            image_info = self.get_image_type(base64_data) # Get MIME and filename
            
            upload_data_payload = { # Payload for the /api/rpc call
                "rpc": "uploadFile",
                "req": {
                    "fileName": image_info["fileName"],
                    "fileMimeType": image_info["mimeType"],
                    "content": image_buffer # Just the base64 content string
                }
            }
            logger.info(f"发送图片上传请求 to {image_upload_url}", "GrokAPIClient")

            sso_cookie_part = Utils.create_auth_headers(model_id_context, True)
            if not sso_cookie_part:
                 raise ValueError(f"无法为模型 {model_id_context} 获取SSO Cookie (upload_base64_image)")

            current_request_cookie = sso_cookie_part
            if CONFIG['SERVER']['CF_CLEARANCE']:
                current_request_cookie = f"{sso_cookie_part};{CONFIG['SERVER']['CF_CLEARANCE']}"
            
            proxy_options = Utils.get_proxy_options()

            current_statsig_id = Utils.get_dynamic_statsig_id(method="POST", pathname=image_upload_pathname)
            current_xai_request_id = str(uuid.uuid4())

            request_headers = {
                **DEFAULT_HEADERS,
                "Content-Type": "application/json", # Important for /api/rpc
                "Cookie": current_request_cookie,
                "x-statsig-id": current_statsig_id,
                "x-xai-request-id": current_xai_request_id
            }
            
            response = curl_requests.post(
                image_upload_url,
                headers=request_headers,
                json=upload_data_payload, # Send as JSON
                impersonate="chrome133a",
                **proxy_options
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"上传图片成功: {result.get('fileMetadataId')}", "GrokAPIClient")
                return result.get("fileMetadataId", "")
            else:
                logger.error(f"上传图片失败, 状态码: {response.status_code}, 响应: {response.text[:200]}", "GrokAPIClient")
                return '' # Return empty as per original logic on failure
        except Exception as error:
            logger.error(f"上传图片过程中发生错误: {error}", "GrokAPIClient", exc_info=True)
            return '' # Return empty on exception

    def prepare_chat_request(self, client_request_data):
        original_model_requested = client_request_data["model"] # e.g. grok-2-imageGen

        if ((original_model_requested == 'grok-2-imageGen' or original_model_requested == 'grok-3-imageGen') and
            not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"] and
            client_request_data.get("stream", False)):
            raise ValueError("该模型流式输出需要配置PICGO或者TUMY图床密钥!")

        todo_messages = client_request_data["messages"]
        # Model-specific message processing (e.g., only last message for imageGen)
        if original_model_requested in ['grok-2-imageGen', 'grok-3-imageGen', 'grok-3-deepsearch']:
            if not todo_messages: raise ValueError("Messages list is empty!")
            last_message = todo_messages[-1]
            if last_message["role"] != 'user':
                raise ValueError('此模型最后一条消息必须是用户消息!')
            # todo_messages = [last_message] # This was the original logic, review if context is needed

        file_attachments_ids = []
        formatted_messages_str = ""
        last_role_processed = None
        last_content_segment = ""
        current_message_char_length = 0
        convert_long_history_to_file = False
        last_user_message_for_file_conversion = "" # if history becomes a file, this is the new prompt

        # Determine search flags and presets based on the specific model from client request
        is_search_enabled = original_model_requested in ['grok-2-search', 'grok-3-search']
        deepsearch_preset_value = ""
        if original_model_requested == 'grok-3-deepsearch': deepsearch_preset_value = 'default'
        elif original_model_requested == 'grok-3-deepersearch': deepsearch_preset_value = 'deeper'
        is_reasoning_model = original_model_requested == 'grok-3-reasoning'
        is_image_gen_model = original_model_requested in ['grok-2-imageGen', 'grok-3-imageGen']


        def remove_think_tags_and_image_placeholders(text):
            import re
            text = re.sub(r'<think>[\s\S]*?<\/think>', '', text, flags=re.DOTALL).strip()
            text = re.sub(r'!\[image\]\(data:.*?base64,.*?\)', '[图片]', text) # Replace embedded base64 images
            return text

        def extract_text_from_content(content_block):
            if isinstance(content_block, list): # OpenAI multimodal format
                text_parts = []
                for item in content_block:
                    if item.get("type") == "text":
                        text_parts.append(remove_think_tags_and_image_placeholders(item.get("text", "")))
                    elif item.get("type") == "image_url":
                        text_parts.append("[图片]") # Placeholder for image
                return "\n".join(filter(None, text_parts))
            elif isinstance(content_block, str):
                return remove_think_tags_and_image_placeholders(content_block)
            return "" # Default for unknown content structure


        for i, message_item in enumerate(todo_messages):
            current_role = 'assistant' if message_item.get("role") == 'assistant' else 'user'
            is_last_message_in_history = (i == len(todo_messages) - 1)
            
            # Process images in the last user message
            if current_role == 'user' and is_last_message_in_history and isinstance(message_item.get("content"), list):
                for content_part in message_item.get("content", []):
                    if content_part.get("type") == "image_url":
                        image_url_data = content_part.get("image_url", {}).get("url", "")
                        if image_url_data:
                            # model_id_context for image upload should be the model making the chat request
                            uploaded_image_id = self.upload_base64_image(image_url_data, original_model_requested)
                            if uploaded_image_id:
                                file_attachments_ids.append(uploaded_image_id)
            
            # Process text content for all messages
            text_content_for_this_message = extract_text_from_content(message_item.get("content"))

            if convert_long_history_to_file and is_last_message_in_history:
                # If history was converted to file, the last message becomes the new prompt
                last_user_message_for_file_conversion = f"{current_role.upper()}: {text_content_for_this_message or ('[图片]' if file_attachments_ids and is_last_message_in_history else '')}\n"
                continue # Don't add to formatted_messages_str if it's the new prompt after file conversion

            if text_content_for_this_message or (is_last_message_in_history and file_attachments_ids): # Ensure message with only image is added
                current_display_content = text_content_for_this_message or \
                                           ('[图片]' if file_attachments_ids and is_last_message_in_history else '')

                if current_role == last_role_processed and current_display_content:
                    last_content_segment += '\n' + current_display_content
                    # Find last occurrence and replace
                    if formatted_messages_str.rfind(f"{current_role.upper()}: ") != -1:
                        formatted_messages_str = formatted_messages_str[:formatted_messages_str.rindex(f"{current_role.upper()}: ")] + \
                                                 f"{current_role.upper()}: {last_content_segment}\n"
                    else: # Should not happen if logic is correct
                         formatted_messages_str += f"{current_role.upper()}: {last_content_segment}\n"

                elif current_display_content: # New role or first message with content
                    formatted_messages_str += f"{current_role.upper()}: {current_display_content}\n"
                    last_content_segment = current_display_content
                    last_role_processed = current_role
            
            current_message_char_length = len(formatted_messages_str)
            if current_message_char_length >= 38000 and not is_last_message_in_history : # Slightly less than 40k to be safe
                convert_long_history_to_file = True
                logger.info(f"消息长度 {current_message_char_length} 已达上限，将转换历史记录为文件。", "GrokAPIClient")


        if convert_long_history_to_file:
            # model_id_context for file upload is the model making the chat request
            history_file_id = self.upload_base64_file(formatted_messages_str.strip(), original_model_requested)
            if history_file_id:
                file_attachments_ids.insert(0, history_file_id) # Prepend history file
            formatted_messages_str = last_user_message_for_file_conversion.strip() # New prompt is the last message

        if not formatted_messages_str.strip() and not file_attachments_ids:
            raise ValueError('消息内容和附件均为空!')
        if not formatted_messages_str.strip() and convert_long_history_to_file: # History became file, prompt is empty but that's ok
            formatted_messages_str = '请根据上传的上下文进行回复。' # Default prompt if only file
        elif not formatted_messages_str.strip() and file_attachments_ids and not convert_long_history_to_file: # Only image(s), no text
            formatted_messages_str = '描述这些图片。' # Default prompt for image-only input


        return {
            "temporary": CONFIG["API"].get("IS_TEMP_CONVERSATION", False),
            "modelName": self.grok_internal_model_name, # Use the internal Grok model name
            "message": formatted_messages_str.strip(),
            "fileAttachments": file_attachments_ids[:4], # Max 4 attachments
            "imageAttachments": [], # Usually handled via fileAttachments for Grok
            "disableSearch": not is_search_enabled, # If true, search tools are disabled
            "enableImageGeneration": is_image_gen_model, # True if it's an image gen model
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "enableImageStreaming": False,
            "imageGenerationCount": 1,
            "forceConcise": False,
            "toolOverrides": { # Based on original_model_requested
                "imageGen": is_image_gen_model,
                "webSearch": is_search_enabled, # Enable all search tools if search model
                "xSearch": is_search_enabled,
                "xMediaSearch": is_search_enabled,
                "trendsSearch": is_search_enabled,
                "xPostAnalyze": is_search_enabled
            },
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "customPersonality": "",
            "deepsearchPreset": deepsearch_preset_value,
            "isReasoning": is_reasoning_model,
            "disableTextFollowUps": True
        }

class MessageProcessor:
    # ... (content identical to your provided code, no changes needed here)
    @staticmethod
    def create_chat_response(message, model, is_stream=False):
        base_response = {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "created": int(time.time()),
            "model": model # This should be the model requested by the client
        }
        if is_stream:
            return {
                **base_response,
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {"content": message if message is not None else ""} # Ensure content is not None
                }]
            }
        # Non-stream
        usage_stats = { # Placeholder, actual tokens would need calculation
                "prompt_tokens": 0, # Placeholder
                "completion_tokens": 0, # Placeholder
                "total_tokens": 0 # Placeholder
            }
        return {
            **base_response,
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": message if message is not None else ""
                },
                "finish_reason": "stop" # Or "length" if truncated
            }],
            "usage": usage_stats # Add usage for non-stream
        }


def process_model_response(grok_response_data, client_requested_model):
    # grok_response_data is the content of result.response from Grok's stream
    # client_requested_model is the model name the client originally asked for (e.g., 'grok-2-search')
    
    output = {"token": None, "imageUrl": None} # Initialize output for each chunk

    # Image generation handling (if 'cachedImageGenerationResponse' exists)
    # This seems to be for pre-generated images or if image gen is the primary action.
    # If IS_IMG_GEN is true, it means an image was requested or detected.
    if CONFIG["IS_IMG_GEN"]: # This global flag is set if doImgGen was seen
        if grok_response_data.get("cachedImageGenerationResponse") and not CONFIG["IS_IMG_GEN2"]:
            # IS_IMG_GEN2 is set when imageUrl is actually processed from this.
            output["imageUrl"] = grok_response_data["cachedImageGenerationResponse"]["imageUrl"]
            logger.info(f"Image Gen: cachedImageGenerationResponse found: {output['imageUrl']}", "ResponseProcessor")
            return output # Early exit if we got the image URL this way.
        # If doImgGen was true but no cachedImageGenerationResponse, we wait for 'token' or 'imageUrl' later in stream.
        # The actual image URL for "on-the-fly" generation might appear in `imageAttachmentInfo.imageUrl` later.

    # Specific logic based on the *client requested model*
    # The 'token' field from Grok is the text chunk.
    text_token = grok_response_data.get("token") # This can be a string or sometimes a dict for actions

    if client_requested_model in ['grok-2-search', 'grok-3-search', 'grok-3-deepsearch', 'grok-3-deepersearch']:
        # Handle web search results if present and configured
        if grok_response_data.get("webSearchResults") and CONFIG["ISSHOW_SEARCH_RESULTS"] and not CONFIG["IS_THINKING"]:
            # Prepend search results before the actual text token, only if not already in "thinking" block
            # This usually comes as a separate event in the stream.
            search_markdown = Utils.organize_search_results(grok_response_data['webSearchResults'])
            if search_markdown:
                 output["token"] = f"\n<think>\n{search_markdown}\n</think>\n" # Wrap in think tags
                 # No text_token added here, this is a separate "event"
                 return output # Return search results, next event will have the text.

    # Handling for "thinking" process (deepsearch, reasoning)
    is_deepsearch_family = client_requested_model in ['grok-3-deepsearch', 'grok-3-deepersearch']
    is_reasoning_model = client_requested_model == 'grok-3-reasoning'

    current_step_is_thinking = False
    if is_deepsearch_family:
        current_step_is_thinking = bool(grok_response_data.get("messageStepId")) # True if step ID exists
    elif is_reasoning_model:
        current_step_is_thinking = grok_response_data.get("isThinking", False)

    if current_step_is_thinking:
        if not CONFIG["SHOW_THINKING"]: return output # Skip if not showing thinking steps (empty token)
        if not CONFIG["IS_THINKING"]: # Start of thinking block
            CONFIG["IS_THINKING"] = True
            prefix = "<think>\n"
            # For deepsearch, the 'token' during messageStepId might be an action object or preliminary text
            action_text = ""
            if isinstance(text_token, dict) and text_token.get("action") == "webSearch":
                action_text = f"Searching for: {text_token.get('action_input', {}).get('query', '')}\n"
            elif isinstance(text_token, str):
                action_text = text_token
            output["token"] = prefix + action_text
        else: # Continuation of thinking
            if isinstance(text_token, dict) and text_token.get("action") == "webSearch":
                 output["token"] = f"Searching for: {text_token.get('action_input', {}).get('query', '')}\n"
            elif grok_response_data.get("webSearchResults") and CONFIG["ISSHOW_SEARCH_RESULTS"]:
                 output["token"] = Utils.organize_search_results(grok_response_data['webSearchResults']) + "\n"
            elif isinstance(text_token, str):
                 output["token"] = text_token # Regular text token within thinking
    
    elif CONFIG["IS_THINKING"]: # End of thinking block (current_step_is_thinking is false)
        CONFIG["IS_THINKING"] = False
        suffix = "\n</think>\n"
        output["token"] = suffix + (text_token if isinstance(text_token, str) else "")
    
    else: # Not in thinking process, or thinking just ended
        if isinstance(text_token, str):
            output["token"] = (output["token"] or "") + text_token # Append if suffix already exists
        # elif text_token is None and output["token"] is None: # No text, no prior data
            # output["token"] = "" # Ensure delta always has content if no error

    # Handle image attachment info (for on-the-fly generated images)
    image_attachment_info = grok_response_data.get("imageAttachmentInfo")
    if image_attachment_info and image_attachment_info.get("imageUrl"):
        output["imageUrl"] = image_attachment_info["imageUrl"]
        logger.info(f"Image Gen: imageAttachmentInfo found: {output['imageUrl']}", "ResponseProcessor")
        CONFIG["IS_IMG_GEN2"] = True # Mark that we are now processing this specific image url

    # If 'doImgGen' was true, but no image URL yet, the text_token might be a prompt or status
    if CONFIG["IS_IMG_GEN"] and not output["imageUrl"] and isinstance(text_token, str) and not CONFIG["IS_THINKING"]:
        # If it's image gen mode and we got a text token, pass it through.
        # If an image URL also comes in this same event, it will be handled above.
        # If no text token was set from thinking logic, use this one
        if output["token"] is None: output["token"] = text_token


    # Ensure output["token"] is a string if it's not None, or default to empty string if it was None and no image.
    if output["token"] is None and output["imageUrl"] is None:
        output["token"] = "" # Avoid sending None for delta content

    return output

def handle_image_response(image_path_from_grok): # e.g., "images/2023/.../img.png"
    # ... (content mostly identical to your provided code)
    # Key change: Use curl_cffi for fetching image from assets.grok.com for consistency
    max_retries = 2
    retry_count = 0
    image_response_from_assets = None # Renamed from image_base64_response
    image_full_url = f"https://assets.grok.com/{image_path_from_grok.lstrip('/')}"
    
    proxy_options = Utils.get_proxy_options()

    while retry_count < max_retries:
        try:
            logger.info(f"Fetching image from assets: {image_full_url}", "ImageHandler")
            # Assuming CONFIG["SERVER"]['COOKIE'] holds the necessary auth for assets.grok.com
            # This might need adjustment if assets.grok.com needs a different/no auth
            asset_headers = {**DEFAULT_HEADERS} # Copy default
            # Remove content-type as it's a GET, Origin/Referer might not be needed or different
            asset_headers.pop('Content-Type', None) 
            # asset_headers['Origin'] = "https://grok.com" # Or assets.grok.com
            # asset_headers['Referer'] = "https://grok.com/"
            asset_headers['Cookie'] = CONFIG["SERVER"]['COOKIE'] # Use the main chat cookie for now

            image_response_from_assets = curl_requests.get(
                image_full_url,
                headers=asset_headers,
                impersonate="chrome133a",
                timeout=15, # Increased timeout for image download
                **proxy_options
            )
            if image_response_from_assets.status_code == 200:
                break
            else:
                logger.warning(f"assets.grok.com returned {image_response_from_assets.status_code} for image {image_path_from_grok}", "ImageHandler")
            
            retry_count += 1
            if retry_count >= max_retries:
                raise Exception(f"获取图片失败! 上游服务状态码: {image_response_from_assets.status_code}")
            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * (retry_count + 1)) # Slightly longer sleep
        except Exception as error:
            logger.error(f"获取图片时发生错误 ({image_path_from_grok}): {error}", "ImageHandler")
            retry_count += 1
            if retry_count >= max_retries:
                raise
            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * (retry_count + 1))

    image_buffer = image_response_from_assets.content
    
    # PicGo / TuMy upload logic (using standard requests, with its proxy format)
    std_req_proxies = Utils.get_proxy_options().get("proxies") # Get proxy for 'requests' lib

    if not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"]:
        # Fallback to Base64 encoding if no image host configured
        base64_image_str = base64.b64encode(image_buffer).decode('utf-8')
        image_content_type = image_response_from_assets.headers.get('content-type', 'image/jpeg')
        logger.info("No image host configured, returning Base64 encoded image.", "ImageHandler")
        return f"![image](data:{image_content_type};base64,{base64_image_str})"

    logger.info("配置了图床，开始上传...", "ImageHandler")
    if CONFIG["API"]["PICGO_KEY"]:
        # ... (PicGo logic - ensure it uses std_req_proxies if needed)
        files = {'source': ('image.jpg', image_buffer, image_response_from_assets.headers.get('content-type', 'image/jpeg'))}
        headers = {"X-API-Key": CONFIG["API"]["PICGO_KEY"]}
        try:
            response_url = requests.post("https://www.picgo.net/api/1/upload", files=files, headers=headers, proxies=std_req_proxies, timeout=20)
            if response_url.status_code == 200:
                result = response_url.json()
                logger.info(f"PicGo 上传成功: {result['image']['url']}", "ImageHandler")
                return f"![image]({result['image']['url']})"
            else:
                logger.error(f"PicGo 上传失败, Status: {response_url.status_code}, Response: {response_url.text[:100]}", "ImageHandler")
                return "生图失败(PicGo错误)，请检查PICGO图床密钥或服务状态。"
        except Exception as e_picgo:
            logger.error(f"PicGo 上传异常: {e_picgo}", "ImageHandler")
            return "生图失败(PicGo连接异常)。"


    elif CONFIG["API"]["TUMY_KEY"]:
        # ... (TuMy logic - ensure it uses std_req_proxies if needed)
        files = {'file': ('image.jpg', image_buffer, image_response_from_assets.headers.get('content-type', 'image/jpeg'))}
        headers = {"Accept": "application/json", 'Authorization': f"Bearer {CONFIG['API']['TUMY_KEY']}"}
        try:
            response_url = requests.post("https://tu.my/api/v1/upload", files=files, headers=headers, proxies=std_req_proxies, timeout=20)
            if response_url.status_code == 200:
                result = response_url.json()
                logger.info(f"TuMy 上传成功: {result['data']['links']['url']}", "ImageHandler")
                return f"![image]({result['data']['links']['url']})"
            else:
                logger.error(f"TuMy 上传失败, Status: {response_url.status_code}, Response: {response_url.text[:100]}", "ImageHandler")
                return "生图失败(TuMy错误)，请检查TUMY图床密钥或服务状态。"
        except Exception as e_tumy:
            logger.error(f"TuMy 上传异常: {e_tumy}", "ImageHandler")
            return "生图失败(TuMy连接异常)。"
            
    return "[Image generation failed or image hosting not configured]" # Fallback

def handle_non_stream_response(grok_http_response, client_requested_model):
    # ... (content mostly identical, ensure use of client_requested_model in process_model_response)
    try:
        logger.info("开始处理非流式响应", "StreamHandler")
        full_response_text = ""
        # Reset persistent state flags for this request
        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False # Reset: true if 'doImgGen' is seen in any chunk
        CONFIG["IS_IMG_GEN2"] = False # Reset: true if 'imageUrl' is processed

        for chunk_bytes in grok_http_response.iter_lines():
            if not chunk_bytes: continue
            try:
                line_json_str = chunk_bytes.decode("utf-8", errors='replace').strip()
                if not line_json_str: continue
                
                line_json = json.loads(line_json_str)

                if line_json.get("error"): # Handle Grok API error message in stream
                    error_detail = line_json.get("error", {"message": "Unknown error from Grok stream"})
                    logger.error(f"Grok API流错误 (非流式处理): {json.dumps(error_detail, indent=2)}", "StreamHandler")
                    # For non-stream, we might collect all errors or just the first significant one.
                    # Let's assume we stop and return this error.
                    return json.dumps({"error": "GrokAPIRateLimitOrError", "details": error_detail.get("message", error_detail)})


                grok_result_response_part = line_json.get("result", {}).get("response")
                if not grok_result_response_part: continue

                # Set IS_IMG_GEN if doImgGen is true in this chunk
                if grok_result_response_part.get("doImgGen") or grok_result_response_part.get("imageAttachmentInfo"):
                    CONFIG["IS_IMG_GEN"] = True
                    logger.info("非流式响应检测到图像生成信号。", "StreamHandler")


                processed_chunk_data = process_model_response(grok_result_response_part, client_requested_model)
                
                if processed_chunk_data.get("token"):
                    full_response_text += processed_chunk_data["token"]
                
                if processed_chunk_data.get("imageUrl"): # Image URL is available
                    # CONFIG["IS_IMG_GEN2"] = True # process_model_response sets this
                    try:
                        image_markdown_link = handle_image_response(processed_chunk_data["imageUrl"])
                        full_response_text += f"\n{image_markdown_link}\n"
                    except Exception as img_e:
                        logger.error(f"非流式处理图片时出错: {img_e}", "StreamHandler")
                        full_response_text += f"\n[图片处理错误: {img_e}]\n"
            
            except json.JSONDecodeError:
                logger.warning(f"非流式响应中遇到非JSON行: '{line_json_str[:100]}...'", "StreamHandler")
                continue # Skip malformed JSON lines
            except Exception as e_chunk:
                logger.error(f"处理非流式响应块时出错: {e_chunk}", "StreamHandler", exc_info=True)
                continue # Skip problematic chunks

        return full_response_text.strip()
    except Exception as e_overall:
        logger.error(f"处理非流式响应时发生整体错误: {e_overall}", "StreamHandler", exc_info=True)
        raise # Re-raise to be caught by the main API endpoint handler


def handle_stream_response(grok_http_response, client_requested_model):
    # ... (content mostly identical, ensure use of client_requested_model in process_model_response)
    def generate_stream_chunks():
        logger.info("开始处理流式响应", "StreamHandler")
        # Reset persistent state flags for this request
        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False # Reset: true if 'doImgGen' is seen
        CONFIG["IS_IMG_GEN2"] = False # Reset: true if 'imageUrl' is processed

        for chunk_bytes in grok_http_response.iter_lines():
            if not chunk_bytes: continue
            try:
                line_json_str = chunk_bytes.decode("utf-8", errors='replace').strip()
                if not line_json_str: continue
                
                # logger.debug(f"Raw stream chunk: {line_json_str}", "StreamHandler") # Verbose
                line_json = json.loads(line_json_str)

                if line_json.get("error"): # Handle Grok API error message in stream
                    error_detail = line_json.get("error", {"message": "Unknown error from Grok stream"})
                    logger.error(f"Grok API流错误: {json.dumps(error_detail, indent=2)}", "StreamHandler")
                    error_message_payload = MessageProcessor.create_chat_response(
                        f"Grok API Error: {error_detail.get('message', json.dumps(error_detail))}",
                        client_requested_model, True
                    )
                    yield f"data: {json.dumps(error_message_payload)}\n\n"
                    # Continue, or break if error is fatal? For now, continue to see if more comes.
                    # Some errors might be per-message in a batch.
                    continue 


                grok_result_response_part = line_json.get("result", {}).get("response")
                if not grok_result_response_part:
                    # logger.debug(f"Skipping chunk, no 'result.response': {line_json_str}", "StreamHandler")
                    continue
                
                # Set IS_IMG_GEN if doImgGen is true in this chunk
                if grok_result_response_part.get("doImgGen") or grok_result_response_part.get("imageAttachmentInfo"):
                    if not CONFIG["IS_IMG_GEN"]: # Log only on first detection
                        logger.info("流式响应检测到图像生成信号。", "StreamHandler")
                    CONFIG["IS_IMG_GEN"] = True


                processed_chunk_data = process_model_response(grok_result_response_part, client_requested_model)
                
                # Yield text token if present
                if processed_chunk_data.get("token") is not None: # Allow empty string token
                    text_payload = MessageProcessor.create_chat_response(processed_chunk_data["token"], client_requested_model, True)
                    yield f"data: {json.dumps(text_payload)}\n\n"
                
                # Yield image if URL is present
                if processed_chunk_data.get("imageUrl"):
                    # CONFIG["IS_IMG_GEN2"] = True # process_model_response sets this
                    try:
                        image_markdown_link = handle_image_response(processed_chunk_data["imageUrl"])
                        image_payload = MessageProcessor.create_chat_response(image_markdown_link, client_requested_model, True)
                        yield f"data: {json.dumps(image_payload)}\n\n"
                    except Exception as img_e:
                        logger.error(f"流式处理图片时出错: {img_e}", "StreamHandler")
                        error_img_payload = MessageProcessor.create_chat_response(f"\n[图片处理错误: {img_e}]\n", client_requested_model, True)
                        yield f"data: {json.dumps(error_img_payload)}\n\n"
            
            except json.JSONDecodeError:
                # logger.warning(f"流式响应中遇到非JSON行: '{line_json_str[:100]}...'", "StreamHandler")
                # Silently skip malformed JSON lines in stream as they might be partial or noise
                continue
            except Exception as e_chunk:
                logger.error(f"处理流式响应块时出错: {e_chunk}", "StreamHandler", exc_info=True)
                error_chunk_payload = MessageProcessor.create_chat_response(f"[流处理块错误: {e_chunk}]", client_requested_model, True)
                yield f"data: {json.dumps(error_chunk_payload)}\n\n"
                continue # Try to process next chunk

        yield "data: [DONE]\n\n"
    return generate_stream_chunks()


def initialization():
    sso_array_str = os.environ.get("SSO", "")
    if sso_array_str:
        sso_array = sso_array_str.split(',')
        logger.info("开始加载SSO令牌", "Initializer")
        # token_manager.load_token_status() # Already called in AuthTokenManager.__init__
        for sso_val in sso_array:
            if sso_val.strip():
                # Construct the full cookie string format Grok uses
                full_sso_cookie = f"sso-rw={sso_val.strip()};sso={sso_val.strip()}"
                token_manager.add_token(full_sso_cookie, is_initialization=True)
        token_manager.save_token_status() # Save after initial batch add
        logger.info(f"成功加载 {len(token_manager.get_all_tokens())} 个唯一SSO令牌。", "Initializer")
    else:
        logger.warning("未从环境变量 SSO 中找到令牌进行初始化。", "Initializer")

    if CONFIG["API"]["PROXY"]:
        logger.info(f"代理已设置: {CONFIG['API']['PROXY']}", "Initializer")
    
    # Start token reset thread if not already (it has its own guard)
    if not CONFIG["API"]["IS_CUSTOM_SSO"] and token_manager.get_all_tokens():
        token_manager.start_token_reset_process()
    
    logger.info("项目初始化完成。", "Initializer")


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app) # Important for correct IP handling if behind proxy
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)
app.json.sort_keys = False # Preserve order in JSON responses


@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    # ... (content mostly identical, ensure CONFIG values are checked for None/empty)
    if CONFIG["ADMIN"]["MANAGER_SWITCH"] and CONFIG["ADMIN"]["PASSWORD"]:
        if flask_request.method == 'POST':
            password = flask_request.form.get('password')
            if password == CONFIG["ADMIN"]["PASSWORD"]:
                session['is_logged_in'] = True
                logger.info("管理员登录成功。", "Auth")
                return redirect('/manager')
            else:
                logger.warning("管理员登录失败：密码错误。", "Auth")
                return render_template('login.html', error="密码错误")
        return render_template('login.html', error=None)
    else:
        logger.info("管理员面板未启用或未配置密码。", "Auth")
        return redirect('/')


def check_auth(): # For manager panel
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"] or not CONFIG["ADMIN"]["PASSWORD"]:
        return False
    return session.get('is_logged_in', False)

@app.route('/manager')
def manager_panel_home(): # Renamed from 'manager'
    if not check_auth():
        return redirect('/manager/login')
    return render_template('manager.html', # Pass necessary data to template
                           sso_tokens=token_manager.get_all_tokens(),
                           token_status=token_manager.get_token_status_map(),
                           cf_clearance_current=CONFIG["SERVER"]["CF_CLEARANCE"] or "")


@app.route('/manager/api/get_tokens_status') # More specific name
def get_manager_tokens_status_api():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(token_manager.get_token_status_map())

@app.route('/manager/api/add_sso', methods=['POST']) # More specific
def add_manager_sso_api():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    try:
        sso_value = flask_request.json.get('sso_value')
        if not sso_value or not isinstance(sso_value, str) or not sso_value.strip():
            return jsonify({"error": "SSO value is required and must be a non-empty string"}), 400
        
        full_sso_cookie = f"sso-rw={sso_value.strip()};sso={sso_value.strip()}"
        token_manager.add_token(full_sso_cookie) # Will save status
        logger.info(f"管理员添加了SSO: {sso_value[:10]}...", "ManagerAPI")
        return jsonify({"success": True, "message": f"SSO {sso_value[:10]}... 已添加。", "sso_status": token_manager.get_token_status_map().get(sso_value.strip())})
    except Exception as e:
        logger.error(f"管理员添加SSO时出错: {e}", "ManagerAPI", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/delete_sso', methods=['POST']) # More specific
def delete_manager_sso_api():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    try:
        sso_value = flask_request.json.get('sso_value')
        if not sso_value or not isinstance(sso_value, str) or not sso_value.strip():
            return jsonify({"error": "SSO value is required"}), 400
        
        full_sso_cookie_to_delete = f"sso-rw={sso_value.strip()};sso={sso_value.strip()}"
        if token_manager.delete_token(full_sso_cookie_to_delete):
            logger.info(f"管理员删除了SSO: {sso_value[:10]}...", "ManagerAPI")
            return jsonify({"success": True, "message": f"SSO {sso_value[:10]}... 已删除。"})
        else:
            return jsonify({"error": "SSO删除失败或未找到。", "sso_value": sso_value}), 404
    except Exception as e:
        logger.error(f"管理员删除SSO时出错: {e}", "ManagerAPI", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/set_cf_clearance', methods=['POST']) # More specific
def set_manager_cf_clearance_api():
    if not check_auth(): return jsonify({"error": "Unauthorized"}), 401
    try:
        cf_clearance_val = flask_request.json.get('cf_clearance', "") # Default to empty string
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance_val.strip() if cf_clearance_val else None
        logger.info(f"管理员设置CF Clearance为: '{CONFIG['SERVER']['CF_CLEARANCE']}'", "ManagerAPI")
        return jsonify({"success": True, "message": f"CF Clearance已更新为 '{CONFIG['SERVER']['CF_CLEARANCE']}'。", "cf_clearance": CONFIG["SERVER"]['CF_CLEARANCE']})
    except Exception as e:
        logger.error(f"管理员设置CF Clearance时出错: {e}", "ManagerAPI", exc_info=True)
        return jsonify({"error": str(e)}), 500


# Public API Key protected endpoints
@app.route('/api/v1/tokens/status', methods=['GET']) # Changed path
def get_tokens_status_public_api():
    # ... (content identical, just path change for clarity)
    auth_header = flask_request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义SSO令牌模式下无法获取轮询池状态'}), 403
    elif auth_header != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized - Invalid API Key'}), 401
    return jsonify(token_manager.get_token_status_map())


@app.route('/api/v1/tokens/add', methods=['POST']) # Changed path
def add_token_public_api(): # Renamed original add_token
    # ... (content identical)
    auth_header = flask_request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义SSO令牌模式下无法添加轮询池令牌'}), 403
    elif auth_header != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized - Invalid API Key'}), 401
    try:
        sso_value = flask_request.json.get('sso')
        if not sso_value or not sso_value.strip():
             return jsonify({"error": "SSO value is required"}), 400
        full_sso_cookie = f"sso-rw={sso_value.strip()};sso={sso_value.strip()}"
        token_manager.add_token(full_sso_cookie)
        return jsonify({"message": f"SSO {sso_value[:10]}... 添加成功。", "status": token_manager.get_token_status_map().get(sso_value.strip(), {})}), 200
    except Exception as error:
        logger.error(f"API添加SSO时出错: {error}", "PublicAPI", exc_info=True)
        return jsonify({"error": f'添加SSO令牌失败: {str(error)}'}), 500

@app.route('/api/v1/tokens/delete', methods=['POST']) # Changed path
def delete_token_public_api(): # Renamed original delete_token
    # ... (content identical)
    auth_header = flask_request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义SSO令牌模式下无法删除轮询池令牌'}), 403
    elif auth_header != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized - Invalid API Key'}), 401
    try:
        sso_value = flask_request.json.get('sso')
        if not sso_value or not sso_value.strip():
             return jsonify({"error": "SSO value is required"}), 400
        full_sso_cookie = f"sso-rw={sso_value.strip()};sso={sso_value.strip()}"
        if token_manager.delete_token(full_sso_cookie):
            return jsonify({"message": f"SSO {sso_value[:10]}... 删除成功。"}), 200
        else:
            return jsonify({"message": f"SSO {sso_value[:10]}... 删除失败或未找到。"}), 404
    except Exception as error:
        logger.error(f"API删除SSO时出错: {error}", "PublicAPI", exc_info=True)
        return jsonify({"error": f'删除SSO令牌失败: {str(error)}'}), 500

@app.route('/api/v1/server/cf_clearance', methods=['POST']) # Changed path
def set_cf_clearance_public_api(): # Renamed original setCf_clearance
    # ... (content identical)
    auth_header = flask_request.headers.get('Authorization', '').replace('Bearer ', '')
    if auth_header != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized - Invalid API Key'}), 401
    try:
        cf_clearance_val = flask_request.json.get('cf_clearance', "")
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance_val.strip() if cf_clearance_val else None
        logger.info(f"API设置CF Clearance为: '{CONFIG['SERVER']['CF_CLEARANCE']}'", "PublicAPI")
        return jsonify({"message": 'CF Clearance 设置成功', "new_value": CONFIG['SERVER']['CF_CLEARANCE']}), 200
    except Exception as error:
        logger.error(f"API设置CF Clearance时出错: {error}", "PublicAPI", exc_info=True)
        return jsonify({"error": f'设置CF Clearance失败: {str(error)}'}), 500


@app.route('/v1/models', methods=['GET'])
def get_openai_models_list(): # Renamed from get_models
    # ... (content identical)
    auth_header = flask_request.headers.get('Authorization', '').replace('Bearer ', '')
    # Allow access even with IS_CUSTOM_SSO, as models list is static.
    # API key check is still important.
    if not auth_header and not CONFIG["API"]["IS_CUSTOM_SSO"]: # No key and not custom sso = error
         return jsonify({"error": "API key required for this endpoint."}), 401
    if not CONFIG["API"]["IS_CUSTOM_SSO"] and auth_header != CONFIG["API"]["API_KEY"]:
         return jsonify({"error": "Invalid API Key."}), 401
    # If IS_CUSTOM_SSO, auth_header is the SSO, can proceed.

    return jsonify({
        "object": "list",
        "data": [
            {"id": model_name, "object": "model", "created": int(time.time()), "owned_by": "xai-grok"}
            for model_name in CONFIG["MODELS"].keys()
        ]
    })


@app.route('/v1/chat/completions', methods=['POST'])
def handle_chat_completions(): # Renamed from chat_completions
    # ... (significant changes for clarity and error handling)
    response_status_code = 500 # Default
    client_requested_model = "" # Will be set from request payload

    try:
        auth_header = flask_request.headers.get('Authorization', '').replace('Bearer ', '')
        if not auth_header:
            response_status_code = 401
            return jsonify({"error": {'message': 'Authorization header missing. API Key or custom SSO token required.', 'type': 'auth_error'}}), response_status_code

        if CONFIG["API"]["IS_CUSTOM_SSO"]:
            sso_token_from_header = auth_header # Header is the SSO token
            # Construct the full Grok cookie format
            full_sso_cookie_custom = f"sso-rw={sso_token_from_header};sso={sso_token_from_header}"
            token_manager.set_token(full_sso_cookie_custom) # Set this as the current token for all models
            logger.info(f"使用自定义SSO: {sso_token_from_header[:10]}...", "ChatAPI")
        elif auth_header != CONFIG["API"]["API_KEY"]:
            response_status_code = 401
            return jsonify({"error": {'message': 'Unauthorized: Invalid API Key provided.', 'type': 'auth_error'}}), response_status_code
        # If not IS_CUSTOM_SSO and API key is valid, proceed with token pool.

        client_payload = flask_request.json
        client_requested_model = client_payload.get("model")
        stream_requested_by_client = client_payload.get("stream", False)

        if not client_requested_model or client_requested_model not in CONFIG["MODELS"]:
            response_status_code = 400
            return jsonify({"error": {'message': f"Invalid or missing model: '{client_requested_model}'. Supported: {list(CONFIG['MODELS'].keys())}", 'type': 'invalid_request_error'}}), response_status_code

        grok_api_client_instance = GrokApiClient(client_requested_model)
        # This call can raise ValueError (e.g. image upload needs keys, message format issues)
        grok_request_payload = grok_api_client_instance.prepare_chat_request(client_payload)
        logger.info(f"Grok请求负载 for {client_requested_model}: {json.dumps(grok_request_payload, indent=2, ensure_ascii=False)}", "ChatAPI")

        # Retry loop for making the request to Grok
        last_grok_error = None
        for attempt in range(1, CONFIG["RETRY"]["MAX_ATTEMPTS"] + 1):
            logger.info(f"尝试 {attempt}/{CONFIG['RETRY']['MAX_ATTEMPTS']} for model {client_requested_model}", "ChatAPI")
            
            # Get SSO cookie for this attempt from the pool (or custom SSO if set)
            current_sso_for_request = Utils.create_auth_headers(client_requested_model, False) # False = increment count
            if not current_sso_for_request:
                logger.warning(f"尝试 {attempt}: 模型 {client_requested_model} 无可用SSO令牌。", "ChatAPI")
                last_grok_error = ValueError(f"模型 {client_requested_model} 当前无可用SSO令牌。")
                if CONFIG["API"]["IS_CUSTOM_SSO"]: # Custom SSO should always provide one via set_token
                    logger.error("逻辑错误: 自定义SSO模式下 create_auth_headers 未返回令牌。", "ChatAPI")
                    break # Break if custom SSO somehow failed to provide a token.
                if attempt < CONFIG["RETRY"]["MAX_ATTEMPTS"]: time.sleep(1.5) # Wait before retrying pool
                continue # Try next attempt

            CONFIG["API"]["SIGNATURE_COOKIE"] = current_sso_for_request # Store for potential removal/logging
            
            # Construct full cookie for the request
            final_request_cookie = current_sso_for_request
            if CONFIG['SERVER']['CF_CLEARANCE']:
                final_request_cookie = f"{current_sso_for_request};{CONFIG['SERVER']['CF_CLEARANCE']}"
            CONFIG["SERVER"]['COOKIE'] = final_request_cookie # For use by image handlers etc.
            
            # --- Dynamic Headers for Grok Chat Request ---
            chat_pathname = "/rest/app-chat/conversations/new"
            current_statsig_id = Utils.get_dynamic_statsig_id(method="POST", pathname=chat_pathname)
            current_xai_request_id = str(uuid.uuid4())

            grok_http_headers = {
                **DEFAULT_HEADERS,
                "Cookie": final_request_cookie,
                "x-statsig-id": current_statsig_id,
                "x-xai-request-id": current_xai_request_id,
                "Content-Type": "text/plain;charset=UTF-8", # Grok expects this for chat
            }

            try:
                proxy_options_for_curl = Utils.get_proxy_options()
                
                grok_response = curl_requests.post(
                    f"{CONFIG['API']['BASE_URL']}{chat_pathname}",
                    headers=grok_http_headers,
                    data=json.dumps(grok_request_payload), # Grok expects a JSON string in plain text body
                    impersonate="chrome133a",
                    stream=True, # Always request stream from Grok backend
                    timeout=120, # Generous timeout for Grok response start
                    **proxy_options_for_curl
                )
                logger.info(f"Grok API请求已发送 (Cookie: ...{final_request_cookie[-20:]}, Statsig: ...{current_statsig_id[-10:]})", "ChatAPI")

                if grok_response.status_code == 200:
                    logger.info(f"Grok API 响应成功 (200 OK) for {client_requested_model}.", "ChatAPI")
                    if stream_requested_by_client:
                        return Response(stream_with_context(handle_stream_response(grok_response, client_requested_model)), content_type='text/event-stream')
                    else:
                        full_content = handle_non_stream_response(grok_response, client_requested_model)
                        if isinstance(full_content, str) and full_content.startswith('{"error":'):
                             try: error_json = json.loads(full_content); return jsonify(error_json), 400 # Or other appropriate code
                             except: pass # Fall through if not valid JSON
                        return jsonify(MessageProcessor.create_chat_response(full_content, client_requested_model))
                
                # Handle non-200 responses from Grok
                response_text_preview = grok_response.text[:250] if hasattr(grok_response, "text") else "N/A"
                logger.warning(f"Grok API 错误: Status {grok_response.status_code}, Response: {response_text_preview}", "ChatAPI")
                last_grok_error = Exception(f"Grok API Error {grok_response.status_code}: {response_text_preview}")
                response_status_code = grok_response.status_code # Store for final error response

                if grok_response.status_code in [401, 429]: # Token issue (unauthorized, rate limited)
                    if not CONFIG["API"]["IS_CUSTOM_SSO"]: # Only remove from pool if not custom
                        token_manager.remove_token_from_model(token_manager.normalize_model_name(client_requested_model), current_sso_for_request)
                    else: # Custom SSO failed
                         break # No point retrying with the same custom SSO if it's bad
                elif grok_response.status_code == 403: # IP/CF issue, don't remove token, but maybe pause this IP/token
                    if not CONFIG["API"]["IS_CUSTOM_SSO"]:
                         token_manager.reduce_token_request_count(client_requested_model, 1) # Don't penalize token fully
                    # Consider specific handling for 403, e.g., longer backoff
                    time.sleep(attempt * 2) # Longer sleep for 403
                # For other errors, token might still be an issue, or server-side Grok problem
                
                if attempt >= CONFIG["RETRY"]["MAX_ATTEMPTS"]: break # Exhausted retries
                time.sleep(1 + attempt) # Exponential backoff for retries

            except curl_requests.RequestsError as net_err: # Network/Connection errors
                logger.error(f"网络/连接错误 (尝试 {attempt}): {net_err}", "ChatAPI", exc_info=True)
                last_grok_error = net_err
                if attempt >= CONFIG["RETRY"]["MAX_ATTEMPTS"]: break
                time.sleep(attempt * 2) # Longer backoff for network issues
            except Exception as e_inner_loop: # Catch other unexpected errors within loop
                logger.error(f"内部循环错误 (尝试 {attempt}): {e_inner_loop}", "ChatAPI", exc_info=True)
                last_grok_error = e_inner_loop
                break # Break on unexpected errors in loop, likely not retryable with same params

        # If loop finished and no success, raise or return error based on last_grok_error
        if last_grok_error:
             error_message = f"与Grok API通信失败 (尝试 {CONFIG['RETRY']['MAX_ATTEMPTS']} 次): {str(last_grok_error)}"
             if isinstance(last_grok_error, ValueError): response_status_code = 400 # Bad input likely
             # If response_status_code was set from HTTP error, it will be used.
             raise type(last_grok_error)(error_message) from last_grok_error


    except ValueError as ve: # Catch ValueErrors from prepare_chat_request or loop logic
        logger.warning(f"请求处理错误 (ValueError): {ve}", "ChatAPI", exc_info=True)
        response_status_code = 400 # Bad Request for ValueErrors
        return jsonify({"error": {"message": str(ve), "type": "invalid_request_error", "model": client_requested_model}}), response_status_code
    except Exception as e_outer:
        logger.error(f"处理聊天请求时发生意外错误: {e_outer}", "ChatAPI", exc_info=True)
        # Use response_status_code if it was set by an HTTP error, otherwise default to 500
        final_status_code = response_status_code if response_status_code not in [200, 0] else 500
        return jsonify({"error": {"message": f"服务器内部错误: {str(e_outer)}", "type": "server_error", "model": client_requested_model}}), final_status_code


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all_route(path): # Renamed from catch_all
    if path == "health":
        return jsonify({"status": "ok", "timestamp": time.time(), "message": "grok2api is healthy"}), 200
    return f'grok2api 运行中。请求路径: /{path}', 200


if __name__ == '__main__':
    # Initialize AuthTokenManager first as other parts might depend on it
    token_manager = AuthTokenManager() 
    initialization() # Loads SSO tokens from env, sets up proxy logging

    # Create dummy template files if manager is enabled and files don't exist
    if CONFIG["ADMIN"]["MANAGER_SWITCH"] and CONFIG["ADMIN"]["PASSWORD"]:
        templates_dir = Path("templates")
        if not templates_dir.exists():
            templates_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"创建了 '{templates_dir}' 目录。", "Setup")

        login_html_path = templates_dir / "login.html"
        if not login_html_path.exists():
            with open(login_html_path, "w", encoding="utf-8") as f:
                f.write("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Manager Login</title></head><body>
                <h2>Grok2API Manager Login</h2><form method="post">Password: <input type="password" name="password" required>
                <input type="submit" value="Login"></form>{% if error %}<p style="color:red;">{{ error }}</p>{% endif %}</body></html>""")
            logger.info(f"创建了 '{login_html_path}' 模板。", "Setup")

        manager_html_path = templates_dir / "manager.html"
        # A more functional manager.html would be needed for actual management.
        if not manager_html_path.exists():
            with open(manager_html_path, "w", encoding="utf-8") as f:
                f.write("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Grok2API Manager</title></head><body>
                <h1>Grok2API Token Manager</h1><p>Current CF Clearance: <code>{{ cf_clearance_current }}</code></p>
                <p><a href="/manager/login">Logout (simulated, clear session or implement properly)</a></p>
                <h2>SSO Tokens Status:</h2><pre>{{ token_status | tojson(indent=2) }}</pre>
                <hr><h3>Add SSO:</h3><form onsubmit="addSso(event)"><input type="text" id="sso_value" placeholder="Enter SSO value"><button type="submit">Add</button></form>
                <h3>Delete SSO:</h3><form onsubmit="deleteSso(event)"><input type="text" id="sso_delete_value" placeholder="Enter SSO value to delete"><button type="submit">Delete</button></form>
                <h3>Set CF Clearance:</h3><form onsubmit="setCf(event)"><input type="text" id="cf_value" placeholder="Enter CF Clearance (empty to clear)"><button type="submit">Set CF</button></form>
                <script>
                async function apiCall(url, body) {
                    const res = await fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
                    alert(JSON.stringify(await res.json())); location.reload();
                }
                function addSso(e) { e.preventDefault(); apiCall('/manager/api/add_sso', {sso_value: document.getElementById('sso_value').value}); }
                function deleteSso(e) { e.preventDefault(); apiCall('/manager/api/delete_sso', {sso_value: document.getElementById('sso_delete_value').value}); }
                function setCf(e) { e.preventDefault(); apiCall('/manager/api/set_cf_clearance', {cf_clearance: document.getElementById('cf_value').value}); }
                </script></body></html>""")
            logger.info(f"创建了 '{manager_html_path}' 模板。", "Setup")
    
    logger.info(f"启动 Flask 服务于 0.0.0.0:{CONFIG['SERVER']['PORT']}...", "Setup")
    app.run(
        host='0.0.0.0',
        port=CONFIG["SERVER"]["PORT"],
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true" # Enable debug if FLASK_DEBUG=true
    )
