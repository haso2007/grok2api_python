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
import requests # 新增导入，如果Utils.get_dynamic_statsig_id中使用requests
from flask import Flask, request, Response, jsonify, stream_with_context, render_template, redirect, session
from curl_cffi import requests as curl_requests
from werkzeug.middleware.proxy_fix import ProxyFix

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
            caller_frame = frame.f_back.f_back
            full_path = caller_frame.f_code.co_filename
            function = caller_frame.f_code.co_name
            lineno = caller_frame.f_lineno
            filename = os.path.basename(full_path)
            return {
                'filename': filename,
                'function': function,
                'lineno': lineno
            }
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

    async def request_logger(self, request):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"请求: {request.method} {request.path}", "Request")

logger = Logger(level="INFO") # 全局logger实例

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
        "RETRYSWITCH": False,
        "MAX_ATTEMPTS": 2
    },
    "TOKEN_STATUS_FILE": str(DATA_DIR / "token_status.json"),
    "SHOW_THINKING": os.environ.get("SHOW_THINKING") == "true",
    "IS_THINKING": False,
    "IS_IMG_GEN": False,
    "IS_IMG_GEN2": False,
    "ISSHOW_SEARCH_RESULTS": os.environ.get("ISSHOW_SEARCH_RESULTS", "true").lower() == "true"
}

DEFAULT_HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Content-Type': 'text/plain;charset=UTF-8',
    'Connection': 'keep-alive',
    'Origin': 'https://grok.com',
    'Priority': 'u=1, i',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Sec-Ch-Ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"macOS"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Baggage': 'sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c'
}

class AuthTokenManager:
    def __init__(self):
        self.token_model_map = {}
        self.expired_tokens = set()
        self.token_status_map = {}
        self.model_config = {
            "grok-2": {
                "RequestFrequency": 30,
                "ExpirationTime": 1 * 60 * 60 * 1000  # 1小时
            },
            "grok-3": {
                "RequestFrequency": 20,
                "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
            },
            "grok-3-deepsearch": {
                "RequestFrequency": 10,
                "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
            },
            "grok-3-deepersearch": {
                "RequestFrequency": 3,
                "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
            },
            "grok-3-reasoning": {
                "RequestFrequency": 10,
                "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
            }
        }
        self.token_reset_switch = False
        self.token_reset_timer = None
        self.load_token_status() # 加载令牌状态

    def save_token_status(self):
        try:
            with open(CONFIG["TOKEN_STATUS_FILE"], 'w', encoding='utf-8') as f:
                json.dump(self.token_status_map, f, indent=2, ensure_ascii=False)
            logger.info("令牌状态已保存到配置文件", "TokenManager")
        except Exception as error:
            logger.error(f"保存令牌状态失败: {str(error)}", "TokenManager")

    def load_token_status(self):
        try:
            token_status_file = Path(CONFIG["TOKEN_STATUS_FILE"])
            if token_status_file.exists():
                with open(token_status_file, 'r', encoding='utf-8') as f:
                    self.token_status_map = json.load(f)
                logger.info("已从配置文件加载令牌状态", "TokenManager")
        except Exception as error:
            logger.error(f"加载令牌状态失败: {str(error)}", "TokenManager")

    def add_token(self, token,isinitialization=False):
        sso = token.split("sso=")[1].split(";")[0]
        for model in self.model_config.keys():
            if model not in self.token_model_map:
                self.token_model_map[model] = []
            if sso not in self.token_status_map:
                self.token_status_map[sso] = {}
            existing_token_entry = next((entry for entry in self.token_model_map[model] if entry["token"] == token), None)
            if not existing_token_entry:
                self.token_model_map[model].append({
                    "token": token,
                    "RequestCount": 0,
                    "AddedTime": int(time.time() * 1000),
                    "StartCallTime": None
                })
                if model not in self.token_status_map[sso]:
                    self.token_status_map[sso][model] = {
                        "isValid": True,
                        "invalidatedTime": None,
                        "totalRequestCount": 0
                    }
        if not isinitialization:
            self.save_token_status()

    def set_token(self, token):
        models = list(self.model_config.keys())
        self.token_model_map = {model: [{
            "token": token,
            "RequestCount": 0,
            "AddedTime": int(time.time() * 1000),
            "StartCallTime": None
        }] for model in models}
        sso = token.split("sso=")[1].split(";")[0]
        self.token_status_map[sso] = {model: {
            "isValid": True,
            "invalidatedTime": None,
            "totalRequestCount": 0
        } for model in models}

    def delete_token(self, token):
        try:
            sso = token.split("sso=")[1].split(";")[0]
            for model in self.token_model_map:
                self.token_model_map[model] = [entry for entry in self.token_model_map[model] if entry["token"] != token]
            if sso in self.token_status_map:
                del self.token_status_map[sso]

            self.save_token_status()
            logger.info(f"令牌已成功移除: {token}", "TokenManager")
            return True
        except Exception as error:
            logger.error(f"令牌删除失败: {str(error)}")
            return False

    def reduce_token_request_count(self, model_id, count):
        try:
            normalized_model = self.normalize_model_name(model_id)

            if normalized_model not in self.token_model_map:
                logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
                return False

            if not self.token_model_map[normalized_model]:
                logger.error(f"模型 {normalized_model} 没有可用的token", "TokenManager")
                return False

            token_entry = self.token_model_map[normalized_model][0]

            # 确保RequestCount不会小于0
            new_count = max(0, token_entry["RequestCount"] - count)
            reduction = token_entry["RequestCount"] - new_count

            token_entry["RequestCount"] = new_count

            # 更新token状态
            if token_entry["token"]:
                sso = token_entry["token"].split("sso=")[1].split(";")[0]
                if sso in self.token_status_map and normalized_model in self.token_status_map[sso]:
                    self.token_status_map[sso][normalized_model]["totalRequestCount"] = max(
                        0,
                        self.token_status_map[sso][normalized_model]["totalRequestCount"] - reduction
                    )
            return True

        except Exception as error:
            logger.error(f"重置校对token请求次数时发生错误: {str(error)}", "TokenManager")
            return False

    def get_next_token_for_model(self, model_id, is_return=False):
        normalized_model = self.normalize_model_name(model_id)
        if normalized_model not in self.token_model_map or not self.token_model_map[normalized_model]:
            return None
        token_entry = self.token_model_map[normalized_model][0]
        if is_return:
            return token_entry["token"]
        if token_entry:
            if token_entry["StartCallTime"] is None:
                token_entry["StartCallTime"] = int(time.time() * 1000)
            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True
            token_entry["RequestCount"] += 1
            if token_entry["RequestCount"] > self.model_config[normalized_model]["RequestFrequency"]:
                self.remove_token_from_model(normalized_model, token_entry["token"])
                next_token_entry = self.token_model_map[normalized_model][0] if self.token_model_map[normalized_model] else None
                return next_token_entry["token"] if next_token_entry else None
            sso = token_entry["token"].split("sso=")[1].split(";")[0]
            if sso in self.token_status_map and normalized_model in self.token_status_map[sso]:
                if token_entry["RequestCount"] == self.model_config[normalized_model]["RequestFrequency"]:
                    self.token_status_map[sso][normalized_model]["isValid"] = False
                    self.token_status_map[sso][normalized_model]["invalidatedTime"] = int(time.time() * 1000)
                self.token_status_map[sso][normalized_model]["totalRequestCount"] += 1
                self.save_token_status()
            return token_entry["token"]
        return None

    def remove_token_from_model(self, model_id, token):
        normalized_model = self.normalize_model_name(model_id)
        if normalized_model not in self.token_model_map:
            logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
            return False
        model_tokens = self.token_model_map[normalized_model]
        token_index = next((i for i, entry in enumerate(model_tokens) if entry["token"] == token), -1)
        if token_index != -1:
            removed_token_entry = model_tokens.pop(token_index)
            self.expired_tokens.add((
                removed_token_entry["token"],
                normalized_model,
                int(time.time() * 1000)
            ))
            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True
            logger.info(f"模型{model_id}的令牌已失效，已成功移除令牌: {token}", "TokenManager")
            return True
        logger.error(f"在模型 {normalized_model} 中未找到 token: {token}", "TokenManager")
        return False

    def get_expired_tokens(self):
        return list(self.expired_tokens)

    def normalize_model_name(self, model):
        if model.startswith('grok-') and 'deepsearch' not in model and 'reasoning' not in model:
            return '-'.join(model.split('-')[:2])
        return model

    def get_token_count_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return len(self.token_model_map.get(normalized_model, []))

    def get_remaining_token_request_capacity(self):
        remaining_capacity_map = {}
        for model in self.model_config.keys():
            model_tokens = self.token_model_map.get(model, [])
            model_request_frequency = self.model_config[model]["RequestFrequency"]
            total_used_requests = sum(token_entry.get("RequestCount", 0) for token_entry in model_tokens)
            remaining_capacity = (len(model_tokens) * model_request_frequency) - total_used_requests
            remaining_capacity_map[model] = max(0, remaining_capacity)
        return remaining_capacity_map

    def get_token_array_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return self.token_model_map.get(normalized_model, [])

    def start_token_reset_process(self):
        def reset_expired_tokens():
            now = int(time.time() * 1000)
            tokens_to_remove = set()
            for token_info in self.expired_tokens:
                token, model, expired_time = token_info
                expiration_time = self.model_config[model]["ExpirationTime"]
                if now - expired_time >= expiration_time:
                    if not any(entry["token"] == token for entry in self.token_model_map.get(model, [])):
                        if model not in self.token_model_map:
                            self.token_model_map[model] = []
                        self.token_model_map[model].append({
                            "token": token,
                            "RequestCount": 0,
                            "AddedTime": now,
                            "StartCallTime": None
                        })
                    sso = token.split("sso=")[1].split(";")[0]
                    if sso in self.token_status_map and model in self.token_status_map[sso]:
                        self.token_status_map[sso][model]["isValid"] = True
                        self.token_status_map[sso][model]["invalidatedTime"] = None
                        self.token_status_map[sso][model]["totalRequestCount"] = 0
                    tokens_to_remove.add(token_info)
            self.expired_tokens -= tokens_to_remove
            for model in self.model_config.keys():
                if model not in self.token_model_map:
                    continue
                for token_entry in self.token_model_map[model]:
                    if not token_entry.get("StartCallTime"):
                        continue
                    expiration_time = self.model_config[model]["ExpirationTime"]
                    if now - token_entry["StartCallTime"] >= expiration_time:
                        sso = token_entry["token"].split("sso=")[1].split(";")[0]
                        if sso in self.token_status_map and model in self.token_status_map[sso]:
                            self.token_status_map[sso][model]["isValid"] = True
                            self.token_status_map[sso][model]["invalidatedTime"] = None
                            self.token_status_map[sso][model]["totalRequestCount"] = 0
                        token_entry["RequestCount"] = 0
                        token_entry["StartCallTime"] = None
        import threading
        def run_timer():
            while True:
                reset_expired_tokens()
                time.sleep(3600)
        timer_thread = threading.Thread(target=run_timer)
        timer_thread.daemon = True
        timer_thread.start()

    def get_all_tokens(self):
        all_tokens = set()
        for model_tokens in self.token_model_map.values():
            for entry in model_tokens:
                all_tokens.add(entry["token"])
        return list(all_tokens)

    def get_current_token(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        if normalized_model not in self.token_model_map or not self.token_model_map[normalized_model]:
            return None
        token_entry = self.token_model_map[normalized_model][0]
        return token_entry["token"]

    def get_token_status_map(self):
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
        # This method seems to be used for getting the SSO cookie for the 'Cookie' header
        # We will call get_next_token_for_model directly for that purpose.
        # The new x-statsig-id and x-xai-request-id will be handled separately.
        return token_manager.get_next_token_for_model(model, is_return)

    @staticmethod
    def get_dynamic_statsig_id():
        """
        Fetches the dynamic x-statsig-id from the specified endpoint.
        """
        url = "https://grok-statsig.vercel.app/get_grok_statsig"
        try:
            # Using standard requests library here, as curl_cffi might be specific for impersonation
            response = requests.get(url, timeout=10) # Added timeout
            response.raise_for_status() # Raise an exception for HTTP errors
            data = response.json()
            statsig_id = data.get("id")
            if statsig_id:
                logger.info(f"Successfully fetched x-statsig-id: {statsig_id}", "Utils")
                return statsig_id
            else:
                logger.error("Failed to get 'id' key from statsig response.", "Utils")
                return None # Or a default fallback if preferred
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching x-statsig-id: {e}", "Utils")
            return None # Or a default fallback
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from statsig response: {e}", "Utils")
            return None # Or a default fallback

    @staticmethod
    def get_proxy_options():
        proxy = CONFIG["API"]["PROXY"]
        proxy_options = {}
        if proxy:
            logger.info(f"使用代理: {proxy}", "Server")

            if proxy.startswith("socks5://"):
                proxy_options["proxy"] = proxy # For curl_cffi

                if '@' in proxy:
                    auth_part = proxy.split('@')[0].split('://')[1]
                    if ':' in auth_part:
                        username, password = auth_part.split(':')
                        proxy_options["proxy_auth"] = (username, password) # For curl_cffi
            else:
                proxy_options["proxies"] = {"https": proxy, "http": proxy} # For standard requests
        return proxy_options

class GrokApiClient:
    def __init__(self, model_id):
        if model_id not in CONFIG["MODELS"]:
            raise ValueError(f"不支持的模型: {model_id}")
        self.model_id = CONFIG["MODELS"][model_id]

    def process_message_content(self, content):
        if isinstance(content, str):
            return content
        return None

    def get_image_type(self, base64_string):
        mime_type = 'image/jpeg'
        if 'data:image' in base64_string:
            import re
            matches = re.search(r'data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,', base64_string)
            if matches:
                mime_type = matches.group(1)
        extension = mime_type.split('/')[1]
        file_name = f"image.{extension}"
        return {
            "mimeType": mime_type,
            "fileName": file_name
        }

    def upload_base64_file(self, message, model):
        try:
            message_base64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
            upload_data = {
                "fileName": "message.txt",
                "fileMimeType": "text/plain",
                "content": message_base64
            }
            logger.info("发送文字文件请求", "Server")
            cookie = f"{Utils.create_auth_headers(model, True)};{CONFIG['SERVER']['CF_CLEARANCE']}"
            proxy_options = Utils.get_proxy_options()

            # --- 开始修改 ---
            statsig_id = Utils.get_dynamic_statsig_id()
            if not statsig_id:
                 # Fallback or error handling if statsig_id couldn't be fetched
                 # For now, let's use a placeholder or raise an error if it's critical
                 logger.warning("x-statsig-id could not be fetched. Request might fail.", "Server")
                 # statsig_id = "YOUR_FALLBACK_STATSIG_ID_IF_ANY" # Optional: define a fallback
                 # Or raise an error:
                 # raise Exception("Failed to fetch necessary x-statsig-id for file upload.")

            dynamic_headers = {
                "x-statsig-id": statsig_id or "fallback-if-needed-or-omit", # Ensure it's present or handle None
                "x-xai-request-id": str(uuid.uuid4())
            }
            # --- 结束修改 ---

            response = curl_requests.post(
                "https://grok.com/rest/app-chat/upload-file",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie": cookie,
                    **dynamic_headers # Add dynamic headers here
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options
            )
            if response.status_code != 200:
                logger.error(f"上传文件失败,状态码:{response.status_code}", "Server")
                raise Exception(f"上传文件失败,状态码:{response.status_code}")
            result = response.json()
            logger.info(f"上传文件成功: {result}", "Server")
            return result.get("fileMetadataId", "")
        except Exception as error:
            logger.error(str(error), "Server")
            raise Exception(f"上传文件过程中发生错误: {str(error)}") # More specific error

    def upload_base64_image(self, base64_data, url, model_for_cookie): # Added model_for_cookie
        try:
            if 'data:image' in base64_data:
                image_buffer = base64_data.split(',')[1]
            else:
                image_buffer = base64_data
            image_info = self.get_image_type(base64_data)
            mime_type = image_info["mimeType"]
            file_name = image_info["fileName"]
            upload_data = {
                "rpc": "uploadFile",
                "req": {
                    "fileName": file_name,
                    "fileMimeType": mime_type,
                    "content": image_buffer
                }
            }
            logger.info("发送图片请求", "Server")
            proxy_options = Utils.get_proxy_options()

            # --- 开始修改 ---
            # Determine the cookie. If CONFIG["SERVER"]['COOKIE'] is already set (e.g. via custom SSO), use it.
            # Otherwise, generate it using the model associated with the image upload context.
            current_cookie = CONFIG["SERVER"]['COOKIE']
            if not current_cookie or not Utils.create_auth_headers(model_for_cookie, True) in current_cookie:
                 # This logic might need adjustment based on how COOKIE is managed globally vs per-request
                auth_cookie_part = Utils.create_auth_headers(model_for_cookie, True)
                if CONFIG['SERVER']['CF_CLEARANCE']:
                    current_cookie = f"{auth_cookie_part};{CONFIG['SERVER']['CF_CLEARANCE']}"
                else:
                    current_cookie = auth_cookie_part


            statsig_id = Utils.get_dynamic_statsig_id()
            if not statsig_id:
                 logger.warning("x-statsig-id could not be fetched for image upload. Request might fail.", "Server")
                 # statsig_id = "YOUR_FALLBACK_STATSIG_ID_IF_ANY"

            dynamic_headers = {
                "x-statsig-id": statsig_id or "fallback-if-needed-or-omit",
                "x-xai-request-id": str(uuid.uuid4())
            }
            # --- 结束修改 ---

            response = curl_requests.post(
                url, # This is "https://grok.com/api/rpc"
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie": current_cookie, # Use the determined cookie
                    **dynamic_headers # Add dynamic headers here
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options
            )
            if response.status_code != 200:
                logger.error(f"上传图片失败,状态码:{response.status_code}", "Server")
                return ''
            result = response.json()
            logger.info(f"上传图片成功: {result}", "Server")
            return result.get("fileMetadataId", "")
        except Exception as error:
            logger.error(str(error), "Server")
            return ''

    def prepare_chat_request(self, request_data): # Renamed 'request' to 'request_data' to avoid conflict with flask.request
        if ((request_data["model"] == 'grok-2-imageGen' or request_data["model"] == 'grok-3-imageGen') and
            not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"] and
            request_data.get("stream", False)):
            raise ValueError("该模型流式输出需要配置PICGO或者TUMY图床密钥!")

        todo_messages = request_data["messages"]
        if request_data["model"] in ['grok-2-imageGen', 'grok-3-imageGen', 'grok-3-deepsearch']:
            last_message = todo_messages[-1]
            if last_message["role"] != 'user':
                raise ValueError('此模型最后一条消息必须是用户消息!')
            todo_messages = [last_message]

        file_attachments = []
        messages_str = '' # Renamed 'messages' to 'messages_str' to avoid conflict
        last_role = None
        last_content = ''
        message_length = 0
        convert_to_file = False
        last_message_content = ''
        search = request_data["model"] in ['grok-2-search', 'grok-3-search']
        deepsearchPreset = ''
        if request_data["model"] == 'grok-3-deepsearch':
            deepsearchPreset = 'default'
        elif request_data["model"] == 'grok-3-deepersearch':
            deepsearchPreset = 'deeper'

        def remove_think_tags(text):
            import re
            text = re.sub(r'<think>[\s\S]*?<\/think>', '', text).strip()
            text = re.sub(r'!\[image\]\(data:.*?base64,.*?\)', '[图片]', text)
            return text

        def process_content(content):
            if isinstance(content, list):
                text_content = ''
                for item in content:
                    if item["type"] == 'image_url':
                        text_content += ("[图片]" if not text_content else '\n[图片]')
                    elif item["type"] == 'text':
                        text_content += (remove_think_tags(item["text"]) if not text_content else '\n' + remove_think_tags(item["text"]))
                return text_content
            elif isinstance(content, dict) and content is not None:
                if content["type"] == 'image_url':
                    return "[图片]"
                elif content["type"] == 'text':
                    return remove_think_tags(content["text"])
            return remove_think_tags(self.process_message_content(content))

        for current_index, current in enumerate(todo_messages):
            role = 'assistant' if current["role"] == 'assistant' else 'user'
            is_last_message = current_index == len(todo_messages) - 1 # Corrected is_last_message logic

            if is_last_message and "content" in current:
                if isinstance(current["content"], list):
                    for item in current["content"]:
                        if item["type"] == 'image_url':
                            processed_image = self.upload_base64_image(
                                item["image_url"]["url"],
                                f"{CONFIG['API']['BASE_URL']}/api/rpc",
                                request_data["model"] # Pass model for cookie generation context
                            )
                            if processed_image:
                                file_attachments.append(processed_image)
                elif isinstance(current["content"], dict) and current["content"].get("type") == 'image_url':
                    processed_image = self.upload_base64_image(
                        current["content"]["image_url"]["url"],
                        f"{CONFIG['API']['BASE_URL']}/api/rpc",
                        request_data["model"] # Pass model for cookie generation context
                    )
                    if processed_image:
                        file_attachments.append(processed_image)

            text_content = process_content(current.get("content", ""))
            if is_last_message and convert_to_file:
                last_message_content = f"{role.upper()}: {text_content or '[图片]'}\n"
                continue

            if text_content or (is_last_message and file_attachments):
                if role == last_role and text_content:
                    last_content += '\n' + text_content
                    if messages_str.rfind(f"{role.upper()}: ") != -1: # Check if marker exists
                         messages_str = messages_str[:messages_str.rindex(f"{role.upper()}: ")] + f"{role.upper()}: {last_content}\n"
                    else: # If marker not found (e.g. first message or different structure)
                         messages_str += f"{role.upper()}: {last_content}\n" # Append normally
                else:
                    messages_str += f"{role.upper()}: {text_content or '[图片]'}\n"
                    last_content = text_content
                    last_role = role

            message_length += len(messages_str) # Use the correct variable name
            if message_length >= 40000:
                convert_to_file = True

        if convert_to_file:
            file_id = self.upload_base64_file(messages_str, request_data["model"]) # Use correct variable
            if file_id:
                file_attachments.insert(0, file_id)
            messages_str = last_message_content.strip() # Use correct variable

        if messages_str.strip() == '': # Use correct variable
            if convert_to_file:
                messages_str = '基于txt文件内容进行回复：' # Use correct variable
            else:
                raise ValueError('消息内容为空!')

        return {
            "temporary": CONFIG["API"].get("IS_TEMP_CONVERSATION", False),
            "modelName": self.model_id,
            "message": messages_str.strip(), # Use correct variable
            "fileAttachments": file_attachments[:4],
            "imageAttachments": [],
            "disableSearch": False,
            "enableImageGeneration": True,
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "enableImageStreaming": False,
            "imageGenerationCount": 1,
            "forceConcise": False,
            "toolOverrides": {
                "imageGen": request_data["model"] in ['grok-2-imageGen', 'grok-3-imageGen'],
                "webSearch": search,
                "xSearch": search,
                "xMediaSearch": search,
                "trendsSearch": search,
                "xPostAnalyze": search
            },
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "customPersonality": "",
            "deepsearchPreset": deepsearchPreset,
            "isReasoning": request_data["model"] == 'grok-3-reasoning',
            "disableTextFollowUps": True
        }

class MessageProcessor:
    @staticmethod
    def create_chat_response(message, model, is_stream=False):
        base_response = {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "created": int(time.time()),
            "model": model
        }
        if is_stream:
            return {
                **base_response,
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": message
                    }
                }]
            }
        return {
            **base_response,
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": message
                },
                "finish_reason": "stop"
            }],
            "usage": None # Typically, usage is added at the end for non-streaming
        }

def process_model_response(response, model):
    result = {"token": None, "imageUrl": None}
    if CONFIG["IS_IMG_GEN"]:
        if response.get("cachedImageGenerationResponse") and not CONFIG["IS_IMG_GEN2"]:
            result["imageUrl"] = response["cachedImageGenerationResponse"]["imageUrl"]
        return result
    if model == 'grok-2':
        result["token"] = response.get("token")
    elif model in ['grok-2-search', 'grok-3-search']:
        if response.get("webSearchResults") and CONFIG["ISSHOW_SEARCH_RESULTS"]:
            result["token"] = f"\r\n<think>{Utils.organize_search_results(response['webSearchResults'])}</think>\r\n"
        else:
            result["token"] = response.get("token")
    elif model == 'grok-3':
        result["token"] = response.get("token")
    elif model in ['grok-3-deepsearch', 'grok-3-deepersearch']:
        if response.get("messageStepId") and not CONFIG["SHOW_THINKING"]:
            return result # Return early, no token
        if response.get("messageStepId") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "final":
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        elif (response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "assistant") or response.get("messageTag") == "final":
            result["token"] = response.get("token","")
        elif (CONFIG["IS_THINKING"] and isinstance(response.get("token"), dict) and response.get("token",{}).get("action","") == "webSearch"): # Check if token is dict
            result["token"] = response.get("token",{}).get("action_input",{}).get("query","")
        elif (CONFIG["IS_THINKING"] and response.get("webSearchResults")):
            result["token"] = Utils.organize_search_results(response['webSearchResults'])
    elif model == 'grok-3-reasoning':
        if response.get("isThinking") and not CONFIG["SHOW_THINKING"]:
            return result # Return early, no token
        if response.get("isThinking") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("isThinking") and CONFIG["IS_THINKING"]:
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        else:
            result["token"] = response.get("token")
    return result

def handle_image_response(image_url):
    max_retries = 2
    retry_count = 0
    image_base64_response = None
    # Determine which proxy settings to use (curl_cffi or standard requests)
    proxy_options_curl = Utils.get_proxy_options() # For curl_cffi
    proxy_options_std = proxy_options_curl.get("proxies", None) # For standard requests if applicable

    while retry_count < max_retries:
        try:
            # Use curl_requests as it's used for other Grok interactions and supports impersonation
            image_base64_response = curl_requests.get(
                f"https://assets.grok.com/{image_url}",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie":CONFIG["SERVER"]['COOKIE'] # Assuming this cookie is valid for assets
                },
                impersonate="chrome133a",
                proxies=proxy_options_std, # if curl_requests doesn't use 'proxy' and 'proxy_auth' directly
                proxy=proxy_options_curl.get("proxy"), # if curl_requests uses these
                proxy_auth=proxy_options_curl.get("proxy_auth")
            )
            if image_base64_response.status_code == 200:
                break
            retry_count += 1
            if retry_count == max_retries:
                raise Exception(f"上游服务请求失败! status: {image_base64_response.status_code}")
            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)
        except Exception as error:
            logger.error(str(error), "Server")
            retry_count += 1
            if retry_count == max_retries:
                raise
            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

    image_buffer = image_base64_response.content
    if not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"]:
        base64_image = base64.b64encode(image_buffer).decode('utf-8')
        image_content_type = image_base64_response.headers.get('content-type', 'image/jpeg')
        return f"![image](data:{image_content_type};base64,{base64_image})"

    logger.info("开始上传图床", "Server")
    # Standard requests library for PicGo/TuMy as in original code
    std_proxies = Utils.get_proxy_options().get("proxies")

    if CONFIG["API"]["PICGO_KEY"]:
        files = {'source': ('image.jpg', image_buffer, 'image/jpeg')}
        headers = {"X-API-Key": CONFIG["API"]["PICGO_KEY"]}
        response_url = requests.post("https://www.picgo.net/api/1/upload", files=files, headers=headers, proxies=std_proxies)
        if response_url.status_code != 200:
            return "生图失败，请查看PICGO图床密钥是否设置正确"
        else:
            logger.info("生图成功", "Server")
            result = response_url.json()
            return f"![image]({result['image']['url']})"

    elif CONFIG["API"]["TUMY_KEY"]:
        files = {'file': ('image.jpg', image_buffer, 'image/jpeg')}
        headers = {"Accept": "application/json", 'Authorization': f"Bearer {CONFIG['API']['TUMY_KEY']}"}
        response_url = requests.post("https://tu.my/api/v1/upload", files=files, headers=headers, proxies=std_proxies)
        if response_url.status_code != 200:
            return "生图失败，请查看TUMY图床密钥是否设置正确"
        else:
            try:
                result = response_url.json()
                logger.info("生图成功", "Server")
                return f"![image]({result['data']['links']['url']})"
            except Exception as error:
                logger.error(str(error), "Server")
                return "生图失败，请查看TUMY图床密钥是否设置正确"
    return "图床未配置" # Fallback


def handle_non_stream_response(response, model):
    try:
        logger.info("开始处理非流式响应", "Server")
        # iter_lines might not be ideal if the full response isn't line-delimited JSON chunks
        # If the non-stream response is a single JSON object or concatenated JSON, adjust parsing.
        # Assuming it's still line-delimited for now, like streaming.
        full_response_content = ""
        CONFIG["IS_THINKING"] = False # Reset states for each call
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False

        # It's possible non-stream returns a single block of text or a single JSON object
        # For grok, it's usually a stream of JSON objects even for "non-stream" in OpenAI terms.
        # If it's truly one JSON object at the end, then response.json() would be used.
        # The original code implies iter_lines for both, so we keep it.

        for chunk in response.iter_lines(): # iter_lines decodes by default with utf-8
            if not chunk:
                continue
            try:
                line_json_str = chunk.decode('utf-8').strip() # Ensure it's a string
                if not line_json_str: continue

                line_json = json.loads(line_json_str)

                if line_json.get("error"):
                    logger.error(json.dumps(line_json, indent=2), "Server")
                    # For non-stream, we might want to collect all errors or just the first
                    # Returning a specific error structure might be better than just a string
                    return json.dumps({"error": "RateLimitError or other API error", "details": line_json.get("error")})

                response_data = line_json.get("result", {}).get("response")
                if not response_data:
                    continue

                if response_data.get("doImgGen") or response_data.get("imageAttachmentInfo"):
                    CONFIG["IS_IMG_GEN"] = True

                result = process_model_response(response_data, model)

                if result["token"] is not None: # Explicitly check for None as empty string is valid
                    full_response_content += result["token"]

                if result["imageUrl"]: # This implies image generation completed
                    CONFIG["IS_IMG_GEN2"] = True
                    # For non-stream, the image URL should be part of the final content
                    image_markdown = handle_image_response(result["imageUrl"])
                    full_response_content += f"\n{image_markdown}\n" # Append image markdown

            except json.JSONDecodeError as e:
                logger.warning(f"Non-JSON line in non-stream response: '{chunk.decode('utf-8', errors='ignore')}': {e}", "Server")
                # If the line is not JSON, and it's not an error, it might be part of the text.
                # However, Grok usually sends JSON lines. This might indicate an issue or an unexpected format.
                # For now, we skip non-JSON lines if they are not actual content.
                continue
            except Exception as e:
                logger.error(f"处理非流式响应行时出错: {str(e)}", "Server")
                continue
        return full_response_content
    except Exception as error:
        logger.error(f"处理非流式响应整体出错: {str(error)}", "Server")
        raise # Re-raise the exception to be caught by the caller

def handle_stream_response(response, model):
    def generate():
        logger.info("开始处理流式响应", "Server")
        CONFIG["IS_THINKING"] = False # Reset states for each call
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False

        for chunk in response.iter_lines(): # iter_lines decodes by default
            if not chunk:
                continue
            try:
                line_json_str = chunk.decode('utf-8').strip() # Ensure string
                if not line_json_str: continue

                # print(f"Raw chunk: {line_json_str}") # Debugging
                line_json = json.loads(line_json_str)

                if line_json.get("error"):
                    logger.error(json.dumps(line_json, indent=2), "Server")
                    error_payload = MessageProcessor.create_chat_response(
                        json.dumps({"error": "RateLimitError or API error", "details": line_json.get("error")}),
                        model,
                        True
                    )
                    # Change delta to have an error object perhaps, or just stringify
                    error_payload["choices"][0]["delta"]["content"] = f"Error: {line_json.get('error')}"
                    yield f"data: {json.dumps(error_payload)}\n\n"
                    # Optionally, could stop streaming here or let client handle
                    continue # Continue to see if more data comes or just yield done

                response_data = line_json.get("result", {}).get("response")
                if not response_data:
                    # logger.debug(f"Skipping chunk with no response_data: {line_json_str}", "Server")
                    continue

                if response_data.get("doImgGen") or response_data.get("imageAttachmentInfo"):
                    CONFIG["IS_IMG_GEN"] = True
                    logger.info("Image generation detected in stream.", "Server")


                result = process_model_response(response_data, model)

                if result["token"] is not None:
                    yield f"data: {json.dumps(MessageProcessor.create_chat_response(result['token'], model, True))}\n\n"

                if result["imageUrl"]: # Image is ready
                    CONFIG["IS_IMG_GEN2"] = True
                    logger.info(f"Image URL received in stream: {result['imageUrl']}", "Server")
                    try:
                        image_data = handle_image_response(result["imageUrl"])
                        yield f"data: {json.dumps(MessageProcessor.create_chat_response(image_data, model, True))}\n\n"
                    except Exception as img_e:
                        logger.error(f"Error handling image in stream: {img_e}", "Server")
                        yield f"data: {json.dumps(MessageProcessor.create_chat_response(f'[Error processing image: {img_e}]', model, True))}\n\n"

            except json.JSONDecodeError as e:
                # logger.warning(f"Skipping non-JSON line in stream: '{chunk.decode('utf-8', errors='ignore')}': {e}", "Server")
                continue # Skip non-JSON lines silently for streaming
            except Exception as e:
                logger.error(f"处理流式响应行时出错: {str(e)}", "Server")
                # Yield an error message to the client for this specific chunk error
                yield f"data: {json.dumps(MessageProcessor.create_chat_response(f'[Stream processing error: {str(e)}]', model, True))}\n\n"
                continue
        yield "data: [DONE]\n\n"
    return generate()

def initialization():
    sso_array = os.environ.get("SSO", "").split(',')
    logger.info("开始加载令牌", "Server")
    token_manager.load_token_status() # Ensure this is called before add_token if it relies on pre-loaded state
    for sso in sso_array:
        if sso:
            token_manager.add_token(f"sso-rw={sso};sso={sso}",True)
    token_manager.save_token_status() # Save after initial additions
    logger.info(f"成功加载令牌: {json.dumps(token_manager.get_all_tokens(), indent=2)}", "Server")
    logger.info(f"令牌加载完成，共加载: {len(token_manager.get_all_tokens())}个令牌", "Server")
    if CONFIG["API"]["PROXY"]:
        logger.info(f"代理已设置: {CONFIG['API']['PROXY']}", "Server")
    # logger.info("初始化完成", "Server") # Moved to after app run setup

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)
app.json.sort_keys = False

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if CONFIG["ADMIN"]["MANAGER_SWITCH"] and CONFIG["ADMIN"]["PASSWORD"]: # Ensure password is set
        if request.method == 'POST':
            password = request.form.get('password')
            if password == CONFIG["ADMIN"]["PASSWORD"]:
                session['is_logged_in'] = True
                return redirect('/manager')
            return render_template('login.html', error=True)
        return render_template('login.html', error=False)
    else:
        return redirect('/') # Or a "manager disabled" page

def check_auth():
    if not CONFIG["ADMIN"]["MANAGER_SWITCH"] or not CONFIG["ADMIN"]["PASSWORD"]:
        return False # Manager disabled
    return session.get('is_logged_in', False)

@app.route('/manager')
def manager():
    if not check_auth():
        return redirect('/manager/login')
    # Ensure manager.html exists in a 'templates' directory
    return render_template('manager.html')

@app.route('/manager/api/get')
def get_manager_tokens():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(token_manager.get_token_status_map())

@app.route('/manager/api/add', methods=['POST'])
def add_manager_token():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get('sso')
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.add_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"success": True, "sso": sso, "status": token_manager.get_token_status_map().get(sso)})
    except Exception as e:
        logger.error(f"Manager add token error: {e}", "API")
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/delete', methods=['POST'])
def delete_manager_token():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get('sso')
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        if token_manager.delete_token(f"sso-rw={sso};sso={sso}"): # Assuming sso format is just the value
             return jsonify({"success": True, "sso_deleted": sso})
        else:
             return jsonify({"error": "Failed to delete token, or token not found", "sso_attempted": sso}), 404
    except Exception as e:
        logger.error(f"Manager delete token error: {e}", "API")
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/cf_clearance', methods=['POST'])
def setCf_Manager_clearance():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        cf_clearance = request.json.get('cf_clearance')
        # No need to check for None, empty string can clear it
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance
        logger.info(f"Manager set CF Clearance to: '{cf_clearance}'", "API")
        return jsonify({"success": True, "cf_clearance": cf_clearance})
    except Exception as e:
        logger.error(f"Manager set CF Clearance error: {e}", "API")
        return jsonify({"error": str(e)}), 500

@app.route('/get/tokens', methods=['GET'])
def get_tokens():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法获取轮询sso令牌状态'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    return jsonify(token_manager.get_token_status_map())

@app.route('/add/token', methods=['POST'])
def add_token_route(): # Renamed to avoid conflict with AuthTokenManager.add_token
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法添加sso令牌'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    try:
        sso = request.json.get('sso')
        if not sso: # Basic validation
            return jsonify({"error": "SSO value missing"}), 400
        token_manager.add_token(f"sso-rw={sso};sso={sso}")
        return jsonify(token_manager.get_token_status_map().get(sso, {})), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": f'添加sso令牌失败: {str(error)}'}), 500

@app.route('/set/cf_clearance', methods=['POST'])
def setCf_clearance_route(): # Renamed
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    try:
        cf_clearance = request.json.get('cf_clearance')
        # Allow empty string to clear it, no need to check "if not cf_clearance" strictly
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance
        logger.info(f"API set CF Clearance to: '{cf_clearance}'", "API")
        return jsonify({"message": '设置cf_clearance成功', "cf_clearance": cf_clearance}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": f'设置cf_clearance失败: {str(error)}'}), 500

@app.route('/delete/token', methods=['POST'])
def delete_token_route(): # Renamed
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法删除sso令牌'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    try:
        sso = request.json.get('sso')
        if not sso: # Basic validation
            return jsonify({"error": "SSO value missing"}), 400
        if token_manager.delete_token(f"sso-rw={sso};sso={sso}"):
            return jsonify({"message": '删除sso令牌成功', "sso_deleted": sso}), 200
        else:
            return jsonify({"message": '删除sso令牌失败或未找到', "sso_attempted": sso}), 404
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": f'删除sso令牌失败: {str(error)}'}), 500

@app.route('/v1/models', methods=['GET'])
def get_models():
    return jsonify({
        "object": "list",
        "data": [
            {
                "id": model_name, # Use model_name from loop
                "object": "model",
                "created": int(time.time()), # Or a fixed timestamp if models don't change
                "owned_by": "grok" # Or your organization
            }
            for model_name in CONFIG["MODELS"].keys() # Iterate through model names
        ]
    })

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    response_status_code = 500 # Default error status
    try:
        auth_token_header = request.headers.get('Authorization', '').replace('Bearer ', '')
        if auth_token_header:
            if CONFIG["API"]["IS_CUSTOM_SSO"]:
                # For custom SSO, the header IS the SSO token itself
                sso_value = auth_token_header
                full_sso_cookie = f"sso={sso_value};sso-rw={sso_value}" # Construct the cookie format
                token_manager.set_token(full_sso_cookie) # This will set this token for all models
                logger.info(f"Using custom SSO: {sso_value}", "ChatAPI")
            elif auth_token_header != CONFIG["API"]["API_KEY"]:
                response_status_code = 401
                return jsonify({"error": {'message': 'Unauthorized: Invalid API Key', 'type': 'auth_error'}}), response_status_code
            # If not IS_CUSTOM_SSO and API key is valid, proceed
        else:
            response_status_code = 401
            return jsonify({"error": {'message': 'API_KEY缺失', 'type': 'auth_error'}}), response_status_code

        data = request.json
        model = data.get("model")
        if not model or model not in CONFIG["MODELS"]:
            response_status_code = 400
            return jsonify({"error": {'message': f"Invalid or missing model: {model}", 'type': 'invalid_request_error'}}), response_status_code

        stream = data.get("stream", False)
        retry_count = 0
        grok_client = GrokApiClient(model) # model is validated above
        request_payload = grok_client.prepare_chat_request(data) # data is request.json
        logger.info(f"Prepared Grok Request Payload: {json.dumps(request_payload,indent=2, ensure_ascii=False)}", "ChatAPI")

        while retry_count < CONFIG["RETRY"]["MAX_ATTEMPTS"]:
            retry_count += 1
            current_sso_cookie = Utils.create_auth_headers(model) # Gets next available token for the model
            if not current_sso_cookie:
                # This means no tokens available for this model currently
                # If IS_CUSTOM_SSO, this path shouldn't be hit if set_token worked.
                # If not IS_CUSTOM_SSO, then pool is exhausted.
                logger.warning(f"No available token for model {model} on attempt {retry_count}.", "ChatAPI")
                if retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                     raise ValueError(f'该模型 {model} 无可用令牌，请稍后再试或添加新令牌。')
                time.sleep(1) # Brief pause before retry if configured for retries > 1
                continue # Try next attempt to get a token

            CONFIG["API"]["SIGNATURE_COOKIE"] = current_sso_cookie # Store the cookie being used for this attempt
            logger.info(f"Attempt {retry_count}: Using token for model {model}: {current_sso_cookie.split(';')[0]}...", "ChatAPI")
            logger.info(f"Remaining token capacity: {json.dumps(token_manager.get_remaining_token_request_capacity(), indent=2)}", "ChatAPI")

            if CONFIG['SERVER']['CF_CLEARANCE']:
                CONFIG["SERVER"]['COOKIE'] = f"{CONFIG['API']['SIGNATURE_COOKIE']};{CONFIG['SERVER']['CF_CLEARANCE']}"
            else:
                CONFIG["SERVER"]['COOKIE'] = CONFIG['API']['SIGNATURE_COOKIE']

            # --- Dynamic Headers for Grok Request ---
            statsig_id = Utils.get_dynamic_statsig_id()
            if not statsig_id :
                logger.error("Failed to fetch x-statsig-id. Aborting Grok request.", "ChatAPI")
                # This is likely a critical header, so fail if not present
                raise ValueError("无法获取 x-statsig-id, 请求中止。")

            grok_request_headers = {
                **DEFAULT_HEADERS,
                "Cookie": CONFIG["SERVER"]['COOKIE'],
                "x-statsig-id": statsig_id,
                "x-xai-request-id": str(uuid.uuid4())
            }
            # --- End Dynamic Headers ---

            try:
                proxy_options = Utils.get_proxy_options()
                # Pass proxy options correctly to curl_requests
                effective_proxy_options = {}
                if "proxy" in proxy_options: # For SOCKS
                    effective_proxy_options["proxy"] = proxy_options["proxy"]
                    if "proxy_auth" in proxy_options:
                        effective_proxy_options["proxy_auth"] = proxy_options["proxy_auth"]
                elif "proxies" in proxy_options: # For HTTP/HTTPS
                    effective_proxy_options["proxies"] = proxy_options["proxies"]


                response = curl_requests.post(
                    f"{CONFIG['API']['BASE_URL']}/rest/app-chat/conversations/new",
                    headers=grok_request_headers,
                    data=json.dumps(request_payload), # Ensure payload is JSON string
                    impersonate="chrome133a", # ensure this is a valid impersonate string
                    stream=True, # Always stream from backend, then decide how to send to client
                    **effective_proxy_options # Spread the correct proxy dict
                )
                logger.debug(f"Grok API request sent with cookie: {CONFIG['SERVER']['COOKIE']}", "ChatAPI")

                if response.status_code == 200:
                    response_status_code = 200
                    logger.info(f"请求成功 (Status 200) for model {model}.", "ChatAPI")
                    logger.info(f"当前 {model} 剩余可用令牌数: {token_manager.get_token_count_for_model(model)}", "ChatAPI")
                    try:
                        if stream: # If client requested stream
                            return Response(stream_with_context(handle_stream_response(response, model)), content_type='text/event-stream')
                        else: # Client requested non-stream
                            content = handle_non_stream_response(response, model)
                            if isinstance(content, str) and content.startswith('{"error":'): # Check if error JSON string
                                try:
                                    error_json = json.loads(content)
                                    return jsonify(error_json), 400 # Or appropriate error code
                                except json.JSONDecodeError:
                                    pass # Fall through to general error if not valid JSON
                            return jsonify(MessageProcessor.create_chat_response(content, model))
                    except Exception as processing_error: # Catch errors from handle_stream/non_stream_response
                        logger.error(f"Error processing Grok response: {processing_error}", "ChatAPI")
                        # This error might mean the token was valid but response processing failed.
                        # Consider if token should be invalidated here.
                        # For now, assume it's a processing or transient issue.
                        if CONFIG["API"]["IS_CUSTOM_SSO"]:
                             # Custom SSO is one-shot, if it fails, it fails.
                             raise ValueError(f"自定义SSO令牌在处理模型 {model} 的响应时失败: {processing_error}")
                        # For pooled tokens, maybe don't immediately remove unless it's a clear token issue.
                        # token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])
                        # if token_manager.get_token_count_for_model(model) == 0:
                        #     raise ValueError(f"{model} 次数已达上限或处理错误，请切换其他模型或者重新对话")
                        raise # Re-raise to be caught by the outer try-except

                elif response.status_code == 403:
                    response_status_code = 403
                    logger.warning(f"Grok API returned 403. IP/CF issue? Token: {current_sso_cookie.split(';')[0]}... Content: {response.text[:200]}", "ChatAPI")
                    token_manager.reduce_token_request_count(model,1) # Don't penalize token count for this
                    # This is likely not a token issue but an access/IP issue.
                    if retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                        raise ValueError(f"IP暂时被封(403 Forbidden)无法破盾，请稍后重试或者更换ip/CF token。")
                    time.sleep(2 * retry_count) # Longer sleep for 403
                    continue # Retry

                elif response.status_code == 401: # Unauthorized - Could be bad SSO cookie
                    response_status_code = 401
                    logger.warning(f"Grok API returned 401. Bad token? Token: {current_sso_cookie.split(';')[0]}... Content: {response.text[:200]}", "ChatAPI")
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                         raise ValueError(f"自定义SSO令牌无效 (401 Unauthorized) for model {model}.")
                    token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"]) # Bad token, remove it
                    if token_manager.get_token_count_for_model(model) == 0 and retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                        raise ValueError(f"{model} 所有令牌均无效 (401)，请添加新令牌或检查现有令牌。")
                    continue # Retry with next token if available

                elif response.status_code == 429: # Rate limit
                    response_status_code = 429
                    logger.warning(f"Grok API returned 429. Rate limited. Token: {current_sso_cookie.split(';')[0]}...", "ChatAPI")
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                        raise ValueError(f"自定义SSO令牌已达速率限制 (429) for model {model}.")
                    # This token is rate-limited for now, remove it from active pool
                    token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])
                    if token_manager.get_token_count_for_model(model) == 0 and retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                        raise ValueError(f"{model} 所有可用令牌均已达速率上限 (429)。")
                    continue # Retry with next token if available

                else: # Other HTTP errors
                    response_status_code = response.status_code
                    logger.error(f"Grok API Error! Status: {response.status_code}, Response: {response.text[:500]}", "ChatAPI")
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                         raise ValueError(f"自定义SSO令牌请求失败，状态码: {response.status_code} for model {model}.")
                    # Potentially a bad token or other issue
                    token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])
                    if token_manager.get_token_count_for_model(model) == 0 and retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                        raise ValueError(f"{model} 模型请求失败，状态码: {response.status_code}，且无更多令牌可用。")
                    continue # Retry

            except curl_requests.RequestsError as e: # Catch cURL specific errors
                logger.error(f"curl_requests.RequestsError on attempt {retry_count} for {model}: {e}", "ChatAPI")
                # Network error, proxy error, etc. Don't necessarily invalidate token unless it's a clear auth issue.
                # For now, assume it's a network hiccup.
                if retry_count >= CONFIG["RETRY"]["MAX_ATTEMPTS"]:
                    raise ValueError(f"请求处理时发生网络或连接错误: {e}")
                time.sleep(1 * retry_count) # Wait a bit before retrying
                continue
            # The general Exception 'e' was too broad here for the retry loop, moved to outer catch.

        # If loop finishes without returning/raising, it means all retries failed.
        # This part should ideally not be reached if errors are raised correctly within the loop.
        if response_status_code != 200 : # Check if loop exhausted without success
            logger.error(f"All retry attempts failed for model {model}. Last status: {response_status_code}", "ChatAPI")
            raise ValueError(f'当前模型 {model} 所有令牌均暂无可用或请求失败，请稍后重试。Last status: {response_status_code}')


    except ValueError as ve: # Catch known value errors (like no token, bad sso)
        logger.error(f"ValueError in chat_completions: {str(ve)}", "ChatAPI")
        error_type = "invalid_request_error" if "model" in str(ve).lower() or "token" in str(ve).lower() else "server_error"
        # Determine appropriate status code based on error message
        if "401" in str(ve) or "Unauthorized" in str(ve): response_status_code = 401
        elif "403" in str(ve) or "Forbidden" in str(ve): response_status_code = 403
        elif "429" in str(ve): response_status_code = 429
        elif "令牌" in str(ve) or "token" in str(ve).lower(): response_status_code = 400 # Bad request if token issue
        else: response_status_code = 500 # Default to server error

        return jsonify({"error": {"message": str(ve), "type": error_type}}), response_status_code

    except Exception as error: # Catch all other unexpected errors
        logger.error(f"Unexpected error in chat_completions: {str(error)}", "ChatAPI", exc_info=True)
        return jsonify({"error": {"message": f"An unexpected error occurred: {str(error)}", "type": "server_error"}}), 500


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    # Could add a simple health check or status page here
    if path == "health":
        return jsonify({"status": "ok", "timestamp": time.time()}), 200
    return 'API 运行正常 (grok2api)', 200

if __name__ == '__main__':
    token_manager = AuthTokenManager() # Initialize token manager globally
    initialization() # Run initialization logic (loads tokens, etc.)
    logger.info("初始化完成，服务启动中...", "Server")
    # Make sure 'templates' directory exists if using render_template
    if CONFIG["ADMIN"]["MANAGER_SWITCH"] and not Path("templates").exists():
        Path("templates").mkdir(exist_ok=True)
        # Create dummy login.html and manager.html if they don't exist for manager to function
        if not Path("templates/login.html").exists():
            with open("templates/login.html", "w") as f:
                f.write("<h1>Login</h1><form method='post'><input type='password' name='password'><input type='submit' value='Login'></form>{% if error %}Invalid password{% endif %}")
        if not Path("templates/manager.html").exists():
            with open("templates/manager.html", "w") as f:
                f.write("<h1>Token Manager</h1><p>Implement manager UI here.</p><a href='/manager/login'>Logout (simulation)</a>")


    app.run(
        host='0.0.0.0',
        port=CONFIG["SERVER"]["PORT"],
        debug=False # Set to True for development if needed, but False for production
    )
