


   

import asyncio

import json

import time

from pathlib import Path

from typing import Dict, List, Optional, Tuple

from playwright.async_api import async_playwright, Browser, Page, BrowserContext

from dataclasses import dataclass

@dataclass

class AuthResult:

                                              

    success: bool

    method: str

    cookies: List[Dict]

    local_storage: Dict[str, str]

    session_token: Optional[str]

    error_message: Optional[str] = None

class BrowserAutomation:

    


       

    def __init__(self, headless: bool = True, timeout: int = 30000):

        self.headless = headless

        self.timeout = timeout

        self.browser: Optional[Browser] = None

        self.context: Optional[BrowserContext] = None

        self.page: Optional[Page] = None

    async def start(self):

                                         

        playwright = await async_playwright().start()

        self.browser = await playwright.chromium.launch(

            headless=self.headless,

            args=[

                '--no-sandbox',

                '--disable-setuid-sandbox',

                '--disable-dev-shm-usage',

                '--disable-accelerated-2d-canvas',

                '--disable-gpu'

            ]

        )

        return self

    async def stop(self):

                                       

        if self.browser:

            await self.browser.close()

            self.browser = None

    async def create_context(self, user_agent: Optional[str] = None) -> BrowserContext:

                                                                

        if not self.browser:

            raise RuntimeError("Browser not initialized. Call start() first.")

        context_args = {

            'viewport': {'width': 1920, 'height': 1080},

            'ignore_https_errors': True,

            'java_script_enabled': True,

        }

        if user_agent:

            context_args['user_agent'] = user_agent

        self.context = await self.browser.new_context(**context_args)

        return self.context

    async def detect_auth_forms(self, url: str) -> Dict[str, Optional[str]]:

        


           

        if not self.context:

            await self.create_context()

        self.page = await self.context.new_page()

        await self.page.goto(url, wait_until='networkidle', timeout=self.timeout)

        login_selectors = {

            'username': [

                'input[name="username"]',

                'input[name="user"]',

                'input[name="email"]',

                'input[type="email"]',

                '#username',

                '#user',

                '#email',

                'input[placeholder*="user" i]',

                'input[placeholder*="email" i]',

            ],

            'password': [

                'input[type="password"]',

                'input[name="password"]',

                '#password',

            ],

            'submit': [

                'button[type="submit"]',

                'input[type="submit"]',

                'button:has-text("Login")',

                'button:has-text("Sign In")',

                'button:has-text("Log In")',

                '.login-btn',

                '#login-btn',

            ],

            'register_link': [

                'a:has-text("Register")',

                'a:has-text("Sign Up")',

                'a[href*="register"]',

                'a[href*="signup"]',

                '.register-link',

                '#register-link',

            ]

        }

        detected = {

            'has_login': False,

            'has_register': False,

            'username_selector': None,

            'password_selector': None,

            'submit_selector': None,

            'register_link_selector': None,

            'is_admin_panel': False

        }

        for selector in login_selectors['username']:

            try:

                element = await self.page.query_selector(selector)

                if element:

                    detected['username_selector'] = selector

                    detected['has_login'] = True

                    break

            except:

                continue

        for selector in login_selectors['password']:

            try:

                element = await self.page.query_selector(selector)

                if element and detected['username_selector']:

                    detected['password_selector'] = selector

                    break

            except:

                continue

        for selector in login_selectors['submit']:

            try:

                element = await self.page.query_selector(selector)

                if element and detected['has_login']:

                    detected['submit_selector'] = selector

                    break

            except:

                continue

        for selector in login_selectors['register_link']:

            try:

                element = await self.page.query_selector(selector)

                if element:

                    detected['register_link_selector'] = selector

                    detected['has_register'] = True

                    break

            except:

                continue

        admin_keywords = ['admin', 'dashboard', 'wp-admin', 'cpanel', 'manager']

        page_content = await self.page.content()

        if any(keyword in page_content.lower() for keyword in admin_keywords):

            detected['is_admin_panel'] = True

        await self.page.close()

        return detected

    async def attempt_login(

        self, 

        url: str, 

        credentials: Dict[str, str],

        detected_forms: Optional[Dict] = None

    ) -> AuthResult:

        

           

        if not self.context:

            await self.create_context()

        self.page = await self.context.new_page()

        try:

            await self.page.goto(url, wait_until='networkidle', timeout=self.timeout)

            if not detected_forms:

                detected_forms = await self.detect_auth_forms(url)

            if not detected_forms['has_login']:

                return AuthResult(

                    success=False,

                    method='none',

                    cookies=[],

                    local_storage={},

                    session_token=None,

                    error_message="No login form detected"

                )

            if detected_forms['username_selector']:

                await self.page.fill(detected_forms['username_selector'], 

                                   credentials.get('username', credentials.get('email', '')))

            if detected_forms['password_selector']:

                await self.page.fill(detected_forms['password_selector'], 

                                   credentials['password'])

            if detected_forms['submit_selector']:

                await self.page.click(detected_forms['submit_selector'])

            else:

                await self.page.press(detected_forms['password_selector'], 'Enter')

            try:

                await self.page.wait_for_load_state('networkidle', timeout=10000)

            except:

                pass

            await asyncio.sleep(2)

            cookies = await self.context.cookies()

            local_storage = await self._get_local_storage()

            session_token = self._extract_session_token(cookies, local_storage)

            current_url = self.page.url

            login_success = (

                current_url != url or 

                session_token is not None or

                len([c for c in cookies if 'session' in c['name'].lower() or 'auth' in c['name'].lower()]) > 0

            )

            return AuthResult(

                success=login_success,

                method='login',

                cookies=cookies,

                local_storage=local_storage,

                session_token=session_token

            )

        except Exception as e:

            return AuthResult(

                success=False,

                method='login',

                cookies=[],

                local_storage={},

                session_token=None,

                error_message=str(e)

            )

        finally:

            await self.page.close()

    async def attempt_registration(

        self,

        url: str,

        credentials: Dict[str, str],

        detected_forms: Optional[Dict] = None

    ) -> AuthResult:

        

           

        if not self.context:

            await self.create_context()

        self.page = await self.context.new_page()

        try:

            await self.page.goto(url, wait_until='networkidle', timeout=self.timeout)

            if not detected_forms:

                detected_forms = await self.detect_auth_forms(url)

            if not detected_forms['has_register']:

                return AuthResult(

                    success=False,

                    method='none',

                    cookies=[],

                    local_storage={},

                    session_token=None,

                    error_message="No registration option detected"

                )

            if detected_forms['register_link_selector']:

                await self.page.click(detected_forms['register_link_selector'])

                await self.page.wait_for_load_state('networkidle', timeout=10000)

            import random

            import string

            username = credentials.get('username', f'user_{random.randint(1000, 9999)}')

            email = credentials.get('email', f'{username}@test.com')

            password = credentials.get('password', ''.join(random.choices(string.ascii_letters + string.digits, k=12)))

            reg_selectors = {

                'username': ['input[name="username"]', 'input[name="user"]', '#username'],

                'email': ['input[name="email"]', 'input[type="email"]', '#email'],

                'password': ['input[name="password"]', 'input[type="password"]', '#password'],

                'submit': ['button[type="submit"]', 'input[type="submit"]', '.register-btn']

            }

            for selector in reg_selectors['username']:

                try:

                    element = await self.page.query_selector(selector)

                    if element:

                        await self.page.fill(selector, username)

                        break

                except:

                    continue

            for selector in reg_selectors['email']:

                try:

                    element = await self.page.query_selector(selector)

                    if element:

                        await self.page.fill(selector, email)

                        break

                except:

                    continue

            for selector in reg_selectors['password']:

                try:

                    element = await self.page.query_selector(selector)

                    if element:

                        await self.page.fill(selector, password)

                        break

                except:

                    continue

            for selector in reg_selectors['submit']:

                try:

                    element = await self.page.query_selector(selector)

                    if element:

                        await self.page.click(selector)

                        break

                except:

                    continue

            await asyncio.sleep(3)

            await self.page.close()

            login_result = await self.attempt_login(

                url, 

                {'username': username, 'password': password}

            )

            if login_result.success:

                login_result.method = 'register'

            return login_result

        except Exception as e:

            return AuthResult(

                success=False,

                method='register',

                cookies=[],

                local_storage={},

                session_token=None,

                error_message=str(e)

            )

        finally:

            await self.page.close()

    async def _get_local_storage(self) -> Dict[str, str]:

                                                         

        if not self.page:

            return {}

        try:

            storage = await self.page.evaluate('() => { return Object.assign({}, localStorage) }')

            return storage

        except:

            return {}

    def _extract_session_token(self, cookies: List[Dict], local_storage: Dict[str, str]) -> Optional[str]:

                                                                

        session_names = ['session', 'auth', 'token', 'jwt', 'access', 'refresh', 'sid']

        for cookie in cookies:

            name_lower = cookie['name'].lower()

            if any(keyword in name_lower for keyword in session_names):

                return cookie['value']

        for key, value in local_storage.items():

            key_lower = key.lower()

            if any(keyword in key_lower for keyword in session_names):

                return value

        return None

    async def take_screenshot(self, save_path: str) -> str:

                                             

        if not self.page:

            raise RuntimeError("No active page")

        await self.page.screenshot(path=save_path, full_page=True)

        return save_path

    async def export_session(self, save_path: str) -> str:

                                                             

        if not self.context:

            raise RuntimeError("No active context")

        cookies = await self.context.cookies()

        local_storage = await self._get_local_storage()

        session_data = {

            'cookies': cookies,

            'local_storage': local_storage,

            'timestamp': time.time()

        }

        Path(save_path).parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, 'w') as f:

            json.dump(session_data, f, indent=2)

        return save_path

    async def import_session(self, load_path: str) -> bool:

                                      

        if not self.context:

            await self.create_context()

        with open(load_path, 'r') as f:

            session_data = json.load(f)

        cookies = session_data.get('cookies', [])

        if cookies:

            await self.context.add_cookies(cookies)

        return True

async def test_browser_automation():

                                              

    print("Testing Browser Automation...")

    automation = BrowserAutomation(headless=True)

    await automation.start()

    try:

        detected = await automation.detect_auth_forms('https://httpbin.org/forms/post')

        print(f"Detected forms: {detected}")

        print("✅ Browser automation test completed")

    except Exception as e:

        print(f"❌ Test failed: {e}")

    finally:

        await automation.stop()

if __name__ == '__main__':

    asyncio.run(test_browser_automation())
