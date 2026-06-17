"""
Browser Agent — Playwright-based browser automation for:
- Login flow handling (form auth, cookie injection)
- Dynamic page analysis (SPAs, JS-rendered content)
- DOM XSS detection via payload injection
- Screenshot evidence collection
"""

import time
import re
from typing import Optional
from pathlib import Path
from urllib.parse import urljoin, urlparse
from .agents.base import fmt_time

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
]


class BrowserAgent:
    """Browser-based security analysis agent.
    Supports chromium, firefox, and webkit (playwright).
    """

    def __init__(self, headless: bool = True, timeout: int = 15000, browser_type: str = "chromium"):
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && python3 -m playwright install")
        if browser_type not in ("chromium", "firefox", "webkit"):
            browser_type = "chromium"
        self.headless = headless
        self.timeout = timeout
        self.browser_type = browser_type
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

    def start(self):
        """Launch browser (chromium, firefox, or webkit)."""
        self._playwright = sync_playwright().start()
        browser_map = {
            "chromium": self._playwright.chromium,
            "firefox": self._playwright.firefox,
            "webkit": self._playwright.webkit,
        }
        browser_engine = browser_map.get(self.browser_type, self._playwright.chromium)
        self._browser = browser_engine.launch(headless=self.headless)
        self._context = self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        self._page = self._context.new_page()
        self._page.set_default_timeout(self.timeout)
        return self

    def close(self):
        """Close browser."""
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    def navigate(self, url: str) -> dict:
        """Navigate to a URL and return page info."""
        if not self._page:
            self.start()
        t0 = time.time()
        try:
            resp = self._page.goto(url, wait_until="networkidle", timeout=self.timeout)
            elapsed = fmt_time(time.time() - t0)
            info = {
                "url": self._page.url,
                "title": self._page.title(),
                "status": resp.status if resp else 0,
                "time": elapsed,
                "html_length": len(self._page.content()),
                "screenshot": None,
            }

            # Extract forms
            forms = self._page.evaluate("""() => Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type, id: e.id}))
            }))""")
            info["forms"] = forms

            # Extract links
            links = self._page.evaluate("""() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(h => h.startsWith('http'))""")
            info["links"] = list(set(links))[:50]

            # Extract scripts
            scripts = self._page.evaluate("""() => Array.from(document.scripts).map(s => s.src).filter(s => s)""")
            info["scripts"] = scripts[:20]

            # Check for tech indicators in window
            tech = self._detect_client_tech()
            info["client_tech"] = tech

            return info
        except PWTimeout:
            return {"url": url, "error": "timeout", "time": fmt_time(time.time() - t0)}
        except Exception as e:
            return {"url": url, "error": str(e), "time": fmt_time(time.time() - t0)}

    def login_form(self, url: str, username: str, password: str,
                   username_field: str = "input[name=username], input[name=email], input[type=email], input[name=login], #username, #email",
                   password_field: str = "input[name=password], input[type=password], #password",
                   submit_btn: str = "button[type=submit], input[type=submit], button:has-text('Login'), button:has-text('Sign in')") -> dict:
        """Automate form-based login."""
        t0 = time.time()
        info = self.navigate(url)
        if "error" in info:
            return info

        try:
            # Wait for form
            self._page.wait_for_selector(username_field.split(",")[0].strip(), timeout=5000)

            # Fill credentials
            uname_el = self._page.query_selector(username_field)
            if uname_el:
                uname_el.fill(username)
            pass_el = self._page.query_selector(password_field)
            if pass_el:
                pass_el.fill(password)

            # Submit
            submit_el = self._page.query_selector(submit_btn)
            if submit_el:
                submit_el.click()
            else:
                self._page.press(password_field.split(",")[0].strip(), "Enter")

            # Wait for navigation after login
            self._page.wait_for_load_state("networkidle", timeout=10000)

            # Check if login succeeded (URL changed or no login form visible)
            current_url = self._page.url
            login_still_visible = self._page.query_selector(username_field.split(",")[0].strip()) is not None
            success = current_url != url or not login_still_visible

            return {
                "success": success,
                "final_url": current_url,
                "cookies": self._context.cookies(),
                "time": fmt_time(time.time() - t0),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "time": fmt_time(time.time() - t0)}

    def inject_cookies(self, cookies: list):
        """Inject cookies into browser session."""
        if self._context:
            self._context.add_cookies(cookies)

    def screenshot(self, path: str = None) -> Optional[str]:
        """Take a screenshot."""
        if not self._page:
            return None
        if not path:
            path = f"/tmp/suvari_screenshot_{int(time.time())}.png"
        self._page.screenshot(path=path, full_page=True)
        return path

    def check_dom_xss(self, url: str, params: dict = None) -> list:
        """Check for DOM-based XSS by injecting payloads into URL parameters."""
        findings = []
        base_url = url.split("?")[0]

        if not params:
            # Extract existing URL parameters
            parsed = urlparse(url)
            if parsed.query:
                params = {p.split("=")[0]: "" for p in parsed.query.split("&")}
            else:
                # Try common parameter names
                params = {"q": "", "search": "", "id": "", "page": "", "name": ""}

        for param_name in params:
            for payload in XSS_PAYLOADS[:3]:  # Test first 3 payloads per param
                test_url = f"{base_url}?{param_name}={payload}"
                try:
                    info = self.navigate(test_url)
                    if "error" in info:
                        continue

                    # Check if payload is reflected in page
                    content = self._page.content()
                    reflected_payloads = [p for p in XSS_PAYLOADS if p in content and len(p) > 5]
                    if reflected_payloads:
                        findings.append({
                            "type": "DOM XSS (reflected)",
                            "parameter": param_name,
                            "payload": reflected_payloads[0],
                            "url": test_url[:150],
                            "severity": "HIGH",
                        })
                        break  # One finding per parameter is enough
                except Exception:
                    continue

        return findings

    def get_rendered_html(self, url: str) -> str:
        """Get fully rendered HTML (for SPAs)."""
        self.navigate(url)
        return self._page.content()

    def _detect_client_tech(self) -> list:
        """Detect client-side technologies."""
        tech = []
        try:
            checks = {
                "React": "window.__REACT_DEVTOOLS_GLOBAL_HOOK__",
                "Angular": "window.ng",
                "Vue": "window.__VUE__",
                "jQuery": "window.jQuery",
                "Next.js": "window.__NEXT_DATA__",
                "Nuxt.js": "window.__NUXT__",
                "Svelte": "window.__svelte",
            }
            for name, check in checks.items():
                if self._page.evaluate(f"typeof({check}) !== 'undefined'"):
                    tech.append(name)
        except Exception:
            pass
        return tech

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.close()

    def self_register(self, url: str, email_prefix: str = "suvari_test") -> dict:
        """Try to self-register on the target site."""
        import random
        import string

        t0 = time.time()
        page_info = self.navigate(url)
        if "error" in page_info:
            return page_info

        # Look for registration forms
        forms = page_info.get("forms", [])
        register_forms = []
        for f in forms:
            form_str = str(f).lower()
            if any(w in form_str for w in ["register", "signup", "sign-up", "create", "new account"]):
                register_forms.append(f)

        # Also look for register links/buttons
        try:
            reg_links = self._page.evaluate("""() => {
                const links = document.querySelectorAll('a[href*=\"register\"], a[href*=\"signup\"], a[href*=\"sign-up\"], a[href*=\"create-account\"]');
                return Array.from(links).map(a => a.href);
            }""")
            if reg_links and not register_forms:
                # Navigate to registration page
                self.navigate(reg_links[0])
                forms = page_info.get("forms", [])
                for f in forms:
                    form_str = str(f).lower()
                    if any(w in form_str for w in ["password", "email", "username"]):
                        register_forms.append(f)
        except Exception:
            pass

        if not register_forms:
            return {"success": False, "reason": "No registration form found"}

        # Generate random credentials
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        creds = {
            "email": f"{email_prefix}_{suffix}@test.com",
            "username": f"test_{suffix}",
            "password": f"TestPass_{suffix}!",
        }

        try:
            # Try filling the form
            for form_sel in ["input[name=email]", "input[type=email]", "#email"]:
                el = self._page.query_selector(form_sel)
                if el:
                    el.fill(creds["email"])
                    break
            for form_sel in ["input[name=username]", "input[name=user]", "#username", "#user"]:
                el = self._page.query_selector(form_sel)
                if el:
                    el.fill(creds["username"])
                    break
            for form_sel in ["input[name=password]", "input[type=password]", "#password"]:
                el = self._page.query_selector(form_sel)
                if el:
                    el.fill(creds["password"])
                    break
            # Confirm password if needed
            for form_sel in ["input[name=password_confirm]", "input[name=confirm_password]", "#confirm_password"]:
                el = self._page.query_selector(form_sel)
                if el:
                    el.fill(creds["password"])
                    break

            # Submit
            for btn_sel in ["button[type=submit]", "input[type=submit]", "button:has-text('Register')",
                            "button:has-text('Sign Up')", "button:has-text('Create')"]:
                btn = self._page.query_selector(btn_sel)
                if btn:
                    btn.click()
                    break

            self._page.wait_for_load_state("networkidle", timeout=8000)
            current_url = self._page.url

            return {
                "success": current_url != url or "error" not in self._page.content().lower(),
                "credentials": creds,
                "final_url": current_url,
                "time": fmt_time(time.time() - t0),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "credentials": creds}
