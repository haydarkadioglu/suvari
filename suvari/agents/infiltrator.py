"""
InfiltratorAgent: Otomatik Kayıt ve Giriş Yaparak Yetki Kazanma Agent'ı
"""
import asyncio
import random
import string
import json
from typing import Dict, Any, Optional, List
from playwright.async_api import async_playwright, Page, BrowserContext

# Use standard logging instead of custom logger
import logging
logger = logging.getLogger("InfiltratorAgent")

# Import config loader (Config class doesn't exist, use dict-based config)
from ..config import load_config

class InfiltratorAgent:
    """
    Hedef uygulamaya otomatik kayıt olup giriş yaparak 
    yetkili erişim token'ı/cookie'si elde eden agent.
    """
    
    def __init__(self, config: dict = None):
        self.config = config or load_config()
        self.name = "Infiltrator"
        self.description = "Otomatik kayıt ve giriş ile yetki kazanır"
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        
        # Rastgele kullanıcı üretimi için şablonlar
        self.domains = ["tempmail.com", "fakeinbox.org", "testmail.net"]
        
    async def _generate_credentials(self) -> Dict[str, str]:
        """Rastgele ama geçerli görünen kullanıcı bilgileri üretir."""
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return {
            "username": f"user_{rand_str}",
            "email": f"user_{rand_str}@{random.choice(self.domains)}",
            "password": f"TestPass_{rand_str}!",
            "full_name": f"Test User {rand_str}"
        }

    async def _find_form_fields(self, page: Page, url_type: str) -> Optional[Dict[str, str]]:
        """
        Sayfadaki form alanlarını tespit eder ve selector map döner.
        url_type: 'login' veya 'register'
        """
        # Basit heuristic selector denemeleri
        selectors = {
            "username": ["input[name='username']", "input[id='username']", "input[placeholder*='user']"],
            "email": ["input[name='email']", "input[id='email']", "input[type='email']", "input[placeholder*='email']"],
            "password": ["input[type='password']", "input[name='password']"],
            "submit": ["button[type='submit']", "input[type='submit']", "button.submit"]
        }
        
        if url_type == "register":
            selectors["full_name"] = ["input[name='fullname']", "input[name='name']", "input[placeholder*='name']"]

        found_fields = {}
        
        for field, tries in selectors.items():
            if field == "full_name" and url_type != "register":
                continue
                
            for selector in tries:
                try:
                    element = await page.wait_for_selector(selector, timeout=2000)
                    if element:
                        found_fields[field] = selector
                        logger.debug(f"[{url_type}] {field} alanı bulundu: {selector}")
                        break
                except:
                    continue
        
        # En azından username/email, password ve submit bulunmalı
        required = ["password", "submit"]
        if url_type == "login":
            required.append("username") # Veya email
        else:
            required.append("email")
            
        if all(k in found_fields for k in required):
            return found_fields
            
        return None

    async def execute(self, target_url: str, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ana yürütme fonksiyonu.
        1. Login/Register sayfalarını bul.
        2. Register dene.
        3. Login yap.
        4. Token/Cookie al.
        """
        result = {
            "success": False,
            "agent": self.name,
            "method": "auto_registration",
            "credentials": {},
            "cookies": [],
            "token": None,
            "message": "Giriş/Kayıt işlemi başarısız veya form bulunamadı."
        }

        logger.info(f"🕵️ {self.name} devrede: Hedef {target_url} üzerinde yetki kazanmaya çalışıyor...")

        try:
            async with async_playwright() as p:
                # Headless tarayıcı başlat
                self.browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
                self.context = await self.browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    viewport={"width": 1920, "height": 1080}
                )
                self.page = await self.context.new_page()
                
                # 1. Adım: Login/Register sayfalarını keşfet veya doğrudan dene
                urls_to_try = [
                    f"{target_url}/login",
                    f"{target_url}/signin",
                    f"{target_url}/auth/login",
                    f"{target_url}/register",
                    f"{target_url}/signup",
                    f"{target_url}/auth/register",
                    target_url # Ana sayfa da olabilir
                ]
                
                creds = await self._generate_credentials()
                logger.debug(f"Üretilen Kimlikler: {creds['username']} / {creds['password']}")
                
                registered = False
                
                # Önce Kayıt Denemesi
                for url in urls_to_try:
                    if "register" in url or "signup" in url:
                        logger.debug(f"Kayıt sayfası deneniyor: {url}")
                        try:
                            await self.page.goto(url, timeout=10000, wait_until="domcontentloaded")
                            fields = await self._find_form_fields(self.page, "register")
                            
                            if fields:
                                # Formu doldur
                                if "full_name" in fields:
                                    await self.page.fill(fields["full_name"], creds["full_name"])
                                await self.page.fill(fields["email"], creds["email"])
                                await self.page.fill(fields["username"], creds["username"])
                                await self.page.fill(fields["password"], creds["password"])
                                
                                # Submit
                                await self.page.click(fields["submit"])
                                
                                # Başarı mesajı bekle (basitçe sayfa değişimi veya URL değişimi)
                                await asyncio.sleep(2) 
                                
                                # Kayıt başarılı mı? (URL değişimi veya başarı toast'ı aranabilir)
                                # Şimdilik basitçe login sayfasına yönlendirildi mi diye bakalım veya hata var mı?
                                if "login" in self.page.url or "success" in self.page.content().lower():
                                    logger.info(f"✅ Kayıt başarılı olabilir: {url}")
                                    registered = True
                                    break
                        except Exception as e:
                            logger.debug(f"Kayıt denemesi başarısız ({url}): {str(e)}")
                            continue

                # Eğer kayıt olmadıysa veya zaten kayıt sayfası yoksa, direkt login dene
                # Not: Gerçek senaryoda önce register sonra o bilgilerle login gerekir.
                # Burada akışı basitleştirip önce register sayfalarını, sonra login sayfalarını deniyoruz.
                
                login_urls = [u for u in urls_to_try if "login" in u or "signin" in u]
                if not registered:
                     # Kayıt başarısız olduysa belki zaten üye vardır? (Deneme yanılma - riskli olabilir, atlıyoruz)
                     # Veya register formu ana sayfadaydı.
                     pass

                # 2. Adım: Giriş Yap (Eğer register başarılı olduysa veya manuel account varsa)
                # Biz burada otomatik register olduğu varsayımıyla aynı creds ile login deneyeceğiz.
                # Eğer register başarısız olduysa bu adım da başarısız olur, ki bu normaldir.
                
                if registered or True: # Her durumda login sayfalarını dene (belki önceden üye vardır)
                    for url in login_urls:
                        logger.debug(f"Giriş sayfası deneniyor: {url}")
                        try:
                            await self.page.goto(url, timeout=10000, wait_until="domcontentloaded")
                            fields = await self._find_form_fields(self.page, "login")
                            
                            if fields:
                                # Username veya Email alanını doldur
                                user_field = "username" if "username" in fields else "email"
                                await self.page.fill(fields[user_field], creds[user_field])
                                await self.page.fill(fields["password"], creds["password"])
                                
                                await self.page.click(fields["submit"])
                                await asyncio.sleep(3) # Yönlendirme bekle
                                
                                # Giriş başarılı mı? (URL değişimi, Logout butonu varlığı vb.)
                                content = await self.page.content()
                                if "logout" in content.lower() or "dashboard" in self.page.url or "profile" in self.page.url:
                                    logger.info(f"✅ GİRİŞ BAŞARILI: {url}")
                                    
                                    # Cookie ve Tokenları topla
                                    cookies = await self.context.cookies()
                                    auth_cookies = [c for c in cookies if any(x in c['name'].lower() for x in ['session', 'auth', 'token', 'jwt'])]
                                    
                                    # LocalStorage'dan token çekmeyi dene
                                    storage = await self.page.evaluate("() => localStorage")
                                    token = None
                                    for k, v in storage.items():
                                        if "token" in k.lower() or "jwt" in k.lower() or "auth" in k.lower():
                                            token = v
                                            break
                                            
                                    result["success"] = True
                                    result["credentials"] = {"username": creds["username"], "password": creds["password"]}
                                    result["cookies"] = auth_cookies
                                    result["token"] = token
                                    result["message"] = "Otomatik kayıt ve giriş başarılı. Yetkili erişim sağlandı."
                                    
                                    # Context'i diğer agentlar için hazırla
                                    # Bu bilgi scan orchestrator'a dönecek
                                    return result
                                    
                        except Exception as e:
                            logger.debug(f"Giriş denemesi başarısız ({url}): {str(e)}")
                            continue

                # Eğer hiçbir şey çalışmazsa
                logger.warning("⚠️ Otomatik giriş/kayıt işlemi başarısız oldu. Anonymous devam edilecek.")
                return result

        except Exception as e:
            logger.error(f"InfiltratorAgent hatası: {str(e)}")
            result["error"] = str(e)
            return result
        finally:
            if self.browser:
                await self.browser.close()

    def get_summary(self) -> str:
        return f"{self.name}: Otomatik kimlik oluşturma ve oturum açma işlemlerini yürütür."
