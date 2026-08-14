"""
Infiltrator Agent - Automatic Authentication Module
Handles auto-registration, login, and session management for authenticated scanning
"""

from typing import Dict, List, Optional
from rich.console import Console
from ..core.browser import BrowserAutomation, AuthResult
from ..agents.base import BaseAgent
import asyncio

console = Console()


class InfiltratorAgent(BaseAgent):
    """
    Agent responsible for automatic authentication
    - Detects login/register forms
    - Attempts auto-registration if needed
    - Performs automatic login
    - Exports session for authenticated scanning
    """
    
    def __init__(self, workspace=None, llm_client=None):
        super().__init__('infiltrator', workspace, llm_client)
        self.browser: Optional[BrowserAutomation] = None
        self.auth_result: Optional[AuthResult] = None
        self.session_file: Optional[str] = None
        
    async def initialize(self):
        """Initialize browser automation"""
        self.browser = BrowserAutomation(headless=True, timeout=30000)
        await self.browser.start()
        
    async def shutdown(self):
        """Cleanup browser resources"""
        if self.browser:
            await self.browser.stop()
            
    async def detect_authentication_opportunities(
        self, 
        target_url: str
    ) -> Dict:
        """
        Detect login/register forms and admin panels
        Returns detection results
        """
        if not self.browser:
            await self.initialize()
            
        console.print(f"[cyan]🔍 Detecting authentication forms on {target_url}...[/cyan]")
        
        try:
            detected = await self.browser.detect_auth_forms(target_url)
            
            if detected['has_login']:
                console.print("[green]✓ Login form detected[/green]")
            if detected['has_register']:
                console.print("[green]✓ Registration option detected[/green]")
            if detected['is_admin_panel']:
                console.print("[yellow]⚠ Admin panel indicators found[/yellow]")
                
            return detected
            
        except Exception as e:
            console.print(f"[red]✗ Detection failed: {e}[/red]")
            return {
                'has_login': False,
                'has_register': False,
                'is_admin_panel': False,
                'error': str(e)
            }
    
    async def attempt_auto_login(
        self,
        target_url: str,
        credentials: Optional[Dict[str, str]] = None,
        detected_forms: Optional[Dict] = None
    ) -> AuthResult:
        """
        Attempt automatic login with provided or default credentials
        """
        if not self.browser:
            await self.initialize()
            
        # Default test credentials if none provided
        if not credentials:
            credentials = {
                'username': 'admin',
                'password': 'admin'
            }
            
        console.print(f"[cyan]🔐 Attempting login to {target_url}...[/cyan]")
        
        result = await self.browser.attempt_login(
            url=target_url,
            credentials=credentials,
            detected_forms=detected_forms
        )
        
        if result.success:
            console.print("[green]✓ Login successful![/green]")
            self.auth_result = result
            
            # Export session
            if self.workspace:
                self.session_file = f"{self.workspace.path}/session.json"
                await self.browser.export_session(self.session_file)
                console.print(f"[green]💾 Session saved to {self.session_file}[/green]")
        else:
            console.print(f"[red]✗ Login failed: {result.error_message}[/red]")
            
        return result
    
    async def attempt_auto_registration(
        self,
        target_url: str,
        credentials: Optional[Dict[str, str]] = None,
        detected_forms: Optional[Dict] = None
    ) -> AuthResult:
        """
        Attempt automatic registration followed by login
        """
        if not self.browser:
            await self.initialize()
            
        console.print(f"[cyan]📝 Attempting registration on {target_url}...[/cyan]")
        
        result = await self.browser.attempt_registration(
            url=target_url,
            credentials=credentials,
            detected_forms=detected_forms
        )
        
        if result.success:
            console.print(f"[green]✓ Registration and login successful! (method: {result.method})[/green]")
            self.auth_result = result
            
            # Export session
            if self.workspace:
                self.session_file = f"{self.workspace.path}/session.json"
                await self.browser.export_session(self.session_file)
                console.print(f"[green]💾 Session saved to {self.session_file}[/green]")
        else:
            console.print(f"[red]✗ Registration failed: {result.error_message}[/red]")
            
        return result
    
    async def get_authenticated_cookies(self) -> List[Dict]:
        """Get cookies from authenticated session"""
        if self.auth_result and self.auth_result.success:
            return self.auth_result.cookies
        return []
    
    async def get_session_token(self) -> Optional[str]:
        """Get session token from authenticated session"""
        if self.auth_result and self.auth_result.success:
            return self.auth_result.session_token
        return None
    
    def get_scan_headers(self) -> Dict[str, str]:
        """Get headers for authenticated scanning"""
        headers = {}
        token = self.get_session_token()
        if token:
            # Check if it looks like a JWT
            if token.count('.') == 2:
                headers['Authorization'] = f'Bearer {token}'
        return headers
    
    async def execute(self, context: Dict) -> Dict:
        """
        Main execution method for the agent
        Context should contain:
        - target_url: URL to test
        - credentials: Optional login credentials
        - auto_register: Whether to attempt auto-registration
        """
        target_url = context.get('target_url')
        credentials = context.get('credentials')
        auto_register = context.get('auto_register', True)
        
        if not target_url:
            return {
                'success': False,
                'error': 'No target URL provided',
                'agent': self.name
            }
        
        result = {
            'agent': self.name,
            'target': target_url,
            'authentication_attempted': False,
            'authentication_success': False,
            'method': None,
            'session_available': False,
            'findings': []
        }
        
        try:
            # Step 1: Detect authentication opportunities
            detected = await self.detect_authentication_opportunities(target_url)
            result['detection'] = detected
            
            if not detected.get('has_login') and not detected.get('has_register'):
                console.print("[yellow]⚠ No authentication forms detected, skipping infiltration[/yellow]")
                result['findings'].append({
                    'type': 'info',
                    'title': 'No Authentication Forms Detected',
                    'description': 'Target does not appear to have login/registration forms',
                    'severity': 'info'
                })
                return result
            
            # Step 2: Attempt login first if credentials provided
            if credentials:
                login_result = await self.attempt_auto_login(
                    target_url, 
                    credentials,
                    detected
                )
                result['authentication_attempted'] = True
                
                if login_result.success:
                    result['authentication_success'] = True
                    result['method'] = 'login'
                    result['session_available'] = True
                    result['findings'].append({
                        'type': 'success',
                        'title': 'Successful Authentication',
                        'description': f'Successfully logged in using provided credentials',
                        'severity': 'info',
                        'details': {
                            'method': 'login',
                            'session_token': login_result.session_token is not None,
                            'cookies_count': len(login_result.cookies)
                        }
                    })
                    return result
            
            # Step 3: If login failed and auto-register enabled, try registration
            if auto_register and detected.get('has_register'):
                register_result = await self.attempt_auto_registration(
                    target_url,
                    credentials,
                    detected
                )
                result['authentication_attempted'] = True
                
                if register_result.success:
                    result['authentication_success'] = True
                    result['method'] = 'register'
                    result['session_available'] = True
                    result['findings'].append({
                        'type': 'success',
                        'title': 'Successful Auto-Registration',
                        'description': 'Successfully registered and logged in automatically',
                        'severity': 'info',
                        'details': {
                            'method': 'register',
                            'session_token': register_result.session_token is not None,
                            'cookies_count': len(register_result.cookies)
                        }
                    })
                    return result
            
            # If we reach here, authentication failed
            result['findings'].append({
                'type': 'warning',
                'title': 'Authentication Failed',
                'description': 'Could not authenticate with target',
                'severity': 'low',
                'details': {
                    'has_login': detected.get('has_login', False),
                    'has_register': detected.get('has_register', False)
                }
            })
            
            return result
            
        except Exception as e:
            console.print(f"[red]✗ Infiltrator agent error: {e}[/red]")
            result['error'] = str(e)
            return result
        finally:
            await self.shutdown()
    
    def get_recommendations(self) -> List[str]:
        """Get recommendations based on authentication results"""
        recommendations = []
        
        if self.auth_result and self.auth_result.success:
            recommendations.append("Use authenticated session for deeper vulnerability scanning")
            recommendations.append("Test for privilege escalation vulnerabilities")
            recommendations.append("Check for session management issues (fixation, hijacking)")
            if self.auth_result.method == 'register':
                recommendations.append("Investigate registration process for vulnerabilities (email verification bypass, etc.)")
        else:
            recommendations.append("Consider manual authentication testing")
            recommendations.append("Try default credentials or credential stuffing")
            
        return recommendations


async def test_infiltrator_agent():
    """Test function for InfiltratorAgent"""
    print("Testing InfiltratorAgent...")
    
    agent = InfiltratorAgent()
    
    try:
        # Test detection
        detected = await agent.detect_authentication_opportunities('https://httpbin.org/forms/post')
        print(f"Detection result: {detected}")
        
        print("✅ InfiltratorAgent test completed")
    except Exception as e:
        print(f"❌ Test failed: {e}")
    finally:
        await agent.shutdown()


if __name__ == '__main__':
    asyncio.run(test_infiltrator_agent())
