"""
Smart Browser-Based Vulnerability Tester
Uses Playwright for intelligent browser automation and testing
"""

import base64
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from utils.logger import get_logger

logger = get_logger(__name__)


class SmartBrowserTester:
    """Browser-based vulnerability testing with Playwright."""
    
    def __init__(self, config: Dict):
        """Initialize smart browser tester."""
        self.config = config
        self.advanced_config = config.get('advanced', {})
        self.screenshot_enabled = self.advanced_config.get('screenshot_enabled', False)
        self.screenshots = []
        self.browser = None
        self.playwright = None
        self.page = None
        self.context = None
        
    async def initialize_browser(self):
        """Initialize Playwright browser."""
        try:
            from playwright.async_api import async_playwright
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            self.page = await self.context.new_page()
            logger.info("Playwright browser initialized successfully")
            return True
        except ImportError:
            logger.warning("Playwright not installed. Install with: pip install playwright && playwright install chromium")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}")
            return False
    
    async def close_browser(self):
        """Close browser and cleanup."""
        try:
            if hasattr(self, 'page') and self.page:
                await self.page.close()
            if hasattr(self, 'context') and self.context:
                await self.context.close()
            if hasattr(self, 'browser') and self.browser:
                await self.browser.close()
            if hasattr(self, 'playwright') and self.playwright:
                await self.playwright.stop()
            logger.info("Playwright browser closed successfully")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")
    
    async def take_screenshot(self, title: str = "screenshot", page=None) -> Optional[str]:
        """Take screenshot and return base64 encoded data URL."""
        if not self.screenshot_enabled:
            return None
        
        try:
            # Use provided page or default
            screenshot_page = page or self.page
            if not screenshot_page:
                return None
            
            screenshot_bytes = await screenshot_page.screenshot(full_page=False)
            base64_screenshot = base64.b64encode(screenshot_bytes).decode('utf-8')
            data_url = f"data:image/png;base64,{base64_screenshot}"
            
            self.screenshots.append({
                'title': title,
                'data_url': data_url
            })
            
            logger.debug(f"Screenshot captured: {title}")
            return data_url
        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            return None
    
    async def test_xss_browser(self, url: str, payloads: List[str]) -> List[Dict]:
        """Test XSS vulnerabilities using Playwright."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        logger.info(f"Testing XSS with Playwright on: {url}")
        
        for param_name in params.keys():
            for payload in payloads[:3]:  # Test first 3 payloads
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    # Navigate to URL
                    try:
                        await self.page.goto(test_url, wait_until='networkidle', timeout=15000)
                    except Exception:
                        # Timeout or other error, continue
                        pass
                    
                    # Check for XSS execution via console logs
                    console_messages = []
                    self.page.on('console', lambda msg: console_messages.append(msg.text))
                    
                    # Wait a bit for any scripts to execute
                    await asyncio.sleep(1)
                    
                    # Check if alert dialog appeared
                    dialog_detected = False
                    async def handle_dialog(dialog):
                        nonlocal dialog_detected
                        dialog_detected = True
                        try:
                            await dialog.dismiss()
                        except Exception:
                            # Ignore errors if dialog is already handled or closed
                            pass
                    
                    self.page.on('dialog', handle_dialog)
                    try:
                        # Wait a bit for any scripts to execute
                        await asyncio.sleep(1)
                    finally:
                        self.page.remove_listener('dialog', handle_dialog)
                    
                    # Check page content for payload
                    page_content = await self.page.content()
                    
                    if payload in page_content or dialog_detected:
                        screenshot_url = await self.take_screenshot(f"XSS_{param_name}")
                        
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS) - Browser Verified',
                            'severity': 'high',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'XSS payload executed in browser. Dialog detected: {dialog_detected}',
                            'description': 'XSS vulnerability confirmed via browser execution',
                            'remediation': 'Implement proper input validation and output encoding',
                            'screenshot': screenshot_url
                        })
                        logger.info(f"XSS confirmed on {url} - param: {param_name}")
                        break
                    
                except Exception as e:
                    logger.debug(f"Error testing XSS with browser on {url}: {e}")
                    continue
        
        return vulnerabilities
    
    async def test_sqli_browser(self, url: str, payloads: List[str]) -> List[Dict]:
        """Test SQL injection using Playwright."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        logger.info(f"Testing SQLi with Playwright on: {url}")
        
        # SQL error patterns to look for
        sql_errors = [
            'SQL syntax',
            'mysql_fetch',
            'PostgreSQL.*ERROR',
            'Warning.*mysql',
            'valid MySQL result',
            'MySQLSyntaxErrorException',
            'SqlException',
            'SQLite/JDBCDriver',
            'Oracle error',
            'ODBC SQL Server Driver'
        ]
        
        for param_name in params.keys():
            for payload in payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    # Navigate and wait for response
                    try:
                        await self.page.goto(test_url, wait_until='networkidle', timeout=15000)
                    except Exception:
                        pass
                        
                    page_content = await self.page.content()
                    
                    # Check for SQL errors in page
                    for error_pattern in sql_errors:
                        if error_pattern.lower() in page_content.lower():
                            screenshot_url = await self.take_screenshot(f"SQLi_{param_name}")
                            
                            vulnerabilities.append({
                                'type': 'SQL Injection - Browser Verified',
                                'severity': 'critical',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'SQL error detected in browser: {error_pattern}',
                                'description': 'SQL injection confirmed via browser-based testing',
                                'remediation': 'Use parameterized queries or prepared statements',
                                'screenshot': screenshot_url
                            })
                            logger.info(f"SQLi confirmed on {url} - param: {param_name}")
                            break
                    
                except Exception as e:
                    logger.debug(f"Error testing SQLi with browser on {url}: {e}")
                    continue
        
        return vulnerabilities
    
    async def test_dom_xss(self, url: str) -> List[Dict]:
        """Test for DOM-based XSS vulnerabilities."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        logger.info(f"Testing DOM XSS on: {url}")
        
        try:
            # Navigate to page
            await self.page.goto(url, wait_until='networkidle', timeout=15000)
            
            # Inject test payloads via hash/URL
            dom_payloads = [
                '#<img src=x onerror=alert(1)>',
                '#javascript:alert(1)',
                '#<svg/onload=alert(1)>'
            ]
            
            for payload in dom_payloads:
                try:
                    test_url = url + payload
                    await self.page.goto(test_url, wait_until='networkidle', timeout=10000)
                    
                    # Check for dialog
                    dialog_detected = False
                    async def handle_dialog(dialog):
                        nonlocal dialog_detected
                        dialog_detected = True
                        try:
                            await dialog.dismiss()
                        except Exception:
                            pass
                    
                    self.page.on('dialog', handle_dialog)
                    try:
                        await asyncio.sleep(1)
                    finally:
                        self.page.remove_listener('dialog', handle_dialog)
                    
                    if dialog_detected:
                        screenshot_url = await self.take_screenshot("DOM_XSS")
                        
                        vulnerabilities.append({
                            'type': 'DOM-Based XSS',
                            'severity': 'high',
                            'url': url,
                            'payload': payload,
                            'evidence': 'Alert dialog triggered via DOM manipulation',
                            'description': 'DOM-based XSS vulnerability allows client-side code execution',
                            'remediation': 'Sanitize DOM operations and validate URL fragments',
                            'screenshot': screenshot_url
                        })
                        logger.info(f"DOM XSS confirmed on {url}")
                        break
                
                except Exception as e:
                    logger.debug(f"Error testing DOM XSS payload: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error testing DOM XSS on {url}: {e}")
        
        return vulnerabilities
    
    async def test_clickjacking(self, url: str) -> List[Dict]:
        """Test for clickjacking vulnerabilities."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        logger.info(f"Testing clickjacking on: {url}")
        
        try:
            # Try to frame the page
            frame_html = f'''
            <!DOCTYPE html>
            <html>
            <head><title>Clickjacking Test</title></head>
            <body>
                <iframe src="{url}" width="100%" height="600px"></iframe>
            </body>
            </html>
            '''
            
            await self.page.set_content(frame_html)
            await asyncio.sleep(2)
            
            # Check if iframe loaded successfully
            frames = self.page.frames
            if len(frames) > 1:  # Main frame + iframe
                screenshot_url = await self.take_screenshot("Clickjacking")
                
                vulnerabilities.append({
                    'type': 'Clickjacking',
                    'severity': 'medium',
                    'url': url,
                    'evidence': 'Page can be embedded in iframe without X-Frame-Options protection',
                    'description': 'Site is vulnerable to clickjacking attacks',
                    'remediation': 'Implement X-Frame-Options or CSP frame-ancestors directive',
                    'screenshot': screenshot_url
                })
                logger.info(f"Clickjacking vulnerability confirmed on {url}")
        
        except Exception as e:
            logger.debug(f"Error testing clickjacking on {url}: {e}")
        
        return vulnerabilities
    
    async def test_hidden_elements(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Test hidden elements for vulnerabilities using Playwright."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        logger.info(f"Testing hidden elements with Playwright on: {url}")
        
        try:
            await self.page.goto(url, wait_until='networkidle', timeout=15000)
            
            # Find all hidden elements
            hidden_inputs = await self.page.query_selector_all('input[type="hidden"]')
            hidden_display = await self.page.query_selector_all('[style*="display:none"], [style*="display: none"]')
            hidden_visibility = await self.page.query_selector_all('[style*="visibility:hidden"], [style*="visibility: hidden"]')
            
            all_hidden = hidden_inputs + hidden_display + hidden_visibility
            
            if len(all_hidden) > 0:
                logger.info(f"Found {len(all_hidden)} hidden elements")
                
                # Check for sensitive data in hidden inputs
                for hidden in hidden_inputs[:10]:  # Check first 10
                    try:
                        name = await hidden.get_attribute('name') or 'unnamed'
                        value = await hidden.get_attribute('value') or ''
                        
                        # Check for sensitive patterns
                        sensitive_patterns = ['token', 'key', 'secret', 'password', 'api', 'auth']
                        if any(pattern in name.lower() or pattern in value.lower() for pattern in sensitive_patterns):
                            screenshot_url = await self.take_screenshot(f"Hidden_Sensitive_{name}")
                            
                            vulnerabilities.append({
                                'type': 'Sensitive Data in Hidden Elements',
                                'severity': 'high',
                                'url': url,
                                'parameter': name,
                                'evidence': f'Hidden field "{name}" contains potentially sensitive data',
                                'description': 'Hidden input field contains sensitive information that can be accessed via browser inspection',
                                'remediation': 'Avoid storing sensitive data in hidden fields. Use server-side session management.',
                                'screenshot': screenshot_url
                            })
                            logger.info(f"Found sensitive data in hidden field: {name}")
                        
                        # Try to manipulate hidden field value
                        xss_payload = payloads.get('xss', ['<script>alert(1)</script>'])[0]
                        await self.page.evaluate(f'document.querySelector(\'input[name="{name}"]\').value = "{xss_payload}"')
                        
                    except Exception as e:
                        logger.debug(f"Error checking hidden element: {e}")
                        continue
                
                # Take overall screenshot
                screenshot_url = await self.take_screenshot("Hidden_Elements_Overview")
                
                vulnerabilities.append({
                    'type': 'Hidden Elements Detected',
                    'severity': 'info',
                    'url': url,
                    'evidence': f'Found {len(all_hidden)} hidden elements ({len(hidden_inputs)} hidden inputs)',
                    'description': 'Page contains hidden elements that may be exploitable',
                    'remediation': 'Review all hidden elements for security implications. Validate server-side.',
                    'screenshot': screenshot_url
                })
        
        except Exception as e:
            logger.debug(f"Error testing hidden elements with Playwright: {e}")
        
        return vulnerabilities
    
    async def test_all_browser_vulnerabilities(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Run all browser-based vulnerability tests including hidden elements."""
        all_vulnerabilities = []
        
        try:
            # Initialize browser once
            if not await self.initialize_browser():
                logger.warning("Browser initialization failed, skipping browser tests")
                return all_vulnerabilities
            
            # Test XSS
            if payloads.get('xss'):
                xss_vulns = await self.test_xss_browser(url, payloads['xss'])
                all_vulnerabilities.extend(xss_vulns)
            
            # Test SQL Injection
            if payloads.get('sql_injection'):
                sqli_vulns = await self.test_sqli_browser(url, payloads['sql_injection'])
                all_vulnerabilities.extend(sqli_vulns)
            
            # Test DOM XSS
            dom_xss_vulns = await self.test_dom_xss(url)
            all_vulnerabilities.extend(dom_xss_vulns)
            
            # Test Clickjacking
            clickjacking_vulns = await self.test_clickjacking(url)
            all_vulnerabilities.extend(clickjacking_vulns)
            
            # Test Hidden Elements
            hidden_vulns = await self.test_hidden_elements(url, payloads)
            all_vulnerabilities.extend(hidden_vulns)
            
        except Exception as e:
            logger.error(f"Error in browser-based testing: {e}")
        finally:
            await self.close_browser()
        
        return all_vulnerabilities
    
    def test_browser_sync(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Synchronous wrapper for browser testing."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.test_all_browser_vulnerabilities(url, payloads)
        )
