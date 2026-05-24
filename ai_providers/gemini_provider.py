"""
Google Gemini AI Provider
Provides integration with Google Gemini API for payload generation
"""

from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)


class GeminiProvider:
    """Google Gemini AI provider for Deep Eye."""
    
    def __init__(self, config: dict):
        """
        Initialize Gemini provider.
        
        Args:
            config: Provider configuration dictionary
        """
        self.config = config
        self.api_key = config.get('api_key', '')
        self.model = config.get('model', 'gemini-1.5-flash')
        self.temperature = config.get('temperature', 0.7)
        self.max_tokens = config.get('max_tokens', 2000)
        self.timeout = config.get('timeout', 30)
        self.client = None
        
        if self.api_key:
            self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Gemini client."""
        try:
            import google.generativeai as genai
            
            # Configure Gemini with API key
            genai.configure(api_key=self.api_key)
            
            # Initialize model
            self.client = genai.GenerativeModel(
                model_name=self.model,
                generation_config={
                    'temperature': self.temperature,
                    'max_output_tokens': self.max_tokens,
                }
            )
            
            logger.info(f"Gemini provider initialized with model: {self.model}")
            
        except ImportError:
            logger.error("Google Generative AI library not installed. Install with: pip install google-generativeai")
            self.client = None
        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")
            self.client = None
    
    def generate(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """
        Generate response from Gemini.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate (optional)
            
        Returns:
            Generated text response
        """
        if not self.client:
            raise RuntimeError("Gemini client not initialized. Check API key and installation.")
        
        try:
            # Generate content
            response = self.client.generate_content(
                prompt,
                generation_config={
                    'temperature': self.temperature,
                    'max_output_tokens': max_tokens or self.max_tokens,
                }
            )
            
            # Extract text from response
            if hasattr(response, 'text'):
                return response.text
            elif hasattr(response, 'candidates') and response.candidates:
                return response.candidates[0].content.parts[0].text
            else:
                logger.warning("Unexpected Gemini response format")
                return ""
            
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            raise
    
    def is_available(self) -> bool:
        """Check if Gemini provider is available."""
        return self.client is not None
    
    def get_model_info(self) -> dict:
        """Get information about the current model."""
        return {
            'provider': 'gemini',
            'model': self.model,
            'temperature': self.temperature,
            'max_tokens': self.max_tokens,
            'available': self.is_available()
        }

