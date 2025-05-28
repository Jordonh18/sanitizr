"""
Tests for the super deep URL extraction functionality in Sanitizr.
"""

import unittest
from urllib.parse import quote_plus
from sanitizr.sanitizr.core.cleaner import URLCleaner


class TestDeepExtraction(unittest.TestCase):
    """Test cases for the super deep URL extraction functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cleaner = URLCleaner()
    
    def test_facebook_complex_redirect(self):
        """Test extraction from a complex Facebook redirect URL."""
        # Original URL: https://example.com/offer?sessionid=abc123
        target_url = "https://example.com/offer?sessionid=abc123"
        encoded_url = quote_plus(target_url)
        fb_url = f"https://l.facebook.com/l.php?u={encoded_url}&h=AT0KJx123&__tn__=H-R"
        
        cleaned = self.cleaner.clean_url(fb_url)
        self.assertEqual(cleaned, target_url)
    
    def test_double_encoded_facebook_redirect(self):
        """Test extraction from a doubly encoded Facebook redirect URL."""
        # Original URL with tracking: https://example.com/product?id=123&utm_source=facebook
        target_url = "https://example.com/product?id=123&utm_source=facebook"
        # Expected cleaned URL: https://example.com/product?id=123
        expected_cleaned = "https://example.com/product?id=123"
        
        # First encoding
        encoded_once = quote_plus(target_url)
        # Second encoding
        encoded_twice = quote_plus(f"https://l.facebook.com/l.php?u={encoded_once}&h=AT123")
        # Final URL
        fb_url = f"https://m.facebook.com/l.php?u={encoded_twice}&h=AT789&__tn__=C-R"
        
        cleaned = self.cleaner.clean_url(fb_url)
        self.assertEqual(cleaned, expected_cleaned)
    
    def test_instagram_redirect(self):
        """Test extraction from an Instagram redirect URL."""
        target_url = "https://example.com/product?id=456"
        encoded_url = quote_plus(target_url)
        ig_url = f"https://l.instagram.com/?u={encoded_url}&e=ATM98q"
        
        cleaned = self.cleaner.clean_url(ig_url)
        self.assertEqual(cleaned, target_url)
    
    def test_linkedin_redirect(self):
        """Test extraction from a LinkedIn redirect URL."""
        target_url = "https://example.com/job?position=developer"
        encoded_url = quote_plus(target_url)
        linkedin_url = f"https://www.linkedin.com/redir/redirect?url={encoded_url}&urlhash=BcD3&trk=article-card_share-article"
        
        cleaned = self.cleaner.clean_url(linkedin_url)
        self.assertEqual(cleaned, target_url)
    
    def test_multi_platform_redirect_chain(self):
        """Test extraction from a chain of redirects across multiple platforms."""
        # Original target
        target_url = "https://example.com/special?id=789"
        
        # LinkedIn redirect
        linkedin_encoded = quote_plus(target_url)
        linkedin_url = f"https://www.linkedin.com/redir/redirect?url={linkedin_encoded}&urlhash=XyZ"
        
        # Facebook redirect of LinkedIn URL
        fb_encoded = quote_plus(linkedin_url)
        fb_url = f"https://l.facebook.com/l.php?u={fb_encoded}&h=AT123"
        
        # Final URL coming from Google
        google_encoded = quote_plus(fb_url)
        final_url = f"https://www.google.com/url?q={google_encoded}&sa=D&source=editors"
        
        cleaned = self.cleaner.clean_url(final_url)
        self.assertEqual(cleaned, target_url)
    
    def test_url_fragment_redirect(self):
        """Test extraction from a URL with redirect in fragment."""
        target_url = "https://example.com/page?id=999"
        encoded_url = quote_plus(target_url)
        fragment_url = f"https://website.com/redirect#url={encoded_url}"
        
        cleaned = self.cleaner.clean_url(fragment_url)
        self.assertEqual(cleaned, target_url)
    
    def test_deeply_nested_params(self):
        """Test extraction from deeply nested URL parameters."""
        inner_url = "https://example.com/nested?id=555"
        inner_encoded = quote_plus(inner_url)
        middle_url = f"https://middle.com/jump?target={inner_encoded}&tracking=123"
        middle_encoded = quote_plus(middle_url)
        outer_url = f"https://outer.com/goto?url={middle_encoded}&source=campaign"
        
        cleaned = self.cleaner.clean_url(outer_url)
        self.assertEqual(cleaned, inner_url)
    
    def test_malformed_redirects(self):
        """Test handling of malformed redirect URLs."""
        # Missing scheme in redirect target - our cleaner is now smart enough to add https://
        malformed = "https://facebook.com/l.php?u=example.com/page"
        self.assertEqual(self.cleaner.clean_url(malformed), "https://example.com/page")
        
        # Empty redirect parameter - our cleaner now removes empty query parameters
        empty_param = "https://linkedin.com/redirect?url="
        self.assertEqual(self.cleaner.clean_url(empty_param), "https://linkedin.com/redirect")
    
    def test_max_depth_limit(self):
        """Test that max_depth parameter prevents infinite recursion."""
        # Create a URL with a custom domain that our cleaner won't recognize as a redirect
        custom_url = "https://custom-redirect.example/r?url=https%3A%2F%2Fexample.com%2Fpage"
        
        # With max_depth=0, we should get back the original URL without extraction
        cleaned = self.cleaner.clean_url(custom_url, max_depth=0)
        self.assertEqual(cleaned, custom_url)
        
        # Add domain to redirect params temporarily for testing with max_depth=1
        original_redirect_params = self.cleaner.redirect_params.copy()
        self.cleaner.redirect_params["custom-redirect.example"] = ["url"]
        
        try:
            # With max_depth=1 and the domain in redirect_params, extraction should work
            cleaned = self.cleaner.clean_url(custom_url, max_depth=1)
            self.assertEqual(cleaned, "https://example.com/page")
        finally:
            # Restore original redirect params
            self.cleaner.redirect_params = original_redirect_params
    
    def test_tracking_params_after_extraction(self):
        """Test that tracking parameters are removed after URL extraction."""
        # Target URL with tracking parameters
        target_with_tracking = "https://example.com/product?id=123&utm_source=social&fbclid=abc"
        expected_cleaned = "https://example.com/product?id=123"
        
        # Encode in a Facebook redirect
        encoded = quote_plus(target_with_tracking)
        fb_url = f"https://l.facebook.com/l.php?u={encoded}&h=AT123"
        
        cleaned = self.cleaner.clean_url(fb_url)
        self.assertEqual(cleaned, expected_cleaned)


if __name__ == "__main__":
    unittest.main()
