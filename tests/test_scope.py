import pytest
from src.vael.scope import ScopeManager, ScopeError

def test_valid_scope():
    manager = ScopeManager(["https://example.com"])
    # Should pass (public domain, in scope)
    assert manager.is_authorized("https://example.com/login") is True

def test_unauthorized_domain():
    manager = ScopeManager(["https://example.com"])
    # Should fail (not in scope)
    with pytest.raises(ScopeError):
        manager.is_authorized("https://google.com")

def test_ssrf_localhost():
    manager = ScopeManager(["https://example.com"])
    # Should fail (localhost blocked)
    assert manager.is_authorized("http://localhost:8080") is False
    assert manager.is_authorized("http://127.0.0.1") is False

def test_ssrf_internal_ip():
    manager = ScopeManager(["https://example.com"])
    # Should fail (private IP blocked)
    with pytest.raises(ScopeError):
        manager.is_authorized("http://192.168.1.1") # Typical home router

def test_blocked_redirect():
    manager = ScopeManager(["https://example.com"])
    # Redirecting to a different domain should be blocked
    with pytest.raises(ScopeError):
        manager.validate_redirect("https://example.com/login", "https://evil.com/steal")
