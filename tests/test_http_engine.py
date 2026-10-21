import pytest
import asyncio
from src.vael.scope import ScopeManager
from src.vael.http_engine import HTTPEngine

@pytest.mark.asyncio
async def test_http_engine_blocks_out_of_scope():
    # Set scope strictly to example.com
    scope = ScopeManager(["https://example.com"])
    engine = HTTPEngine(scope)
    
    # Try to request a domain not in scope
    response = await engine.request("GET", "https://google.com")
    assert response is None
    
    await engine.close()

@pytest.mark.asyncio
async def test_http_engine_allows_in_scope():
    scope = ScopeManager(["https://example.com"])
    engine = HTTPEngine(scope)
    
    # Request example.com (this will make a real network request)
    response = await engine.request("GET", "https://example.com")
    assert response is not None
    assert response.status_code == 200
    
    await engine.close()
