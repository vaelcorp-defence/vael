import pytest
from src.vael.scope import ScopeManager
from src.vael.http_engine import HTTPEngine
from src.vael.crawler import Crawler

@pytest.mark.asyncio
async def test_crawler_finds_links():
    # We use a real, safe website that is built for testing
    target = "https://example.com"
    
    scope = ScopeManager([target])
    engine = HTTPEngine(scope)
    crawler = Crawler(engine)
    
    await crawler.crawl(target, max_pages=2)
    await engine.close()
    
    # Example.com has 1 link (to iana.org), but we should at least find the homepage
    assert len(crawler.found_urls) >= 1
    assert target in crawler.found_urls
