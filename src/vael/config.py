from pydantic import BaseModel, Field
from typing import List, Literal

class ScopeConfig(BaseModel):
    targets: List[str] = Field(default_factory=list, description="Authorized target URLs or IPs")
    allow_subdomains: bool = False

class ScanConfig(BaseModel):
    profile: Literal["passive", "safe", "advanced"] = "passive"
    max_requests: int = 1000
    timeout_seconds: int = 30

class AIConfig(BaseModel):
    enabled: bool = False
    provider: str = "local"
    model: str = ""

class ReportConfig(BaseModel):
    format: Literal["json", "markdown", "html"] = "markdown"
    output_dir: str = "./reports"

class VaelConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
