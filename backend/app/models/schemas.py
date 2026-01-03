"""Shared Pydantic schemas for API responses."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============ Common Schemas ============

class TimeRangeQuery(BaseModel):
    """Query parameters for time range."""
    time_range: str = Field(default="24h", pattern="^(1h|24h|7d|30d)$")


class StatsResponse(BaseModel):
    """Basic statistics response."""
    total_events: int
    unique_ips: int
    time_range: str


class TimelinePoint(BaseModel):
    """Single point in a timeline."""
    timestamp: str
    count: int


class TimelineResponse(BaseModel):
    """Timeline response with multiple data points."""
    data: List[TimelinePoint]
    time_range: str


class GeoPoint(BaseModel):
    """Geographic point."""
    country: str
    count: int


class GeoDistributionResponse(BaseModel):
    """Geographic distribution response."""
    data: List[GeoPoint]
    time_range: str


class TopAttacker(BaseModel):
    """Top attacker with geo information."""
    ip: str
    count: int
    country: Optional[str] = None
    city: Optional[str] = None
    # Duration metrics for human vs script detection
    total_duration_seconds: Optional[float] = None
    avg_session_duration: Optional[float] = None
    session_count: Optional[int] = None
    behavior_classification: Optional[str] = None  # "Script", "Human", "Bot"


class TopAttackersResponse(BaseModel):
    """Top attackers response."""
    data: List[TopAttacker]
    time_range: str


# ============ Dashboard Schemas ============

class HoneypotStats(BaseModel):
    """Statistics for a single honeypot."""
    name: str
    total_events: int
    unique_ips: int
    color: str


class DashboardOverview(BaseModel):
    """Dashboard overview response."""
    honeypots: List[HoneypotStats]
    total_events: int
    total_unique_ips: int
    time_range: str


# ============ Attack Map Schemas ============

class AttackEvent(BaseModel):
    """Attack event for real-time map."""
    id: str
    timestamp: str
    honeypot: str
    src_ip: str
    src_lat: Optional[float] = None
    src_lon: Optional[float] = None
    src_country: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_lat: Optional[float] = None
    dst_lon: Optional[float] = None
    protocol: Optional[str] = None
    port: Optional[int] = None


class AttackMapStats(BaseModel):
    """Attack map statistics."""
    total_attacks: int
    unique_ips: int
    countries: int


# ============ Cowrie Schemas ============

class CowrieSession(BaseModel):
    """Cowrie session data."""
    session_id: str
    src_ip: str
    start_time: str
    end_time: Optional[str] = None
    duration: Optional[float] = None
    commands_count: int
    country: Optional[str] = None
    sensor: Optional[str] = None


class CowrieCredential(BaseModel):
    """Cowrie credential attempt."""
    username: str
    password: str
    count: int
    success: bool = False


class CowrieCommand(BaseModel):
    """Cowrie command executed."""
    command: str
    count: int


class CowrieHassh(BaseModel):
    """SSH fingerprint (HASSH)."""
    hassh: str
    count: int
    client_version: Optional[str] = None


class CowrieVariantStats(BaseModel):
    """Cowrie variant comparison."""
    variant: str
    total_events: int
    unique_ips: int
    avg_session_duration: Optional[float] = None
    unique_commands: int
    sessions_count: Optional[int] = None


# ============ Dionaea Schemas ============

class DionaeaProtocolStats(BaseModel):
    """Dionaea protocol statistics."""
    protocol: str
    count: int


class DionaeaPortStats(BaseModel):
    """Dionaea port statistics."""
    port: int
    count: int
    protocol: Optional[str] = None


class DionaeaMalware(BaseModel):
    """Dionaea malware sample."""
    md5: str
    count: int
    first_seen: Optional[str] = None
    sha256: Optional[str] = None
    file_name: Optional[str] = None


# ============ Galah Schemas ============

class GalahRequest(BaseModel):
    """Galah HTTP request."""
    method: str
    uri: str
    count: int


class GalahUserAgent(BaseModel):
    """Galah user agent."""
    user_agent: str
    count: int


class GalahPath(BaseModel):
    """Galah path statistics."""
    path: str
    count: int
    methods: List[str]


# ============ RDPY Schemas ============

class RDPYSession(BaseModel):
    """RDPY session data."""
    session_id: str
    src_ip: str
    username: Optional[str] = None
    domain: Optional[str] = None
    timestamp: str
    country: Optional[str] = None
    message: Optional[str] = None


class RDPYCredential(BaseModel):
    """RDPY credential attempt."""
    username: str
    password: Optional[str] = None
    domain: Optional[str] = None
    count: int


# ============ Heralding Schemas ============

class HeraldingCredential(BaseModel):
    """Heralding credential attempt."""
    protocol: str
    username: str
    password: str
    count: int


class HeraldingProtocolStats(BaseModel):
    """Heralding protocol statistics."""
    protocol: str
    count: int
    unique_ips: int


# ============ Firewall Schemas ============

class FirewallBlockedTraffic(BaseModel):
    """Firewall blocked traffic stats."""
    src_ip: str
    count: int
    ports: List[int]
    protocols: List[str]
    country: Optional[str] = None


class PortScanDetection(BaseModel):
    """Port scan detection result."""
    src_ip: str
    unique_ports: int
    time_window: str
    first_seen: str
    last_seen: str
    country: Optional[str] = None


class RepeatOffender(BaseModel):
    """Repeat offender data."""
    src_ip: str
    total_blocks: int
    first_seen: str
    last_seen: str
    targeted_ports: List[int]
    country: Optional[str] = None


# ============ Attacker Profile Schemas ============

class HoneypotActivity(BaseModel):
    """Activity on a specific honeypot."""
    honeypot: str
    event_count: int
    first_seen: str
    last_seen: str
    duration_seconds: Optional[float] = None
    session_count: Optional[int] = None


class AttackerProfile(BaseModel):
    """Complete attacker profile."""
    ip: str
    total_events: int
    first_seen: str
    last_seen: str
    countries: List[str]
    honeypot_activity: List[HoneypotActivity]
    credentials_tried: Optional[List[CowrieCredential]] = None
    commands_executed: Optional[List[str]] = None
    # Duration metrics for human vs script detection
    total_duration_seconds: Optional[float] = None
    avg_session_duration: Optional[float] = None
    session_count: Optional[int] = None
    behavior_classification: Optional[str] = None  # "Script", "Human", "Bot"

