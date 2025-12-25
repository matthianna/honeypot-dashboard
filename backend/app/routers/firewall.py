"""Firewall (OPNsense) API routes."""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, Query

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service
from app.models.schemas import (
    StatsResponse,
    TimelineResponse,
    TimelinePoint,
    GeoDistributionResponse,
    GeoPoint,
    TopAttackersResponse,
    TopAttacker,
    FirewallBlockedTraffic,
    PortScanDetection,
    RepeatOffender,
)

router = APIRouter()
INDEX = ".ds-filebeat-*"

# Internal IP addresses to focus on
INTERNAL_IPS = ["193.246.121.231", "193.246.121.232", "193.246.121.233"]

# Firewall logs have a 1-hour offset (stored in local time but marked as UTC)
FIREWALL_TIMEZONE_OFFSET_HOURS = 1


def adjust_firewall_timestamp(timestamp_str: Optional[str]) -> Optional[str]:
    """Adjust firewall timestamp by adding the timezone offset."""
    if not timestamp_str:
        return timestamp_str
    try:
        # Parse ISO timestamp
        if timestamp_str.endswith('Z'):
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            dt = datetime.fromisoformat(timestamp_str)
        # Add offset to correct the time
        corrected = dt + timedelta(hours=FIREWALL_TIMEZONE_OFFSET_HOURS)
        return corrected.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    except Exception:
        return timestamp_str


@router.get("/stats", response_model=StatsResponse)
async def get_firewall_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall statistics."""
    es = get_es_service()
    
    # Use firewall-specific fields: fw.src_ip and source.ip
    try:
        result = await es.search(
            index=INDEX,
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "total": {"value_count": {"field": "@timestamp"}},
                "unique_ips": {"cardinality": {"field": "fw.src_ip"}}
            }
        )
        
        aggs = result.get("aggregations", {})
        total_events = aggs.get("total", {}).get("value", 0)
        unique_ips = aggs.get("unique_ips", {}).get("value", 0)
    except Exception:
        total_events = 0
        unique_ips = 0
    
    return StatsResponse(
        total_events=total_events,
        unique_ips=unique_ips,
        time_range=time_range
    )


@router.get("/timeline", response_model=TimelineResponse)
async def get_firewall_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall event timeline."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    timeline = await es.get_timeline(INDEX, time_range, interval)
    
    return TimelineResponse(
        data=[TimelinePoint(**point) for point in timeline],
        time_range=time_range
    )


@router.get("/geo", response_model=GeoDistributionResponse)
async def get_firewall_geo(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall geographic distribution."""
    es = get_es_service()
    
    geo_data = await es.get_geo_distribution(INDEX, time_range)
    
    return GeoDistributionResponse(
        data=[GeoPoint(**point) for point in geo_data],
        time_range=time_range
    )


@router.get("/top-attackers", response_model=TopAttackersResponse)
async def get_firewall_top_attackers(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=10, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """Get top blocked IPs."""
    es = get_es_service()
    
    top_ips = await es.get_top_source_ips(INDEX, time_range, size=limit)
    
    attackers = [
        TopAttacker(
            ip=ip_data["ip"],
            count=ip_data["count"],
            country=ip_data.get("geo", {}).get("country_name"),
            city=ip_data.get("geo", {}).get("city_name")
        )
        for ip_data in top_ips
    ]
    
    return TopAttackersResponse(data=attackers, time_range=time_range)


@router.get("/blocked", response_model=List[FirewallBlockedTraffic])
async def get_blocked_traffic(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get blocked traffic details."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"fw.action": "block"}}
                ]
            }
        },
        size=0,
        aggs={
            "blocked_ips": {
                "terms": {
                    "field": "source.ip",
                    "size": limit
                },
                "aggs": {
                    "ports": {
                        "terms": {
                            "field": "destination.port",
                            "size": 20
                        }
                    },
                    "protocols": {
                        "terms": {
                            "field": "network.transport",
                            "size": 10
                        }
                    },
                    "geo": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["source.geo.country_name"]
                        }
                    }
                }
            }
        }
    )
    
    blocked = []
    for bucket in result.get("aggregations", {}).get("blocked_ips", {}).get("buckets", []):
        hit = bucket["geo"]["hits"]["hits"][0]["_source"] if bucket["geo"]["hits"]["hits"] else {}
        
        ports = [p["key"] for p in bucket["ports"]["buckets"]]
        protocols = [p["key"] for p in bucket["protocols"]["buckets"]]
        
        blocked.append(FirewallBlockedTraffic(
            src_ip=bucket["key"],
            count=bucket["doc_count"],
            ports=ports,
            protocols=protocols,
            country=hit.get("source", {}).get("geo", {}).get("country_name")
        ))
    
    return blocked


@router.get("/events")
async def get_firewall_events(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    action: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    dst_ip: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get firewall events with details."""
    es = get_es_service()
    
    must_clauses = [es._get_time_range_query(time_range)]
    
    if action:
        must_clauses.append({"term": {"fw.action": action}})
    if src_ip:
        must_clauses.append({"term": {"source.ip": src_ip}})
    if dst_ip:
        must_clauses.append({"term": {"destination.ip": dst_ip}})
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": must_clauses}},
        size=limit,
        sort=[{"@timestamp": "desc"}]
    )
    
    events = []
    for hit in result.get("hits", {}).get("hits", []):
        source = hit["_source"]
        fw = source.get("fw", {})
        src_geo = source.get("source", {}).get("geo", {})
        location = src_geo.get("location", {})
        
        events.append({
            "id": hit["_id"],
            "timestamp": adjust_firewall_timestamp(source.get("@timestamp")),
            "action": fw.get("action"),
            "rule": fw.get("rule"),
            "interface": fw.get("iface"),
            "direction": source.get("network", {}).get("direction"),
            "transport": source.get("network", {}).get("transport"),
            "source_ip": source.get("source", {}).get("ip"),
            "source_port": source.get("source", {}).get("port"),
            "source_geo": {
                "country": src_geo.get("country_name"),
                "city": src_geo.get("city_name"),
                "lat": location.get("lat"),
                "lon": location.get("lon"),
            },
            "dest_ip": source.get("destination", {}).get("ip"),
            "dest_port": source.get("destination", {}).get("port"),
            "reason": fw.get("reason"),
        })
    
    return {
        "total": result.get("hits", {}).get("total", {}).get("value", 0),
        "events": events
    }


@router.get("/port-scans", response_model=List[PortScanDetection])
async def get_port_scans(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    min_ports: int = Query(default=10, ge=5, le=100),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """
    Detect potential port scans.
    
    Identifies IPs that have connected to many different ports,
    which is indicative of port scanning behavior.
    """
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "potential_scanners": {
                "terms": {
                    "field": "source.ip",
                    "size": limit * 2
                },
                "aggs": {
                    "unique_ports": {
                        "cardinality": {"field": "destination.port"}
                    },
                    "first_seen": {
                        "min": {"field": "@timestamp"}
                    },
                    "last_seen": {
                        "max": {"field": "@timestamp"}
                    },
                    "geo": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["source.geo.country_name"]
                        }
                    }
                }
            }
        }
    )
    
    scanners = []
    for bucket in result.get("aggregations", {}).get("potential_scanners", {}).get("buckets", []):
        unique_ports = bucket["unique_ports"]["value"]
        
        if unique_ports >= min_ports:
            hit = bucket["geo"]["hits"]["hits"][0]["_source"] if bucket["geo"]["hits"]["hits"] else {}
            
            scanners.append(PortScanDetection(
                src_ip=bucket["key"],
                unique_ports=int(unique_ports),
                time_window=time_range,
                first_seen=adjust_firewall_timestamp(bucket["first_seen"].get("value_as_string", "")),
                last_seen=adjust_firewall_timestamp(bucket["last_seen"].get("value_as_string", "")),
                country=hit.get("source", {}).get("geo", {}).get("country_name")
            ))
    
    scanners.sort(key=lambda x: x.unique_ports, reverse=True)
    
    return scanners[:limit]


@router.get("/repeat-offenders", response_model=List[RepeatOffender])
async def get_repeat_offenders(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    min_blocks: int = Query(default=100, ge=10),
    limit: int = Query(default=50, ge=1, le=500),
    _: str = Depends(get_current_user)
):
    """Get repeat offenders (IPs blocked multiple times)."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"fw.action": "block"}}
                ]
            }
        },
        size=0,
        aggs={
            "offenders": {
                "terms": {
                    "field": "source.ip",
                    "size": limit * 2,
                    "min_doc_count": min_blocks
                },
                "aggs": {
                    "first_seen": {
                        "min": {"field": "@timestamp"}
                    },
                    "last_seen": {
                        "max": {"field": "@timestamp"}
                    },
                    "ports": {
                        "terms": {
                            "field": "destination.port",
                            "size": 20
                        }
                    },
                    "geo": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["source.geo.country_name"]
                        }
                    }
                }
            }
        }
    )
    
    offenders = []
    for bucket in result.get("aggregations", {}).get("offenders", {}).get("buckets", []):
        hit = bucket["geo"]["hits"]["hits"][0]["_source"] if bucket["geo"]["hits"]["hits"] else {}
        
        ports = [p["key"] for p in bucket["ports"]["buckets"]]
        
        offenders.append(RepeatOffender(
            src_ip=bucket["key"],
            total_blocks=bucket["doc_count"],
            first_seen=adjust_firewall_timestamp(bucket["first_seen"].get("value_as_string", "")),
            last_seen=adjust_firewall_timestamp(bucket["last_seen"].get("value_as_string", "")),
            targeted_ports=ports,
            country=hit.get("source", {}).get("geo", {}).get("country_name")
        ))
    
    return offenders[:limit]


@router.get("/actions")
async def get_firewall_actions(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall action distribution."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "actions": {
                "terms": {
                    "field": "fw.action",
                    "size": 10
                }
            }
        }
    )
    
    actions = [
        {"action": bucket["key"], "count": bucket["doc_count"]}
        for bucket in result.get("aggregations", {}).get("actions", {}).get("buckets", [])
    ]
    
    return {"actions": actions, "time_range": time_range}


@router.get("/internal-hosts/{ip}")
async def get_internal_host_stats(
    ip: str,
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get statistics for a specific internal host.
    
    Focuses on the three internal IPs: 193.246.121.231, .232, .233
    """
    if ip not in INTERNAL_IPS:
        return {"error": f"IP {ip} is not a monitored internal host", "valid_ips": INTERNAL_IPS}
    
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"destination.ip": ip}}
                ]
            }
        },
        size=0,
        track_total_hits=True,
        aggs={
            "total_count": {"value_count": {"field": "@timestamp"}},
            "unique_sources": {"cardinality": {"field": "source.ip"}},
            "by_port": {
                "terms": {"field": "destination.port", "size": 20}
            },
            "by_protocol": {
                "terms": {"field": "network.transport.keyword", "size": 10}
            },
            "by_action": {
                "terms": {"field": "fw.action.keyword", "size": 5}
            },
            "top_sources": {
                "terms": {"field": "source.ip", "size": 10},
                "aggs": {
                    "geo": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["source.geo.country_name"]
                        }
                    }
                }
            },
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h"
                }
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    # Use value_count aggregation for accurate count (bypasses 10k hits limit)
    total_events = aggs.get("total_count", {}).get("value", 0)
    
    return {
        "ip": ip,
        "time_range": time_range,
        "total_events": int(total_events),
        "unique_sources": aggs.get("unique_sources", {}).get("value", 0),
        "by_port": [
            {"port": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_port", {}).get("buckets", [])
        ],
        "by_protocol": [
            {"protocol": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_protocol", {}).get("buckets", [])
        ],
        "by_action": [
            {"action": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_action", {}).get("buckets", [])
        ],
        "top_sources": [
            {
                "ip": b["key"],
                "count": b["doc_count"],
                "country": b["geo"]["hits"]["hits"][0]["_source"].get("source", {}).get("geo", {}).get("country_name") if b["geo"]["hits"]["hits"] else None
            }
            for b in aggs.get("top_sources", {}).get("buckets", [])
        ],
        "timeline": [
            {"timestamp": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs.get("timeline", {}).get("buckets", [])
        ]
    }


@router.get("/logs")
async def get_firewall_logs(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=100, ge=1, le=500),
    action: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    dst_ip: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    _: str = Depends(get_current_user)
):
    """Get firewall logs with filtering options."""
    es = get_es_service()
    
    filters = {}
    if action:
        filters["fw.action"] = action
    if src_ip:
        filters["source.ip"] = src_ip
    if dst_ip:
        filters["destination.ip"] = dst_ip
    
    return await es.get_logs(INDEX, time_range, limit, search, filters)


@router.get("/heatmap")
async def get_firewall_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hourly heatmap data for firewall."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    return {"data": heatmap_data, "time_range": time_range}


@router.get("/port-stats")
async def get_firewall_port_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    limit: int = Query(default=50, ge=1, le=100),
    _: str = Depends(get_current_user)
):
    """
    Get comprehensive port attack statistics.
    Shows which ports are most targeted by attackers.
    """
    es = get_es_service()
    
    # Port name mapping for common ports
    PORT_NAMES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
        137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
        161: "SNMP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1900: "SSDP",
        2222: "SSH-Alt", 2223: "SSH-Alt", 2224: "SSH-Alt",
        3000: "Dev-Server", 3306: "MySQL", 3389: "RDP", 3478: "STUN",
        5060: "SIP", 5432: "PostgreSQL", 5555: "ADB", 5900: "VNC",
        6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        8728: "MikroTik", 11211: "Memcached", 27017: "MongoDB"
    }
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "top_ports": {
                "terms": {"field": "destination.port", "size": limit},
                "aggs": {
                    "unique_attackers": {"cardinality": {"field": "source.ip"}},
                    "by_protocol": {"terms": {"field": "network.transport.keyword", "size": 3}}
                }
            },
            "total_unique_ports": {"cardinality": {"field": "destination.port"}},
            "total_unique_attackers": {"cardinality": {"field": "source.ip"}}
        }
    )
    
    aggs = result.get("aggregations", {})
    total_events = result.get("hits", {}).get("total", {}).get("value", 0)
    
    ports = []
    for bucket in aggs.get("top_ports", {}).get("buckets", []):
        port = bucket["key"]
        protocols = [p["key"] for p in bucket.get("by_protocol", {}).get("buckets", [])]
        
        ports.append({
            "port": port,
            "service": PORT_NAMES.get(port, "Unknown"),
            "attack_count": bucket["doc_count"],
            "unique_attackers": bucket["unique_attackers"]["value"],
            "protocols": protocols,
            "percentage": round(bucket["doc_count"] / total_events * 100, 2) if total_events > 0 else 0
        })
    
    return {
        "time_range": time_range,
        "total_events": total_events,
        "total_unique_ports": aggs.get("total_unique_ports", {}).get("value", 0),
        "total_unique_attackers": aggs.get("total_unique_attackers", {}).get("value", 0),
        "ports": ports
    }


@router.get("/protocol-stats")
async def get_firewall_protocol_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get protocol distribution statistics."""
    es = get_es_service()
    
    # Note: network.transport and network.direction are keyword-type in filebeat index
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_protocol": {
                "terms": {"field": "network.transport", "size": 10},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}},
                    "top_ports": {"terms": {"field": "destination.port", "size": 5}}
                }
            },
            "by_direction": {
                "terms": {"field": "network.direction", "size": 5}
            }
        }
    )
    
    aggs = result.get("aggregations", {})
    
    protocols = []
    for bucket in aggs.get("by_protocol", {}).get("buckets", []):
        top_ports = [p["key"] for p in bucket.get("top_ports", {}).get("buckets", [])]
        protocols.append({
            "protocol": bucket["key"].upper(),
            "count": bucket["doc_count"],
            "unique_ips": bucket["unique_ips"]["value"],
            "top_ports": top_ports
        })
    
    directions = []
    for bucket in aggs.get("by_direction", {}).get("buckets", []):
        directions.append({
            "direction": bucket["key"],
            "count": bucket["doc_count"]
        })
    
    return {
        "time_range": time_range,
        "protocols": protocols,
        "directions": directions
    }


@router.get("/service-attacks")
async def get_service_attack_summary(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get attack summary grouped by service category.
    Groups ports into logical service categories for high-level overview.
    """
    es = get_es_service()
    
    # Service categories with their ports
    SERVICE_CATEGORIES = {
        "SSH": [22, 2222, 2223, 2224],
        "HTTP/HTTPS": [80, 443, 8000, 8080, 8443, 3000],
        "RDP/VNC": [3389, 5900],
        "Database": [1433, 1521, 3306, 5432, 6379, 27017, 11211],
        "DNS": [53],
        "Email": [25, 110, 143, 993, 995],
        "VoIP/SIP": [5060, 5061],
        "IoT/SCADA": [102, 502, 1883, 8883],
        "File Sharing": [21, 137, 138, 139, 445],
        "Network Services": [67, 68, 123, 161, 1900, 3478]
    }
    
    # Build aggregation for each category
    port_list = []
    for ports in SERVICE_CATEGORIES.values():
        port_list.extend(ports)
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "ports": {
                "terms": {"field": "destination.port", "size": 200}
            }
        }
    )
    
    # Build port -> count mapping
    port_counts = {}
    for bucket in result.get("aggregations", {}).get("ports", {}).get("buckets", []):
        port_counts[bucket["key"]] = bucket["doc_count"]
    
    # Aggregate by category
    categories = []
    for category, ports in SERVICE_CATEGORIES.items():
        total = sum(port_counts.get(p, 0) for p in ports)
        if total > 0:
            port_breakdown = [
                {"port": p, "count": port_counts.get(p, 0)}
                for p in ports if port_counts.get(p, 0) > 0
            ]
            categories.append({
                "category": category,
                "total_attacks": total,
                "ports": sorted(port_breakdown, key=lambda x: -x["count"])
            })
    
    # Add "Other" category
    categorized_ports = set(port_list)
    other_total = sum(c for p, c in port_counts.items() if p not in categorized_ports)
    if other_total > 0:
        categories.append({
            "category": "Other",
            "total_attacks": other_total,
            "ports": []
        })
    
    # Sort by total attacks
    categories.sort(key=lambda x: -x["total_attacks"])
    
    return {
        "time_range": time_range,
        "categories": categories,
        "total_events": result.get("hits", {}).get("total", {}).get("value", 0)
    }


@router.get("/attack-trends")
async def get_attack_trends(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get attack trends over time with port breakdown."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0
                },
                "aggs": {
                    "by_port": {
                        "terms": {"field": "destination.port", "size": 5}
                    },
                    "unique_ips": {"cardinality": {"field": "source.ip"}}
                }
            }
        }
    )
    
    timeline = []
    for bucket in result.get("aggregations", {}).get("timeline", {}).get("buckets", []):
        top_ports = {
            str(p["key"]): p["doc_count"]
            for p in bucket.get("by_port", {}).get("buckets", [])
        }
        timeline.append({
            "timestamp": adjust_firewall_timestamp(bucket["key_as_string"]),
            "total": bucket["doc_count"],
            "unique_ips": bucket["unique_ips"]["value"],
            "top_ports": top_ports
        })
    
    return {"time_range": time_range, "timeline": timeline}


@router.get("/rule-stats")
async def get_firewall_rule_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get firewall rule trigger frequency."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_rule": {
                "terms": {"field": "fw.rule.keyword", "size": 30},
                "aggs": {
                    "by_action": {
                        "terms": {"field": "fw.action.keyword", "size": 5}
                    },
                    "unique_sources": {"cardinality": {"field": "source.ip"}}
                }
            },
            "total_rules": {"cardinality": {"field": "fw.rule.keyword"}}
        }
    )
    
    rules = []
    for bucket in result.get("aggregations", {}).get("by_rule", {}).get("buckets", []):
        actions = {a["key"]: a["doc_count"] for a in bucket.get("by_action", {}).get("buckets", [])}
        rules.append({
            "rule": bucket["key"],
            "count": bucket["doc_count"],
            "block_count": actions.get("block", 0),
            "pass_count": actions.get("pass", 0),
            "unique_sources": bucket.get("unique_sources", {}).get("value", 0)
        })
    
    return {
        "time_range": time_range,
        "rules": rules,
        "total_rules": result.get("aggregations", {}).get("total_rules", {}).get("value", 0)
    }


@router.get("/action-timeline")
async def get_firewall_action_timeline(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get block vs pass actions over time."""
    es = get_es_service()
    
    intervals = {"1h": "5m", "24h": "1h", "7d": "6h", "30d": "1d"}
    interval = intervals.get(time_range, "1h")
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval
                },
                "aggs": {
                    "block": {"filter": {"term": {"fw.action": "block"}}},
                    "pass": {"filter": {"term": {"fw.action": "pass"}}}
                }
            },
            "totals": {
                "terms": {"field": "fw.action.keyword", "size": 10}
            }
        }
    )
    
    timeline = []
    for bucket in result.get("aggregations", {}).get("over_time", {}).get("buckets", []):
        timeline.append({
            "timestamp": adjust_firewall_timestamp(bucket["key_as_string"]),
            "block": bucket.get("block", {}).get("doc_count", 0),
            "pass": bucket.get("pass", {}).get("doc_count", 0),
            "total": bucket["doc_count"]
        })
    
    totals = {t["key"]: t["doc_count"] for t in result.get("aggregations", {}).get("totals", {}).get("buckets", [])}
    
    return {
        "time_range": time_range,
        "timeline": timeline,
        "totals": totals
    }


@router.get("/direction-stats")
async def get_firewall_direction_stats(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get inbound vs outbound traffic breakdown."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_direction": {
                "terms": {"field": "network.direction.keyword", "size": 5},
                "aggs": {
                    "by_action": {"terms": {"field": "fw.action.keyword", "size": 5}},
                    "unique_sources": {"cardinality": {"field": "source.ip"}},
                    "top_ports": {"terms": {"field": "destination.port", "size": 5}}
                }
            }
        }
    )
    
    directions = []
    for bucket in result.get("aggregations", {}).get("by_direction", {}).get("buckets", []):
        actions = {a["key"]: a["doc_count"] for a in bucket.get("by_action", {}).get("buckets", [])}
        top_ports = [p["key"] for p in bucket.get("top_ports", {}).get("buckets", [])]
        directions.append({
            "direction": bucket["key"],
            "count": bucket["doc_count"],
            "block_count": actions.get("block", 0),
            "pass_count": actions.get("pass", 0),
            "unique_sources": bucket.get("unique_sources", {}).get("value", 0),
            "top_ports": top_ports
        })
    
    return {"time_range": time_range, "directions": directions}


@router.get("/attack-intensity-heatmap")
async def get_firewall_attack_intensity_heatmap(
    time_range: str = Query(default="7d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get hour x day attack intensity heatmap."""
    es = get_es_service()
    
    heatmap_data = await es.get_hourly_heatmap(INDEX, time_range)
    
    # Convert to matrix format
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    matrix = [[0 for _ in range(24)] for _ in range(7)]
    
    for point in heatmap_data:
        day = point.get("day", 0)
        hour = point.get("hour", 0)
        count = point.get("count", 0)
        if 0 <= day < 7 and 0 <= hour < 24:
            matrix[day][hour] = count
    
    # Find max for color scaling
    max_value = max(max(row) for row in matrix) if matrix else 1
    
    return {
        "time_range": time_range,
        "days": days,
        "matrix": matrix,
        "max_value": max_value
    }


@router.get("/tcp-flags")
async def get_firewall_tcp_flags(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get TCP flags distribution for scan detection."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query={"bool": {"must": [
            es._get_time_range_query(time_range),
            {"term": {"fw.proto": "tcp"}}
        ]}},
        size=1000,
        fields=["fw.flags", "fw.rest", "source.ip", "destination.port"]
    )
    
    # Parse TCP flags from the fw.rest field which contains SYN/ACK/FIN/RST etc
    flag_counts = {}
    scan_types = {
        "SYN Scan": 0,
        "FIN Scan": 0,
        "XMAS Scan": 0,
        "NULL Scan": 0,
        "ACK Scan": 0,
        "Normal": 0,
    }
    
    # The fw.rest field contains TCP flag info like "0,S,1439231576,,65535,,mss;..."
    for hit in result.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        rest = src.get("fw", {}).get("rest", "")
        flags = src.get("fw", {}).get("flags", "")
        
        # Count DF/none flags
        if flags:
            flag_counts[flags] = flag_counts.get(flags, 0) + 1
        
        # Parse TCP flags from rest field
        if rest:
            parts = rest.split(",")
            if len(parts) >= 2:
                tcp_flags = parts[1].upper() if len(parts) > 1 else ""
                
                # Detect scan types
                if tcp_flags == "S":
                    scan_types["SYN Scan"] += 1
                elif tcp_flags == "F":
                    scan_types["FIN Scan"] += 1
                elif "FPU" in tcp_flags or tcp_flags == "FUP":
                    scan_types["XMAS Scan"] += 1
                elif tcp_flags == "" or tcp_flags == ".":
                    scan_types["NULL Scan"] += 1
                elif tcp_flags == "A":
                    scan_types["ACK Scan"] += 1
                else:
                    scan_types["Normal"] += 1
    
    flags_list = [{"flag": k, "count": v} for k, v in sorted(flag_counts.items(), key=lambda x: -x[1])]
    scan_list = [{"scan_type": k, "count": v} for k, v in sorted(scan_types.items(), key=lambda x: -x[1]) if v > 0]
    
    return {
        "time_range": time_range,
        "flags": flags_list,
        "scan_types": scan_list,
        "total_tcp_packets": len(result.get("hits", {}).get("hits", []))
    }


@router.get("/ttl-analysis")
async def get_firewall_ttl_analysis(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get TTL distribution for OS fingerprinting."""
    es = get_es_service()
    
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "ttl_distribution": {
                "terms": {"field": "fw.ttl.keyword", "size": 50}
            }
        }
    )
    
    # Common initial TTL values
    os_fingerprints = {
        "Windows": 0,  # TTL 128
        "Linux/Unix": 0,  # TTL 64
        "Cisco/Network": 0,  # TTL 255
        "Solaris": 0,  # TTL 255
        "Unknown": 0,
    }
    
    ttl_buckets = []
    for bucket in result.get("aggregations", {}).get("ttl_distribution", {}).get("buckets", []):
        ttl_str = bucket["key"]
        count = bucket["doc_count"]
        
        try:
            ttl = int(ttl_str)
            
            # Estimate initial TTL and OS
            if ttl > 128:
                initial_ttl = 255
                os_guess = "Cisco/Network"
            elif ttl > 64:
                initial_ttl = 128
                os_guess = "Windows"
            elif ttl > 0:
                initial_ttl = 64
                os_guess = "Linux/Unix"
            else:
                initial_ttl = 0
                os_guess = "Unknown"
            
            hops = initial_ttl - ttl
            
            os_fingerprints[os_guess] += count
            ttl_buckets.append({
                "ttl": ttl,
                "count": count,
                "estimated_initial": initial_ttl,
                "estimated_hops": max(0, hops),
                "os_guess": os_guess
            })
        except ValueError:
            ttl_buckets.append({"ttl": ttl_str, "count": count, "os_guess": "Unknown"})
            os_fingerprints["Unknown"] += count
    
    os_list = [{"os": k, "count": v} for k, v in sorted(os_fingerprints.items(), key=lambda x: -x[1]) if v > 0]
    
    return {
        "time_range": time_range,
        "ttl_distribution": sorted(ttl_buckets, key=lambda x: -x["count"])[:20],
        "os_fingerprints": os_list,
        "total_packets": sum(b["count"] for b in ttl_buckets)
    }


@router.get("/packet-sizes")
async def get_firewall_packet_sizes(
    time_range: str = Query(default="24h", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """Get packet size distribution histogram."""
    es = get_es_service()
    
    # fw.length is stored as string, so we need to aggregate by terms
    result = await es.search(
        index=INDEX,
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "common_sizes": {
                "terms": {"field": "fw.length.keyword", "size": 50}
            }
        }
    )
    
    # Parse sizes and build histogram
    size_counts = []
    for bucket in result.get("aggregations", {}).get("common_sizes", {}).get("buckets", []):
        try:
            size = int(bucket["key"])
            size_counts.append({"size": size, "count": bucket["doc_count"]})
        except ValueError:
            pass
    
    # Build histogram by ranges
    histogram_buckets = {}
    all_sizes = []
    for item in size_counts:
        size = item["size"]
        count = item["count"]
        all_sizes.extend([size] * min(count, 100))  # Limit for stats calculation
        
        bucket_key = (size // 100) * 100  # 100-byte buckets
        if bucket_key not in histogram_buckets:
            histogram_buckets[bucket_key] = 0
        histogram_buckets[bucket_key] += count
    
    histogram = [
        {"range": f"{k}-{k+99}", "min_size": k, "count": v}
        for k, v in sorted(histogram_buckets.items())
    ]
    
    # Calculate stats
    if all_sizes:
        min_size = min(all_sizes)
        max_size = max(all_sizes)
        avg_size = sum(all_sizes) / len(all_sizes)
        total_count = sum(item["count"] for item in size_counts)
    else:
        min_size = max_size = avg_size = total_count = 0
    
    # Common packet sizes with their meaning
    size_meanings = {
        40: "TCP SYN (minimum)",
        52: "TCP SYN with options",
        60: "TCP with options",
        64: "Common minimum",
        96: "Small data packet",
        1500: "Max MTU",
    }
    
    common_sizes = []
    for item in sorted(size_counts, key=lambda x: -x["count"])[:20]:
        common_sizes.append({
            "size": str(item["size"]),
            "count": item["count"],
            "meaning": size_meanings.get(item["size"], "")
        })
    
    return {
        "time_range": time_range,
        "histogram": histogram,
        "stats": {
            "min": min_size,
            "max": max_size,
            "avg": round(avg_size, 1),
            "count": total_count
        },
        "common_sizes": common_sizes
    }
