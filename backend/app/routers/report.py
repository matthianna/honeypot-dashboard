"""Thesis Report API routes - Aggregated analysis for academic research."""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query

from app.auth.jwt import get_current_user
from app.dependencies import get_es_service

router = APIRouter()

# Honeypot indices
INDICES = {
    "cowrie": ".ds-cowrie-*",
    "dionaea": "dionaea-*",
    "galah": ".ds-galah-*",
    "rdpy": ".ds-rdpy-*",
    "heralding": ".ds-heralding-*",
    "firewall": ".ds-filebeat-*",
}

# Variant display names
VARIANT_NAMES = {
    "plain": "Plain (Standard)",
    "openai": "OpenAI (GPT)",
    "ollama": "Ollama (Local LLM)",
}


@router.get("/thesis-summary")
async def get_thesis_summary(
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get executive summary for thesis report.
    Aggregates key metrics across all honeypots for the study period.
    """
    es = get_es_service()
    
    # Get stats for each honeypot
    honeypot_stats = {}
    total_events = 0
    total_unique_ips = set()
    
    for name, index in INDICES.items():
        if name == "firewall":
            continue  # Skip firewall for main honeypot stats
        
        try:
            result = await es.search(
                index=index,
                query=es._get_time_range_query(time_range),
                size=0,
                aggs={
                    "unique_ips": {"cardinality": {"field": es.FIELD_MAPPINGS.get(name, {}).get("src_ip", "source.ip")}},
                    "countries": {"cardinality": {"field": es.FIELD_MAPPINGS.get(name, {}).get("geo_country", "source.geo.country_name")}},
                }
            )
            
            events = result.get("hits", {}).get("total", {}).get("value", 0)
            unique_ips = result.get("aggregations", {}).get("unique_ips", {}).get("value", 0)
            countries = result.get("aggregations", {}).get("countries", {}).get("value", 0)
            
            honeypot_stats[name] = {
                "events": events,
                "unique_ips": unique_ips,
                "countries": countries,
            }
            total_events += events
        except Exception as e:
            honeypot_stats[name] = {"events": 0, "unique_ips": 0, "countries": 0, "error": str(e)}
    
    # Get overall unique IPs and countries
    all_ips_result = await es.search(
        index=",".join([v for k, v in INDICES.items() if k != "firewall"]),
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "unique_ips": {"cardinality": {"field": "source.ip"}},
            "countries": {"cardinality": {"field": "source.geo.country_name"}},
        }
    )
    
    # Get time range boundaries
    time_bounds = await es.search(
        index=",".join([v for k, v in INDICES.items() if k != "firewall"]),
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "min_time": {"min": {"field": "@timestamp"}},
            "max_time": {"max": {"field": "@timestamp"}},
        }
    )
    
    aggs = time_bounds.get("aggregations", {})
    
    return {
        "study_period": {
            "time_range": time_range,
            "start": aggs.get("min_time", {}).get("value_as_string"),
            "end": aggs.get("max_time", {}).get("value_as_string"),
        },
        "totals": {
            "total_events": total_events,
            "unique_ips": all_ips_result.get("aggregations", {}).get("unique_ips", {}).get("value", 0),
            "countries": all_ips_result.get("aggregations", {}).get("countries", {}).get("value", 0),
        },
        "by_honeypot": honeypot_stats,
        "honeypot_percentages": {
            name: round(stats["events"] / total_events * 100, 2) if total_events > 0 else 0
            for name, stats in honeypot_stats.items()
        }
    }


@router.get("/llm-comparison")
async def get_llm_comparison(
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get detailed LLM vs Plain Cowrie comparison metrics.
    This is the key analysis for the thesis comparing honeypot effectiveness.
    """
    es = get_es_service()
    
    # Get aggregated metrics by variant
    result = await es.search(
        index=INDICES["cowrie"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "by_variant": {
                "terms": {"field": "cowrie_variant", "size": 10},
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "json.src_ip"}},
                    "sessions": {"cardinality": {"field": "json.session"}},
                    "login_success": {"filter": {"term": {"json.eventid": "cowrie.login.success"}}},
                    "login_failed": {"filter": {"term": {"json.eventid": "cowrie.login.failed"}}},
                    "commands": {
                        "filter": {"term": {"json.eventid": "cowrie.command.input"}},
                        "aggs": {
                            "unique_commands": {"cardinality": {"field": "json.input"}}
                        }
                    },
                    "downloads": {"filter": {"term": {"json.eventid": "cowrie.session.file_download"}}},
                    "session_new": {"filter": {"term": {"json.eventid": "cowrie.session.connect"}}},
                    "session_closed": {"filter": {"term": {"json.eventid": "cowrie.session.closed"}}},
                }
            }
        }
    )
    
    variants = []
    for bucket in result.get("aggregations", {}).get("by_variant", {}).get("buckets", []):
        variant_key = bucket["key"]
        
        # Calculate derived metrics
        sessions = bucket["session_new"]["doc_count"]
        logins = bucket["login_success"]["doc_count"] + bucket["login_failed"]["doc_count"]
        login_success = bucket["login_success"]["doc_count"]
        commands = bucket["commands"]["doc_count"]
        downloads = bucket["downloads"]["doc_count"]
        
        # Engagement funnel
        login_rate = round(logins / sessions * 100, 2) if sessions > 0 else 0
        success_rate = round(login_success / logins * 100, 2) if logins > 0 else 0
        command_rate = round(commands / login_success * 100, 2) if login_success > 0 else 0
        
        # Get duration stats for this variant
        duration_stats = await get_variant_duration_stats(es, time_range, variant_key)
        
        # Get top commands for this variant
        top_commands = await get_variant_top_commands(es, time_range, variant_key, limit=10)
        
        variants.append({
            "variant": variant_key,
            "display_name": VARIANT_NAMES.get(variant_key, variant_key.title()),
            "metrics": {
                "total_events": bucket["doc_count"],
                "unique_ips": bucket["unique_ips"]["value"],
                "sessions": sessions,
                "login_attempts": logins,
                "login_success": login_success,
                "login_failed": bucket["login_failed"]["doc_count"],
                "commands_executed": commands,
                "unique_commands": bucket["commands"].get("unique_commands", {}).get("value", 0),
                "file_downloads": downloads,
            },
            "engagement": {
                "login_rate": login_rate,
                "success_rate": success_rate,
                "command_rate": command_rate,
                "commands_per_session": round(commands / sessions, 2) if sessions > 0 else 0,
            },
            "duration": duration_stats,
            "top_commands": top_commands,
        })
    
    # Sort by total events (most active first)
    variants.sort(key=lambda x: x["metrics"]["total_events"], reverse=True)
    
    # Calculate effectiveness comparison
    effectiveness = {}
    if len(variants) >= 2:
        # Compare LLM variants to plain
        plain_data = next((v for v in variants if v["variant"] == "plain"), None)
        if plain_data:
            for v in variants:
                if v["variant"] != "plain":
                    effectiveness[v["variant"]] = {
                        "vs_plain": {
                            "session_duration_ratio": round(v["duration"]["avg"] / plain_data["duration"]["avg"], 2) if plain_data["duration"]["avg"] > 0 else 0,
                            "command_ratio": round(v["metrics"]["commands_executed"] / plain_data["metrics"]["commands_executed"], 2) if plain_data["metrics"]["commands_executed"] > 0 else 0,
                            "engagement_ratio": round(v["engagement"]["command_rate"] / plain_data["engagement"]["command_rate"], 2) if plain_data["engagement"]["command_rate"] > 0 else 0,
                        }
                    }
    
    return {
        "time_range": time_range,
        "variants": variants,
        "effectiveness_comparison": effectiveness,
    }


async def get_variant_duration_stats(es, time_range: str, variant: str) -> Dict[str, Any]:
    """Get duration statistics for a variant."""
    result = await es.search(
        index=INDICES["cowrie"],
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"json.eventid": "cowrie.session.closed"}},
                    {"term": {"cowrie_variant": variant}},
                    {"exists": {"field": "json.duration"}}
                ]
            }
        },
        size=5000,
        fields=["json.duration"]
    )
    
    durations = []
    for hit in result.get("hits", {}).get("hits", []):
        try:
            duration_str = hit["_source"].get("json", {}).get("duration")
            if duration_str:
                durations.append(float(duration_str))
        except (ValueError, TypeError):
            pass
    
    if not durations:
        return {"avg": 0, "max": 0, "min": 0, "median": 0, "count": 0}
    
    durations_sorted = sorted(durations)
    median_idx = len(durations_sorted) // 2
    
    return {
        "avg": round(sum(durations) / len(durations), 2),
        "max": round(max(durations), 2),
        "min": round(min(durations), 2),
        "median": round(durations_sorted[median_idx], 2),
        "count": len(durations),
    }


async def get_variant_top_commands(es, time_range: str, variant: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Get top commands for a variant."""
    result = await es.search(
        index=INDICES["cowrie"],
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"json.eventid": "cowrie.command.input"}},
                    {"term": {"cowrie_variant": variant}}
                ]
            }
        },
        size=0,
        aggs={
            "top_commands": {"terms": {"field": "json.input", "size": limit}}
        }
    )
    
    return [
        {"command": b["key"], "count": b["doc_count"]}
        for b in result.get("aggregations", {}).get("top_commands", {}).get("buckets", [])
    ]


@router.get("/pattern-analysis")
async def get_pattern_analysis(
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get attack pattern analysis with MITRE ATT&CK mapping and categorization.
    """
    es = get_es_service()
    
    # Get command categorization from Cowrie
    commands_result = await es.search(
        index=INDICES["cowrie"],
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"term": {"json.eventid": "cowrie.command.input"}}
                ]
            }
        },
        size=0,
        aggs={
            "top_commands": {"terms": {"field": "json.input", "size": 100}},
            "by_variant": {
                "terms": {"field": "cowrie_variant"},
                "aggs": {
                    "commands": {"terms": {"field": "json.input", "size": 20}}
                }
            }
        }
    )
    
    # Categorize commands
    command_categories = {
        "reconnaissance": [],
        "credential_access": [],
        "persistence": [],
        "defense_evasion": [],
        "execution": [],
        "collection": [],
        "exfiltration": [],
        "other": []
    }
    
    # MITRE ATT&CK mappings
    mitre_mappings = {
        "T1082": {"name": "System Information Discovery", "count": 0, "commands": []},
        "T1083": {"name": "File and Directory Discovery", "count": 0, "commands": []},
        "T1105": {"name": "Ingress Tool Transfer", "count": 0, "commands": []},
        "T1059": {"name": "Command and Scripting Interpreter", "count": 0, "commands": []},
        "T1098": {"name": "Account Manipulation", "count": 0, "commands": []},
        "T1070": {"name": "Indicator Removal", "count": 0, "commands": []},
        "T1053": {"name": "Scheduled Task/Job", "count": 0, "commands": []},
        "T1222": {"name": "File and Directory Permissions Modification", "count": 0, "commands": []},
    }
    
    for bucket in commands_result.get("aggregations", {}).get("top_commands", {}).get("buckets", []):
        cmd = bucket["key"].lower()
        count = bucket["doc_count"]
        
        # Categorize and map to MITRE
        if any(x in cmd for x in ["uname", "cat /proc", "whoami", "id", "hostname", "lscpu", "df", "free"]):
            command_categories["reconnaissance"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1082"]["count"] += count
            mitre_mappings["T1082"]["commands"].append(bucket["key"][:50])
        elif any(x in cmd for x in ["ls", "find", "locate", "pwd"]):
            command_categories["reconnaissance"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1083"]["count"] += count
        elif any(x in cmd for x in ["wget", "curl", "tftp", "ftp"]):
            command_categories["execution"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1105"]["count"] += count
            mitre_mappings["T1105"]["commands"].append(bucket["key"][:50])
        elif any(x in cmd for x in ["chmod", "chattr", "chown"]):
            command_categories["persistence"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1222"]["count"] += count
        elif any(x in cmd for x in ["rm ", "history -c", "/var/log", "wtmp"]):
            command_categories["defense_evasion"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1070"]["count"] += count
        elif any(x in cmd for x in ["crontab", "systemctl", "service"]):
            command_categories["persistence"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1053"]["count"] += count
        elif any(x in cmd for x in ["ssh-rsa", "authorized_keys", ".ssh"]):
            command_categories["persistence"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1098"]["count"] += count
            mitre_mappings["T1098"]["commands"].append(bucket["key"][:50])
        elif any(x in cmd for x in ["sh", "bash", "python", "perl", "php"]):
            command_categories["execution"].append({"command": bucket["key"], "count": count})
            mitre_mappings["T1059"]["count"] += count
        else:
            command_categories["other"].append({"command": bucket["key"], "count": count})
    
    # Get credential patterns
    credentials_result = await es.search(
        index=INDICES["cowrie"],
        query={
            "bool": {
                "must": [
                    es._get_time_range_query(time_range),
                    {"terms": {"json.eventid": ["cowrie.login.success", "cowrie.login.failed"]}}
                ]
            }
        },
        size=0,
        aggs={
            "top_usernames": {"terms": {"field": "json.username", "size": 20}},
            "top_passwords": {"terms": {"field": "json.password", "size": 20}},
        }
    )
    
    # Get protocol distribution from Heralding
    protocol_result = await es.search(
        index=INDICES["heralding"],
        query=es._get_time_range_query(time_range),
        size=0,
        aggs={
            "protocols": {"terms": {"field": "network.protocol", "size": 20}}
        }
    )
    
    return {
        "time_range": time_range,
        "command_categories": {
            cat: {"count": len(cmds), "total_executions": sum(c["count"] for c in cmds), "top_5": cmds[:5]}
            for cat, cmds in command_categories.items()
        },
        "mitre_techniques": [
            {"technique_id": tid, **data}
            for tid, data in sorted(mitre_mappings.items(), key=lambda x: x[1]["count"], reverse=True)
            if data["count"] > 0
        ],
        "credentials": {
            "top_usernames": [
                {"username": b["key"], "count": b["doc_count"]}
                for b in credentials_result.get("aggregations", {}).get("top_usernames", {}).get("buckets", [])
            ],
            "top_passwords": [
                {"password": b["key"], "count": b["doc_count"]}
                for b in credentials_result.get("aggregations", {}).get("top_passwords", {}).get("buckets", [])
            ],
        },
        "protocols": [
            {"protocol": b["key"], "count": b["doc_count"]}
            for b in protocol_result.get("aggregations", {}).get("protocols", {}).get("buckets", [])
        ],
    }


@router.get("/trend-analysis")
async def get_trend_analysis(
    _: str = Depends(get_current_user)
):
    """
    Get time-based trend analysis for thesis.
    Compares different time periods and shows attack patterns.
    """
    es = get_es_service()
    
    # Get weekly data for the last 4 weeks
    weekly_data = []
    for i in range(4):
        week_end = datetime.utcnow() - timedelta(weeks=i)
        week_start = week_end - timedelta(weeks=1)
        
        result = await es.search(
            index=",".join([v for k, v in INDICES.items() if k != "firewall"]),
            query={
                "range": {
                    "@timestamp": {
                        "gte": week_start.isoformat(),
                        "lt": week_end.isoformat()
                    }
                }
            },
            size=0,
            aggs={
                "unique_ips": {"cardinality": {"field": "source.ip"}},
                "by_honeypot": {
                    "filters": {
                        "filters": {
                            "cowrie": {"wildcard": {"_index": "*cowrie*"}},
                            "dionaea": {"wildcard": {"_index": "*dionaea*"}},
                            "galah": {"wildcard": {"_index": "*galah*"}},
                            "rdpy": {"wildcard": {"_index": "*rdpy*"}},
                            "heralding": {"wildcard": {"_index": "*heralding*"}},
                        }
                    }
                }
            }
        )
        
        weekly_data.append({
            "week": f"Week {4-i}",
            "start": week_start.isoformat(),
            "end": week_end.isoformat(),
            "total_events": result.get("hits", {}).get("total", {}).get("value", 0),
            "unique_ips": result.get("aggregations", {}).get("unique_ips", {}).get("value", 0),
            "by_honeypot": {
                name: bucket.get("doc_count", 0)
                for name, bucket in result.get("aggregations", {}).get("by_honeypot", {}).get("buckets", {}).items()
            }
        })
    
    # Get hourly pattern (aggregate over 30 days)
    hourly_result = await es.search(
        index=",".join([v for k, v in INDICES.items() if k != "firewall"]),
        query=es._get_time_range_query("30d"),
        size=0,
        aggs={
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "hour"
                }
            }
        }
    )
    
    # Aggregate by hour of day
    hour_counts = [0] * 24
    for bucket in hourly_result.get("aggregations", {}).get("by_hour", {}).get("buckets", []):
        try:
            hour = datetime.fromisoformat(bucket["key_as_string"].replace("Z", "+00:00")).hour
            hour_counts[hour] += bucket["doc_count"]
        except:
            pass
    
    # Get day of week pattern
    daily_result = await es.search(
        index=",".join([v for k, v in INDICES.items() if k != "firewall"]),
        query=es._get_time_range_query("30d"),
        size=0,
        aggs={
            "by_day": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "day"
                }
            }
        }
    )
    
    # Aggregate by day of week
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    day_counts = [0] * 7
    for bucket in daily_result.get("aggregations", {}).get("by_day", {}).get("buckets", []):
        try:
            day = datetime.fromisoformat(bucket["key_as_string"].replace("Z", "+00:00")).weekday()
            day_counts[day] += bucket["doc_count"]
        except:
            pass
    
    return {
        "weekly_trends": weekly_data,
        "hourly_pattern": [
            {"hour": h, "count": c}
            for h, c in enumerate(hour_counts)
        ],
        "daily_pattern": [
            {"day": day_names[i], "day_index": i, "count": c}
            for i, c in enumerate(day_counts)
        ],
        "peak_hour": max(range(24), key=lambda h: hour_counts[h]),
        "peak_day": day_names[max(range(7), key=lambda d: day_counts[d])],
    }


@router.get("/key-findings")
async def get_key_findings(
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Generate key findings for thesis based on data analysis.
    """
    es = get_es_service()
    
    findings = []
    
    # Get summary data
    summary = await get_thesis_summary(time_range, _)
    llm_comparison = await get_llm_comparison(time_range, _)
    
    # Finding 1: Total attack volume
    total_events = summary["totals"]["total_events"]
    findings.append({
        "category": "Overview",
        "finding": f"The honeypot network recorded {total_events:,} attack events from {summary['totals']['unique_ips']:,} unique IP addresses across {summary['totals']['countries']} countries during the study period.",
        "significance": "high"
    })
    
    # Finding 2: Most targeted honeypot
    most_targeted = max(summary["by_honeypot"].items(), key=lambda x: x[1]["events"])
    findings.append({
        "category": "Attack Distribution",
        "finding": f"{most_targeted[0].title()} was the most targeted honeypot, receiving {summary['honeypot_percentages'][most_targeted[0]]}% of all attacks ({most_targeted[1]['events']:,} events).",
        "significance": "medium"
    })
    
    # Finding 3: LLM effectiveness
    if llm_comparison["variants"]:
        plain = next((v for v in llm_comparison["variants"] if v["variant"] == "plain"), None)
        llm_variants = [v for v in llm_comparison["variants"] if v["variant"] != "plain"]
        
        if plain and llm_variants:
            for llm in llm_variants:
                if llm["duration"]["avg"] > plain["duration"]["avg"]:
                    ratio = round(llm["duration"]["avg"] / plain["duration"]["avg"], 2)
                    findings.append({
                        "category": "LLM Effectiveness",
                        "finding": f"{llm['display_name']} achieved {ratio}x longer average session duration ({llm['duration']['avg']}s) compared to Plain honeypot ({plain['duration']['avg']}s), suggesting improved attacker engagement.",
                        "significance": "high"
                    })
    
    # Finding 4: Command patterns
    if llm_comparison["variants"]:
        total_commands = sum(v["metrics"]["commands_executed"] for v in llm_comparison["variants"])
        if total_commands > 0:
            findings.append({
                "category": "Attacker Behavior",
                "finding": f"Attackers executed {total_commands:,} total commands across all Cowrie variants, with an average of {round(total_commands/len(llm_comparison['variants']), 1)} commands per variant.",
                "significance": "medium"
            })
    
    return {
        "time_range": time_range,
        "findings": findings,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/geographic-analysis")
async def get_geographic_analysis(
    time_range: str = Query(default="30d", pattern="^(1h|24h|7d|30d)$"),
    _: str = Depends(get_current_user)
):
    """
    Get geographic distribution analysis for thesis.
    """
    es = get_es_service()
    
    # Get country distribution for each honeypot
    honeypot_geo = {}
    
    for name, index in INDICES.items():
        if name == "firewall":
            continue
            
        geo_field = es.FIELD_MAPPINGS.get(name, {}).get("geo_country", "source.geo.country_name")
        
        result = await es.search(
            index=index,
            query=es._get_time_range_query(time_range),
            size=0,
            aggs={
                "countries": {"terms": {"field": geo_field, "size": 50}}
            }
        )
        
        honeypot_geo[name] = [
            {"country": b["key"], "count": b["doc_count"]}
            for b in result.get("aggregations", {}).get("countries", {}).get("buckets", [])
        ]
    
    # Aggregate all countries
    all_countries = {}
    for name, countries in honeypot_geo.items():
        for c in countries:
            if c["country"] not in all_countries:
                all_countries[c["country"]] = {"total": 0, "by_honeypot": {}}
            all_countries[c["country"]]["total"] += c["count"]
            all_countries[c["country"]]["by_honeypot"][name] = c["count"]
    
    # Sort by total
    top_countries = sorted(
        [{"country": k, **v} for k, v in all_countries.items()],
        key=lambda x: x["total"],
        reverse=True
    )[:20]
    
    return {
        "time_range": time_range,
        "top_countries": top_countries,
        "by_honeypot": honeypot_geo,
        "total_countries": len(all_countries),
    }


