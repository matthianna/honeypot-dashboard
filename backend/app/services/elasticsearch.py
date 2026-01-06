"""Elasticsearch service for querying honeypot data."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import structlog
from elasticsearch import AsyncElasticsearch

logger = structlog.get_logger()

# Internal/private IPs to exclude from statistics
INTERNAL_IPS = {"193.246.121.231", "193.246.121.232", "193.246.121.233"}
INTERNAL_IP_PREFIXES = [
    "192.168.", "10.", "127.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", 
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", 
    "172.28.", "172.29.", "172.30.", "172.31."
]


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private and should be excluded."""
    if not ip:
        return True
    if ip in INTERNAL_IPS:
        return True
    for prefix in INTERNAL_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


class ElasticsearchService:
    """Service for interacting with Elasticsearch."""
    
    # Index patterns for each honeypot (updated based on actual ES indices)
    INDICES = {
        "cowrie": ".ds-cowrie-*",
        "dionaea": "dionaea-*",
        "galah": ".ds-galah-*",
        "rdpy": ".ds-rdpy-*",
        "heralding": ".ds-heralding-*",
        "firewall": ".ds-filebeat-*",
    }
    
    # Field mappings for each honeypot (src_ip and geo fields vary by index)
    # NOTE: Cowrie now uses json.* structure from new filebeat pipeline
    FIELD_MAPPINGS = {
        "cowrie": {
            "src_ip": "json.src_ip",  # Updated: now in json.* namespace
            "geo_country": "cowrie.geo.country_name",  # Cowrie uses cowrie.geo namespace
            "geo_country_fallback": "source.geo.country_name",  # Fallback for older data
            "geo_city": "cowrie.geo.city_name",
            "geo_location": "cowrie.geo.location",
            "session": "json.session",  # Updated
            "eventid": "json.eventid",  # Updated
            "sensor": "observer.name",  # Updated: sensor name in observer.name
        },
        "dionaea": {
            # Note: Dionaea uses TEXT fields that require .keyword for aggregations
            "src_ip": "source.ip.keyword",  # Text field needs .keyword for aggregations
            "geo_country": "source.geo.country_name.keyword",  # Text field needs .keyword
            "geo_city": "source.geo.city_name.keyword",
            "geo_location": "source.geo.location",
            "component": "dionaea.component",
            "transport": "network.transport",
            "dst_port": "destination.port",
        },
        "galah": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "session": "session.id",
            "http_method": "http.request.method",
            "http_uri": "url.path",
        },
        "rdpy": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
        },
        "heralding": {
            "src_ip": "source.ip",
            "geo_country": "source.geo.country_name",  # Already keyword type
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "session": "session_id",
            "protocol": "network.protocol",  # Already keyword type
            "dst_port": "destination.port",
        },
        "firewall": {
            "src_ip": "fw.src_ip",  # Fixed: firewall uses fw.src_ip field
            "geo_country": "source.geo.country_name",  # Already keyword type in filebeat index
            "geo_city": "source.geo.city_name",
            "geo_location": "source.geo.location",
            "action": "fw.action",  # Already keyword type
            "dst_port": "fw.dst_port",  # Fixed: firewall uses fw.dst_port
            "dst_ip": "fw.dst_ip",  # Fixed: firewall uses fw.dst_ip
            "transport": "network.transport",  # Already keyword type
            "direction": "fw.dir",  # Fixed: firewall uses fw.dir
        },
    }
    
    def __init__(self, elasticsearch_url: str):
        """Initialize Elasticsearch service."""
        self.url = elasticsearch_url
        self.client: Optional[AsyncElasticsearch] = None
    
    async def connect(self):
        """Connect to Elasticsearch."""
        self.client = AsyncElasticsearch(
            hosts=[self.url],
            verify_certs=False,
            request_timeout=30,
        )
        
        # Verify connection (don't fail if Elasticsearch is not available)
        try:
            info = await self.client.info()
            logger.info("elasticsearch_connected", version=info["version"]["number"])
        except Exception as e:
            logger.warning("elasticsearch_connection_failed", error=str(e), url=self.url)
            logger.warning("elasticsearch_will_retry", message="Will retry on each request")
    
    async def close(self):
        """Close Elasticsearch connection."""
        if self.client:
            await self.client.close()
    
    def _get_honeypot_from_index(self, index: str) -> str:
        """Determine honeypot type from index pattern."""
        for honeypot, pattern in self.INDICES.items():
            if pattern == index or honeypot in index.lower():
                return honeypot
        return "firewall"  # Default fallback
    
    def _get_field(self, index: str, field_type: str) -> str:
        """Get the correct field name for a honeypot index."""
        honeypot = self._get_honeypot_from_index(index)
        mapping = self.FIELD_MAPPINGS.get(honeypot, self.FIELD_MAPPINGS["firewall"])
        return mapping.get(field_type, field_type)
    
    # Firewall logs have a 1-hour timezone offset (stored in local time but marked as UTC)
    FIREWALL_TIMEZONE_OFFSET_HOURS = 1
    
    def _get_time_range_query(self, time_range: str = "24h", is_firewall: bool = False) -> Dict[str, Any]:
        """Get time range filter for queries.
        
        Args:
            time_range: Time range string (1h, 24h, 7d, 30d)
            is_firewall: If True, applies 1-hour offset adjustment for firewall logs
        """
        now = datetime.utcnow()
        
        time_ranges = {
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }
        
        delta = time_ranges.get(time_range, timedelta(hours=24))
        
        if is_firewall:
            # Firewall logs are stored 1 hour behind actual time
            # Shift the window back to compensate
            offset = timedelta(hours=self.FIREWALL_TIMEZONE_OFFSET_HOURS)
            start_time = now - delta - offset
        else:
            start_time = now - delta
        
        return {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": now.isoformat(),
                }
            }
        }
    
    # Dionaea debug messages to exclude (these are internal noise, not real attacks)
    DIONAEA_NOISE_PATTERNS = [
        "connection_idle_timeout_cb",
        "traceable_idle_timeout_cb",
        "traceable_established_cb",
        "processor_data_creation",
        "processor_data_deletion",
        "processors_init",
        "connection_protocol_ctx_get",
        "connection_idle_timeout_set",
        "connection_tls_handshake_again_cb",
        "SSL_do_handshake",
        "creating filter",
        "creating streamdumper",
        "skip filter",
    ]
    
    def _get_base_filter(self, index: str) -> List[Dict[str, Any]]:
        """Get base filters for each honeypot to exclude noise.
        
        For Dionaea: Only include events with source.ip (real connections).
        For Cowrie: Only include events with actual src_ip (real connections).
        For RDPY: Exclude debug/info messages.
        """
        honeypot = self._get_honeypot_from_index(index)
        
        if honeypot == "dionaea":
            # Only include actual connection events (those with source.ip)
            return [{"exists": {"field": "source.ip"}}]
        
        if honeypot == "cowrie":
            # Only include events with actual IP - use should to match either field
            return [{
                "bool": {
                    "should": [
                        {"exists": {"field": "json.src_ip"}},
                        {"exists": {"field": "cowrie.src_ip"}}
                    ],
                    "minimum_should_match": 1
                }
            }]
        
        if honeypot == "rdpy":
            # Only include events with source.ip (real connections)
            return [{"exists": {"field": "source.ip"}}]
        
        return []
    
    def _get_rdpy_noise_exclusion(self) -> List[Dict[str, Any]]:
        """Get must_not clauses to exclude RDPY debug/info noise messages."""
        return [
            {"match_phrase": {"message": "[*] INFO:"}},
            {"prefix": {"message": "[*] INFO:"}},
            {"prefix": {"message.keyword": "[*] INFO:"}},
        ]
    
    def _get_cowrie_noise_exclusion(self) -> List[Dict[str, Any]]:
        """Get must_not clauses to exclude Cowrie noise/meta events.
        
        Excludes by eventid:
        - cowrie.client.fingerprint - SSH client hassh fingerprint
        - cowrie.client.version - Remote SSH version
        - cowrie.client.size - Terminal size
        - cowrie.log.closed - Closing tty log
        - cowrie.client.kex - Key exchange (noise)
        """
        # Filter by eventid field (supports both json.eventid and cowrie.eventid)
        noise_eventids = [
            "cowrie.client.fingerprint",
            "cowrie.client.version", 
            "cowrie.client.size",
            "cowrie.log.closed",
            "cowrie.client.kex",
        ]
        
        return [
            {"terms": {"json.eventid": noise_eventids}},
            {"terms": {"cowrie.eventid": noise_eventids}},
        ]
    
    def _get_dionaea_noise_exclusion(self) -> List[Dict[str, Any]]:
        """Get must_not clauses to exclude Dionaea debug noise messages.
        
        Note: Keep this minimal to avoid filtering out real attack data.
        The exists: source.ip filter in _get_base_filter already excludes most noise.
        """
        # Only exclude explicit debug-level logs
        return [{"term": {"log.level": "debug"}}]
    
    def build_dionaea_query(self, time_range: str = "24h", additional_must: List[Dict] = None) -> Dict[str, Any]:
        """Build a filtered Dionaea query excluding internal IPs and noise.
        
        This helper ensures all Dionaea queries consistently filter out:
        - Internal IPs (192.168.x.x, 10.x.x.x, etc.)
        - Debug noise messages (timeout callbacks, etc.)
        - Events without source.ip (not real connections)
        """
        must_clauses = [
            self._get_time_range_query(time_range),
            {"exists": {"field": "source.ip"}}  # Only real connections
        ]
        
        if additional_must:
            must_clauses.extend(additional_must)
        
        must_not_clauses = []
        must_not_clauses.extend(self._get_internal_ip_exclusion("dionaea-*"))
        must_not_clauses.extend(self._get_dionaea_noise_exclusion())
        
        return {
            "bool": {
                "must": must_clauses,
                "must_not": must_not_clauses
            }
        }
    
    def _get_internal_ip_exclusion(self, index: str) -> List[Dict[str, Any]]:
        """Get must_not clauses to exclude internal IPs.
        
        Uses 'terms' query for specific IPs only.
        For the 192.168.211.* range, data is filtered post-query if needed.
        """
        src_ip_field = self._get_field(index, "src_ip")
        
        # Combine all internal IPs into a single terms query
        # This is the safest approach that works for both text and ip field types
        all_internal = list(INTERNAL_IPS)
        
        return [{"terms": {src_ip_field: all_internal}}]
    
    async def get_total_events(self, index: str, time_range: str = "24h", exclude_internal: bool = True) -> int:
        """Get total event count for an index, excluding internal IPs and noise."""
        try:
            # Check if this is a firewall query (needs timezone offset adjustment)
            is_firewall = "filebeat" in index or index == self.INDICES.get("firewall")
            honeypot = self._get_honeypot_from_index(index)
            must_clauses = [self._get_time_range_query(time_range, is_firewall=is_firewall)]
            must_clauses.extend(self._get_base_filter(index))
            
            must_not_clauses = []
            if exclude_internal:
                must_not_clauses.extend(self._get_internal_ip_exclusion(index))
            
            # Exclude debug noise messages for specific honeypots
            if honeypot == "dionaea":
                must_not_clauses.extend(self._get_dionaea_noise_exclusion())
            if honeypot == "rdpy":
                must_not_clauses.extend(self._get_rdpy_noise_exclusion())
            if honeypot == "cowrie":
                must_not_clauses.extend(self._get_cowrie_noise_exclusion())
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if must_not_clauses:
                query["bool"]["must_not"] = must_not_clauses
            
            result = await self.client.count(
                index=index,
                body={"query": query}
            )
            return result["count"]
        except Exception as e:
            logger.error("elasticsearch_count_failed", index=index, error=str(e))
            return 0
    
    async def get_unique_ips(self, index: str, time_range: str = "24h", exclude_internal: bool = True) -> int:
        """Get unique source IP count for an index, excluding internal IPs and noise."""
        src_ip_field = self._get_field(index, "src_ip")
        honeypot = self._get_honeypot_from_index(index)
        
        try:
            # Check if this is a firewall query (needs timezone offset adjustment)
            is_firewall = "filebeat" in index or index == self.INDICES.get("firewall")
            must_clauses = [self._get_time_range_query(time_range, is_firewall=is_firewall)]
            must_clauses.extend(self._get_base_filter(index))
            
            must_not_clauses = []
            if exclude_internal:
                must_not_clauses.extend(self._get_internal_ip_exclusion(index))
            
            # Exclude debug noise messages for specific honeypots
            if honeypot == "dionaea":
                must_not_clauses.extend(self._get_dionaea_noise_exclusion())
            if honeypot == "rdpy":
                must_not_clauses.extend(self._get_rdpy_noise_exclusion())
            if honeypot == "cowrie":
                must_not_clauses.extend(self._get_cowrie_noise_exclusion())
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if must_not_clauses:
                query["bool"]["must_not"] = must_not_clauses
            
            # For cowrie, aggregate both old (json.src_ip) and new (cowrie.src_ip) field structures
            aggs = {}
            if honeypot == "cowrie":
                aggs = {
                    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
                    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}}
                }
            else:
                aggs = {"unique_ips": {"cardinality": {"field": src_ip_field}}}
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": aggs
                }
            )
            
            if honeypot == "cowrie":
                # Combine results from both field structures
                old_count = result["aggregations"].get("unique_ips_old", {}).get("value", 0)
                new_count = result["aggregations"].get("unique_ips_new", {}).get("value", 0)
                return max(old_count, new_count)  # Use max since they represent the same data
            else:
                return result["aggregations"]["unique_ips"]["value"]
        except Exception as e:
            logger.error("elasticsearch_unique_ips_failed", index=index, error=str(e))
            return 0
    
    async def get_timeline(
        self,
        index: str,
        time_range: str = "24h",
        interval: str = "1h"
    ) -> List[Dict[str, Any]]:
        """Get event timeline for an index."""
        try:
            honeypot = self._get_honeypot_from_index(index)
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            # Build must_not clauses for noise exclusion
            must_not_clauses = []
            if honeypot == "dionaea":
                must_not_clauses.extend(self._get_dionaea_noise_exclusion())
            if honeypot == "rdpy":
                must_not_clauses.extend(self._get_rdpy_noise_exclusion())
            if honeypot == "cowrie":
                must_not_clauses.extend(self._get_cowrie_noise_exclusion())
            
            query = {"bool": {"must": must_clauses}}
            if must_not_clauses:
                query["bool"]["must_not"] = must_not_clauses
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": {
                        "timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": interval,
                            }
                        }
                    }
                }
            )
            
            buckets = result["aggregations"]["timeline"]["buckets"]
            return [
                {
                    "timestamp": bucket["key_as_string"],
                    "count": bucket["doc_count"]
                }
                for bucket in buckets
            ]
        except Exception as e:
            logger.error("elasticsearch_timeline_failed", index=index, error=str(e))
            return []
    
    async def get_top_source_ips(
        self,
        index: str,
        time_range: str = "24h",
        size: int = 10,
        exclude_internal: bool = True
    ) -> List[Dict[str, Any]]:
        """Get top source IPs for an index, excluding internal IPs and noise."""
        src_ip_field = self._get_field(index, "src_ip")
        geo_country_field = self._get_field(index, "geo_country")
        geo_city_field = self._get_field(index, "geo_city")
        geo_location_field = self._get_field(index, "geo_location")
        honeypot = self._get_honeypot_from_index(index)
        
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            # Build must_not clauses
            must_not_clauses = []
            if exclude_internal:
                must_not_clauses.extend(self._get_internal_ip_exclusion(index))
            
            # Add noise exclusion for specific honeypots
            if honeypot == "dionaea":
                must_not_clauses.extend(self._get_dionaea_noise_exclusion())
            if honeypot == "rdpy":
                must_not_clauses.extend(self._get_rdpy_noise_exclusion())
            if honeypot == "cowrie":
                must_not_clauses.extend(self._get_cowrie_noise_exclusion())
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if must_not_clauses:
                query["bool"]["must_not"] = must_not_clauses
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": {
                        "top_ips": {
                            "terms": {
                                "field": src_ip_field,
                                "size": size
                            },
                            "aggs": {
                                "geo": {
                                    "top_hits": {
                                        "size": 1,
                                        "_source": [geo_country_field, geo_city_field, geo_location_field]
                                    }
                                }
                            }
                        }
                    }
                }
            )
            
            buckets = result["aggregations"]["top_ips"]["buckets"]
            results = []
            
            for bucket in buckets:
                ip = bucket["key"]
                
                # Post-query filter for internal/private IPs
                if exclude_internal and is_internal_ip(ip):
                    continue
                    
                geo_data = {}
                if bucket["geo"]["hits"]["hits"]:
                    source = bucket["geo"]["hits"]["hits"][0]["_source"]
                    # Navigate nested structure to extract geo data
                    geo_data = self._extract_geo_data(source, index)
                
                results.append({
                    "ip": ip,
                    "count": bucket["doc_count"],
                    "geo": geo_data
                })
            
            return results
        except Exception as e:
            logger.error("elasticsearch_top_ips_failed", index=index, error=str(e))
            return []
    
    def _extract_geo_data(self, source: Dict[str, Any], index: str) -> Dict[str, Any]:
        """Extract geo data from nested source structure."""
        honeypot = self._get_honeypot_from_index(index)
        
        if honeypot == "cowrie":
            cowrie = source.get("cowrie", {})
            geo = cowrie.get("geo", {})
            return {
                "country_name": geo.get("country_name"),
                "city_name": geo.get("city_name"),
                "location": geo.get("location"),
            }
        else:
            # Standard ECS format: source.geo.*
            source_data = source.get("source", {})
            geo = source_data.get("geo", {})
            return {
                "country_name": geo.get("country_name"),
                "city_name": geo.get("city_name"),
                "location": geo.get("location"),
            }
    
    async def get_geo_distribution(
        self,
        index: str,
        time_range: str = "24h",
        size: int = 50,
        exclude_internal: bool = True
    ) -> List[Dict[str, Any]]:
        """Get geographic distribution of attacks, excluding internal IPs and noise."""
        geo_country_field = self._get_field(index, "geo_country")
        honeypot = self._get_honeypot_from_index(index)
        
        try:
            must_clauses = [self._get_time_range_query(time_range)]
            must_clauses.extend(self._get_base_filter(index))
            
            # Build must_not clauses
            must_not_clauses = []
            if exclude_internal:
                must_not_clauses.extend(self._get_internal_ip_exclusion(index))
            
            # Add noise exclusion for specific honeypots
            if honeypot == "dionaea":
                must_not_clauses.extend(self._get_dionaea_noise_exclusion())
            if honeypot == "rdpy":
                must_not_clauses.extend(self._get_rdpy_noise_exclusion())
            if honeypot == "cowrie":
                must_not_clauses.extend(self._get_cowrie_noise_exclusion())
            
            query = {
                "bool": {
                    "must": must_clauses,
                }
            }
            
            if must_not_clauses:
                query["bool"]["must_not"] = must_not_clauses
            
            # For Cowrie, aggregate on both possible geo fields (try with and without .keyword)
            if honeypot == "cowrie":
                aggs = {
                    "countries_cowrie": {
                        "terms": {
                            "field": "cowrie.geo.country_name",
                            "size": size
                        }
                    },
                    "countries_cowrie_kw": {
                        "terms": {
                            "field": "cowrie.geo.country_name.keyword",
                            "size": size
                        }
                    },
                    "countries_source": {
                        "terms": {
                            "field": "source.geo.country_name",
                            "size": size
                        }
                    },
                    "countries_source_kw": {
                        "terms": {
                            "field": "source.geo.country_name.keyword",
                            "size": size
                        }
                    }
                }
            else:
                aggs = {
                    "countries": {
                        "terms": {
                            "field": geo_country_field,
                            "size": size
                        }
                    }
                }
            
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": query,
                    "aggs": aggs
                }
            )
            
            # For Cowrie, merge results from all possible geo field locations
            if honeypot == "cowrie":
                country_counts = {}
                for agg_name in ["countries_cowrie", "countries_cowrie_kw", "countries_source", "countries_source_kw"]:
                    buckets = result["aggregations"].get(agg_name, {}).get("buckets", [])
                    for bucket in buckets:
                        # Use max count for each country (not sum, since same data may be in multiple fields)
                        if bucket["key"] not in country_counts or bucket["doc_count"] > country_counts[bucket["key"]]:
                            country_counts[bucket["key"]] = bucket["doc_count"]
                
                # Sort by count and return
                sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:size]
                return [{"country": country, "count": count} for country, count in sorted_countries]
            else:
                buckets = result["aggregations"]["countries"]["buckets"]
                return [
                    {
                        "country": bucket["key"],
                        "count": bucket["doc_count"]
                    }
                    for bucket in buckets
                ]
        except Exception as e:
            logger.error("elasticsearch_geo_failed", index=index, error=str(e), exc_info=True)
            import traceback
            traceback.print_exc()
            return []
    
    async def get_recent_events(
        self,
        index: str,
        size: int = 50,
        fields: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Get recent events from an index."""
        try:
            body: Dict[str, Any] = {
                "size": size,
                "sort": [{"@timestamp": "desc"}],
            }
            
            if fields:
                body["_source"] = fields
            
            result = await self.client.search(index=index, body=body)
            
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error("elasticsearch_recent_events_failed", index=index, error=str(e))
            return []
    
    async def search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 100,
        sort: Optional[List[Dict[str, str]]] = None,
        aggs: Optional[Dict[str, Any]] = None,
        fields: Optional[List[str]] = None,
        from_: int = 0,
        track_total_hits: bool = False,
    ) -> Dict[str, Any]:
        """Execute a custom search query."""
        try:
            body: Dict[str, Any] = {
                "query": query,
                "size": size,
                "from": from_,
            }
            
            if sort:
                body["sort"] = sort
            if aggs:
                body["aggs"] = aggs
            if fields:
                body["_source"] = fields
            if track_total_hits:
                body["track_total_hits"] = True
            
            result = await self.client.search(index=index, body=body)
            return result
        except Exception as e:
            logger.error("elasticsearch_search_failed", index=index, error=str(e))
            return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}
    
    async def get_events_for_ip(
        self,
        ip: str,
        indices: Optional[List[str]] = None,
        time_range: str = "30d",
        size: int = 1000
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get all events for a specific IP across all honeypots.
        
        Handles Cowrie dual-field structure (json.src_ip and cowrie.src_ip).
        """
        if indices is None:
            indices = list(self.INDICES.values())
        
        results = {}
        
        for index in indices:
            try:
                honeypot = self._get_honeypot_from_index(index)
                
                # Apply firewall time offset if needed
                is_firewall = honeypot == "firewall" or "filebeat" in index
                
                # Build IP query - handle Cowrie dual fields
                if honeypot == "cowrie":
                    ip_query = {
                        "bool": {
                            "should": [
                                {"term": {"json.src_ip": ip}},
                                {"term": {"cowrie.src_ip": ip}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                else:
                    src_ip_field = self._get_field(index, "src_ip")
                    ip_query = {"term": {src_ip_field: ip}}
                
                result = await self.client.search(
                    index=index,
                    body={
                        "size": size,
                        "query": {
                            "bool": {
                                "must": [
                                    ip_query,
                                    self._get_time_range_query(time_range, is_firewall=is_firewall)
                                ]
                            }
                        },
                        "sort": [{"@timestamp": "desc"}]
                    }
                )
                
                events = [hit["_source"] for hit in result["hits"]["hits"]]
                if events:
                    results[honeypot] = events
            except Exception as e:
                logger.error("elasticsearch_ip_search_failed", index=index, ip=ip, error=str(e))
        
        return results
    
    async def get_event_counts_for_ip(
        self,
        ip: str,
        indices: Optional[List[str]] = None,
        time_range: str = "30d"
    ) -> Dict[str, int]:
        """Get accurate event counts for a specific IP across all honeypots using count API.
        
        This avoids the size limit issue when counting total events.
        """
        if indices is None:
            indices = list(self.INDICES.values())
        
        results = {}
        
        for index in indices:
            try:
                honeypot = self._get_honeypot_from_index(index)
                
                # Apply firewall time offset if needed
                is_firewall = honeypot == "firewall" or "filebeat" in index
                
                # Build IP query - handle Cowrie dual fields
                if honeypot == "cowrie":
                    ip_query = {
                        "bool": {
                            "should": [
                                {"term": {"json.src_ip": ip}},
                                {"term": {"cowrie.src_ip": ip}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                else:
                    src_ip_field = self._get_field(index, "src_ip")
                    ip_query = {"term": {src_ip_field: ip}}
                
                # Use count API for accurate total
                count_result = await self.client.count(
                    index=index,
                    body={
                        "query": {
                            "bool": {
                                "must": [
                                    ip_query,
                                    self._get_time_range_query(time_range, is_firewall=is_firewall)
                                ]
                            }
                        }
                    }
                )
                
                count = count_result.get("count", 0)
                if count > 0:
                    results[honeypot] = count
            except Exception as e:
                logger.error("elasticsearch_ip_count_failed", index=index, ip=ip, error=str(e))
        
        return results
    
    async def get_hourly_heatmap(
        self,
        index: str,
        time_range: str = "7d"
    ) -> List[Dict[str, Any]]:
        """Get hourly heatmap data for an index."""
        try:
            result = await self.client.search(
                index=index,
                body={
                    "size": 0,
                    "query": self._get_time_range_query(time_range),
                    "aggs": {
                        "by_day": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "calendar_interval": "day"
                            },
                            "aggs": {
                                "by_hour": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "calendar_interval": "hour"
                                    }
                                }
                            }
                        }
                    }
                }
            )
            
            heatmap_data = []
            for day_bucket in result["aggregations"]["by_day"]["buckets"]:
                day = day_bucket["key_as_string"]
                for hour_bucket in day_bucket["by_hour"]["buckets"]:
                    hour = datetime.fromisoformat(hour_bucket["key_as_string"].replace("Z", "+00:00")).hour
                    heatmap_data.append({
                        "day": day,
                        "hour": hour,
                        "count": hour_bucket["doc_count"]
                    })
            
            return heatmap_data
        except Exception as e:
            logger.error("elasticsearch_heatmap_failed", index=index, error=str(e))
            return []
    
    async def get_raw_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Get a raw document by ID."""
        try:
            # Use search with ids query for data stream compatibility
            result = await self.client.search(
                index=index,
                query={"ids": {"values": [doc_id]}},
                size=1
            )
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
            return None
        except Exception as e:
            logger.error("elasticsearch_get_document_failed", index=index, doc_id=doc_id, error=str(e))
            return None
    
    async def get_logs(
        self,
        index: str,
        time_range: str = "24h",
        size: int = 100,
        search_query: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get logs with optional search and filters."""
        must_clauses = [self._get_time_range_query(time_range)]
        
        if search_query:
            must_clauses.append({
                "query_string": {
                    "query": f"*{search_query}*",
                    "default_operator": "AND"
                }
            })
        
        if filters:
            for field, value in filters.items():
                if value is not None:
                    must_clauses.append({"term": {field: value}})
        
        try:
            result = await self.client.search(
                index=index,
                body={
                    "size": size,
                    "query": {"bool": {"must": must_clauses}},
                    "sort": [{"@timestamp": "desc"}]
                }
            )
            
            return {
                "total": result["hits"]["total"]["value"],
                "logs": [
                    {
                        "id": hit["_id"],
                        "index": hit["_index"],
                        **hit["_source"]
                    }
                    for hit in result["hits"]["hits"]
                ]
            }
        except Exception as e:
            logger.error("elasticsearch_logs_failed", index=index, error=str(e))
            return {"total": 0, "logs": []}
    
    async def get_global_stats(self, time_range: str = "24h", exclude_firewall: bool = False) -> Dict[str, Any]:
        """
        Get UNIFIED global statistics across ALL honeypots.
        
        This is the single source of truth for:
        - Total unique IPs (properly deduplicated across all honeypots)
        - Total unique countries (properly counted across all honeypots)
        - Total events by honeypot
        
        Uses document count (not value_count) for accurate event counting.
        
        Args:
            time_range: Time range for query (1h, 24h, 7d, 30d)
            exclude_firewall: If True, excludes firewall data from results
        """
        try:
            # Collect all unique IPs from all honeypots
            all_ips = set()
            all_countries = set()
            honeypot_stats = {}
            
            # Query each honeypot separately to handle different field structures
            for honeypot, index in self.INDICES.items():
                # Skip firewall if excluded
                if exclude_firewall and honeypot == "firewall":
                    continue
                is_firewall = honeypot == "firewall"
                time_query = self._get_time_range_query(time_range, is_firewall=is_firewall)
                
                # Build query with proper filters
                must_clauses = [time_query]
                must_clauses.extend(self._get_base_filter(index))
                
                must_not_clauses = self._get_internal_ip_exclusion(index)
                if honeypot == "dionaea":
                    must_not_clauses.extend(self._get_dionaea_noise_exclusion())
                if honeypot == "rdpy":
                    must_not_clauses.extend(self._get_rdpy_noise_exclusion())
                if honeypot == "cowrie":
                    must_not_clauses.extend(self._get_cowrie_noise_exclusion())
                
                query = {"bool": {"must": must_clauses, "must_not": must_not_clauses}}
                
                try:
                    # First get document count (accurate event count)
                    count_result = await self.client.count(index=index, body={"query": query})
                    event_count = count_result.get("count", 0)
                    
                    # Initialize honeypot stats
                    honeypot_stats[honeypot] = {"events": event_count, "ips": set()}
                    
                    # For Cowrie, use multi-field aggregation and try multiple country field locations
                    if honeypot == "cowrie":
                        # Try multiple country fields for Cowrie
                        cowrie_country_fields = ["source.geo.country_name", "cowrie.geo.country_name"]
                        
                        result = await self.client.search(
                            index=index,
                            body={
                                "size": 0,
                                "query": query,
                                "aggs": {
                                    "unique_ips_json": {"terms": {"field": "json.src_ip", "size": 50000}},
                                    "unique_ips_cowrie": {"terms": {"field": "cowrie.src_ip", "size": 50000}},
                                    "unique_ips_source": {"terms": {"field": "source.ip", "size": 50000}},
                                    # Try both country field locations
                                    "unique_countries_source": {"terms": {"field": "source.geo.country_name", "size": 300}},
                                    "unique_countries_cowrie": {"terms": {"field": "cowrie.geo.country_name", "size": 300}}
                                }
                            }
                        )
                        
                        # Collect IPs from all possible fields
                        for bucket in result.get("aggregations", {}).get("unique_ips_json", {}).get("buckets", []):
                            ip = bucket["key"]
                            if ip and not is_internal_ip(ip):
                                all_ips.add(ip)
                                honeypot_stats[honeypot]["ips"].add(ip)
                        
                        for bucket in result.get("aggregations", {}).get("unique_ips_cowrie", {}).get("buckets", []):
                            ip = bucket["key"]
                            if ip and not is_internal_ip(ip):
                                all_ips.add(ip)
                                honeypot_stats[honeypot]["ips"].add(ip)
                        
                        for bucket in result.get("aggregations", {}).get("unique_ips_source", {}).get("buckets", []):
                            ip = bucket["key"]
                            if ip and not is_internal_ip(ip):
                                all_ips.add(ip)
                                honeypot_stats[honeypot]["ips"].add(ip)
                        
                        # Collect countries from both possible field locations
                        for agg_name in ["unique_countries_source", "unique_countries_cowrie"]:
                            for bucket in result.get("aggregations", {}).get(agg_name, {}).get("buckets", []):
                                country = bucket["key"]
                                if country and country not in ["", "Unknown", "Private range"]:
                                    all_countries.add(country)
                    else:
                        # Standard query for other honeypots
                        ip_field = self._get_field(index, "src_ip")
                        country_field = self._get_field(index, "geo_country")
                        result = await self.client.search(
                            index=index,
                            body={
                                "size": 0,
                                "query": query,
                                "aggs": {
                                    "unique_ips": {"terms": {"field": ip_field, "size": 50000}},
                                    "unique_countries": {"terms": {"field": country_field, "size": 300}}
                                }
                            }
                        )
                        
                        for bucket in result.get("aggregations", {}).get("unique_ips", {}).get("buckets", []):
                            ip = bucket["key"]
                            if ip and not is_internal_ip(ip):
                                all_ips.add(ip)
                                honeypot_stats[honeypot]["ips"].add(ip)
                        
                        # Collect unique countries (for non-Cowrie honeypots)
                        for bucket in result.get("aggregations", {}).get("unique_countries", {}).get("buckets", []):
                            country = bucket["key"]
                            if country and country not in ["", "Unknown", "Private range"]:
                                all_countries.add(country)
                            
                except Exception as e:
                    logger.warning(f"Error querying {honeypot}: {e}")
                    continue
            
            # Calculate totals
            total_events = sum(stats["events"] for stats in honeypot_stats.values())
            
            return {
                "total_unique_ips": len(all_ips),
                "total_unique_countries": len(all_countries),
                "total_events": total_events,
                "countries_list": sorted(list(all_countries)),
                "honeypots": {
                    hp: {
                        "events": int(stats["events"]),
                        "unique_ips": len(stats["ips"])
                    }
                    for hp, stats in honeypot_stats.items()
                }
            }
        except Exception as e:
            logger.error("global_stats_failed", error=str(e))
            return {
                "total_unique_ips": 0,
                "total_unique_countries": 0,
                "total_events": 0,
                "countries_list": [],
                "honeypots": {}
            }
    
    async def get_global_country_breakdown(self, time_range: str = "24h", exclude_firewall: bool = False) -> Dict[str, Any]:
        """
        Get unified country statistics across ALL honeypots.
        
        Returns properly deduplicated IP counts per country.
        Uses document count per country to avoid double-counting for Cowrie.
        
        Args:
            time_range: Time range filter (1h, 24h, 7d, 30d)
            exclude_firewall: If True, exclude firewall data from the results
        """
        try:
            country_data = {}  # country -> {ips: set(), events: int, processed_honeypots: set()}
            
            for honeypot, index in self.INDICES.items():
                # Skip firewall if requested
                if exclude_firewall and honeypot == "firewall":
                    continue
                    
                is_firewall = honeypot == "firewall"
                time_query = self._get_time_range_query(time_range, is_firewall=is_firewall)
                
                must_clauses = [time_query]
                must_clauses.extend(self._get_base_filter(index))
                
                must_not_clauses = self._get_internal_ip_exclusion(index)
                if honeypot == "dionaea":
                    must_not_clauses.extend(self._get_dionaea_noise_exclusion())
                if honeypot == "rdpy":
                    must_not_clauses.extend(self._get_rdpy_noise_exclusion())
                if honeypot == "cowrie":
                    must_not_clauses.extend(self._get_cowrie_noise_exclusion())
                
                query = {"bool": {"must": must_clauses, "must_not": must_not_clauses}}
                
                try:
                    # For Cowrie, try multiple country field locations and get both IP fields in one query
                    if honeypot == "cowrie":
                        # Try multiple country field options for Cowrie
                        cowrie_country_fields = [
                            "source.geo.country_name",      # Standard ECS location
                            "cowrie.geo.country_name",      # Cowrie-specific namespace
                        ]
                        
                        cowrie_found_data = False
                        for country_field in cowrie_country_fields:
                            if cowrie_found_data:
                                break
                                
                            try:
                                result = await self.client.search(
                                    index=index,
                                    body={
                                        "size": 0,
                                        "query": query,
                                        "aggs": {
                                            "countries": {
                                                "terms": {"field": country_field, "size": 300},
                                                "aggs": {
                                                    "ips_json": {"terms": {"field": "json.src_ip", "size": 10000}},
                                                    "ips_cowrie": {"terms": {"field": "cowrie.src_ip", "size": 10000}},
                                                    "ips_source": {"terms": {"field": "source.ip", "size": 10000}}
                                                }
                                            }
                                        }
                                    }
                                )
                                
                                buckets = result.get("aggregations", {}).get("countries", {}).get("buckets", [])
                                if not buckets:
                                    continue  # Try next country field
                                
                                cowrie_found_data = True
                                for country_bucket in buckets:
                                    country = country_bucket["key"]
                                    if country and country not in ["", "Unknown", "Private range"]:
                                        if country not in country_data:
                                            country_data[country] = {"ips": set(), "events": 0, "processed_honeypots": set()}
                                        
                                        # Add events only once per honeypot
                                        if honeypot not in country_data[country]["processed_honeypots"]:
                                            country_data[country]["events"] += country_bucket["doc_count"]
                                            country_data[country]["processed_honeypots"].add(honeypot)
                                        
                                        # Collect IPs from all possible fields
                                        for ip_bucket in country_bucket.get("ips_json", {}).get("buckets", []):
                                            ip = ip_bucket["key"]
                                            if ip and not is_internal_ip(ip):
                                                country_data[country]["ips"].add(ip)
                                        for ip_bucket in country_bucket.get("ips_cowrie", {}).get("buckets", []):
                                            ip = ip_bucket["key"]
                                            if ip and not is_internal_ip(ip):
                                                country_data[country]["ips"].add(ip)
                                        for ip_bucket in country_bucket.get("ips_source", {}).get("buckets", []):
                                            ip = ip_bucket["key"]
                                            if ip and not is_internal_ip(ip):
                                                country_data[country]["ips"].add(ip)
                            except Exception:
                                continue  # Try next country field
                    else:
                        # Standard query for other honeypots
                        ip_field = self._get_field(index, "src_ip")
                        result = await self.client.search(
                            index=index,
                            body={
                                "size": 0,
                                "query": query,
                                "aggs": {
                                    "countries": {
                                        "terms": {"field": country_field, "size": 300},
                                        "aggs": {
                                            "ips": {"terms": {"field": ip_field, "size": 10000}}
                                        }
                                    }
                                }
                            }
                        )
                        
                        for country_bucket in result.get("aggregations", {}).get("countries", {}).get("buckets", []):
                            country = country_bucket["key"]
                            if country and country not in ["", "Unknown", "Private range"]:
                                if country not in country_data:
                                    country_data[country] = {"ips": set(), "events": 0, "processed_honeypots": set()}
                                
                                # Add events
                                country_data[country]["events"] += country_bucket["doc_count"]
                                country_data[country]["processed_honeypots"].add(honeypot)
                                
                                # Add unique IPs
                                for ip_bucket in country_bucket.get("ips", {}).get("buckets", []):
                                    ip = ip_bucket["key"]
                                    if ip and not is_internal_ip(ip):
                                        country_data[country]["ips"].add(ip)
                                        
                except Exception as e:
                    logger.warning(f"Error querying countries for {honeypot}: {e}")
                    continue
            
            # Convert to list and sort by events
            countries_list = [
                {
                    "country": country,
                    "unique_ips": len(data["ips"]),
                    "total_events": data["events"]
                }
                for country, data in country_data.items()
            ]
            countries_list.sort(key=lambda x: -x["total_events"])
            
            return {
                "time_range": time_range,
                "total_countries": len(countries_list),
                "countries": countries_list
            }
        except Exception as e:
            logger.error("global_country_breakdown_failed", error=str(e))
            return {"time_range": time_range, "total_countries": 0, "countries": []}
