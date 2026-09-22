"""
VHost & SNI enumeration graph updates.

Writes Vulnerability nodes with source="vhost_sni_enum" that reuse the existing
Vulnerability label. A hidden vhost is a routing fact, never a DNS one, so this
module writes no RESOLVES_TO edge: a server answering for a Host header does not
mean a resolver would return that IP, and behind a shared proxy it usually would
not. Each finding still has to be reachable from the graph, so it is attached to
the Subdomain for an in-scope hostname (created if recon has not seen it yet,
flagged has_dns_records=false until a resolver confirms it) or to the IP that
served it for an out-of-scope one. The IP node is also enriched with vhost_*
properties (baseline, reverse-proxy flag, hidden vhost count). When the module
discovers a hidden vhost and inject_discovered is enabled, a BaseURL is created
so downstream tools (Nuclei, Katana in follow-up partial recon runs) can pick it
up, owned by its Subdomain or, failing that, by the Service it was served from.

Properties written on each Vulnerability:
    id                       deterministic hash (hostname+ip+port+layer)
    user_id, project_id      tenant isolation
    source                   "vhost_sni_enum"
    type                     "hidden_vhost" | "hidden_sni_route" | "host_header_bypass"
    name                     human-readable
    severity                 high | medium | low | info
    description              short summary
    hostname                 the hidden vhost FQDN
    ip                       target IP that hosts the vhost
    port                     target port
    scheme                   http | https
    layer                    "L7" | "L4" | "both"
    baseline_status          status code returned by raw IP request
    baseline_size            body size returned by raw IP request
    observed_status          status code returned with vhost lie applied
    observed_size            body size returned with vhost lie applied
    size_delta               observed_size - baseline_size
    internal_pattern_match   matched internal-keyword (e.g. "admin"), or None
    first_seen, last_seen    ISO timestamps

Properties written on the Subdomain for an in-scope hidden vhost:
    vhost_tested, vhost_hidden, vhost_routing_layer, vhost_status_code,
    vhost_size_delta, sni_routed, vhost_tested_at

Properties enriched on existing IP nodes:
    vhost_sni_tested, vhost_baseline_status, vhost_baseline_size,
    hosts_hidden_vhosts, hidden_vhost_count, is_reverse_proxy
"""

from __future__ import annotations

from datetime import datetime, timezone


class VhostSniMixin:
    def update_graph_from_vhost_sni(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        """Persist VHost/SNI findings as Vulnerability nodes + enrich IP/Subdomain."""
        stats = {
            "vulnerabilities_created": 0,
            "subdomains_enriched": 0,
            "ips_enriched": 0,
            "baseurls_created": 0,
            "relationships_created": 0,
            "stale_dns_edges_removed": 0,
            "errors": [],
        }

        vhost_data = recon_data.get("vhost_sni") or {}
        findings = vhost_data.get("findings") or []
        by_ip = vhost_data.get("by_ip") or {}
        discovered_baseurls = vhost_data.get("discovered_baseurls") or []

        if not findings and not by_ip and not discovered_baseurls:
            return stats

        target_domain = (
            recon_data.get("domain")
            or recon_data.get("metadata", {}).get("target", "")
            or ""
        ).strip().lower()

        # Which address each discovered_baseurls entry was served from; the URL
        # carries its own port but no IP, and section 3 needs one to reach the
        # Service node.
        finding_ip_by_host: dict = {}
        for f in findings:
            host_key = (f.get("hostname") or "").strip().lower()
            if host_key and f.get("ip") and host_key not in finding_ip_by_host:
                finding_ip_by_host[host_key] = f.get("ip")

        with self.driver.session() as session:
            # ----------------------------------------------------------
            # 1. IP-level enrichment (baseline + reverse-proxy flag)
            # ----------------------------------------------------------
            for ip_addr, ip_info in by_ip.items():
                try:
                    baseline = ip_info.get("baseline") or {}
                    ip_props = {
                        "vhost_sni_tested": True,
                        "vhost_baseline_status": baseline.get("status"),
                        "vhost_baseline_size": baseline.get("size"),
                        "vhost_candidates_tested": int(ip_info.get("candidates_tested") or 0),
                        "vhost_ports_tested": int(ip_info.get("ports_tested") or 0),
                        "hosts_hidden_vhosts": bool(ip_info.get("hosts_hidden_vhosts")),
                        "hidden_vhost_count": int(ip_info.get("anomaly_count") or 0),
                        "is_reverse_proxy": bool(ip_info.get("is_reverse_proxy")),
                        "is_permissive_frontend": bool(ip_info.get("is_permissive_frontend")),
                        "vhost_sni_suppressed_by_control": int(ip_info.get("suppressed_by_control") or 0),
                        "vhost_sni_tested_at": datetime.now(timezone.utc).isoformat(),
                    }
                    ip_props = {k: v for k, v in ip_props.items() if v is not None}

                    res = session.run(
                        """
                        MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                        SET i += $props
                        RETURN count(i) AS matched
                        """,
                        addr=ip_addr, uid=user_id, pid=project_id, props=ip_props,
                    )
                    if res.single()["matched"] > 0:
                        stats["ips_enriched"] += 1
                except Exception as e:
                    stats["errors"].append(f"vhost_sni IP {ip_addr} enrichment failed: {e}")

            # ----------------------------------------------------------
            # 2. Per-finding Vulnerability nodes + existing Subdomain enrichment
            # ----------------------------------------------------------
            for finding in findings:
                try:
                    vuln_id = finding.get("id")
                    hostname = (finding.get("hostname") or "").strip().lower()
                    ip_addr = finding.get("ip")
                    port = finding.get("port")
                    layer = finding.get("layer") or "L7"
                    severity = finding.get("severity") or "info"
                    detected_at = finding.get("discovered_at") or datetime.now(timezone.utc).isoformat()

                    if not vuln_id or not hostname:
                        continue

                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "vhost_sni_enum",
                        "type": finding.get("type") or "hidden_vhost",
                        "name": finding.get("name") or f"Hidden Virtual Host: {hostname}",
                        "severity": severity,
                        "description": finding.get("description") or "",
                        "hostname": hostname,
                        "host": hostname,
                        "ip": ip_addr,
                        "port": port,
                        "scheme": finding.get("scheme") or "https",
                        "layer": layer,
                        "baseline_status": finding.get("baseline_status"),
                        "baseline_size": finding.get("baseline_size"),
                        "observed_status": finding.get("observed_status"),
                        "observed_size": finding.get("observed_size"),
                        "size_delta": finding.get("size_delta"),
                        "internal_pattern_match": finding.get("internal_pattern_match"),
                        "matched_at": _build_url(hostname, port, finding.get("scheme") or "https"),
                        "is_dast_finding": False,
                        "last_seen": detected_at,
                    }
                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id, user_id: $uid,
                                                project_id: $pid})
                        ON CREATE SET v.first_seen = $detected_at
                        SET v += $props,
                            v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props, detected_at=detected_at,
                        uid=user_id, pid=project_id,
                    )
                    stats["vulnerabilities_created"] += 1

                    # A hidden vhost proves routing, not DNS: the candidate may
                    # exist in no public zone at all, and that is exactly the
                    # finding worth keeping. An in-scope name therefore still
                    # gets its Subdomain so the finding stays reachable from the
                    # graph, flagged has_dns_records=false until a resolver says
                    # otherwise. An out-of-scope name (a co-hosted third party)
                    # hangs off the IP that served it instead.
                    sub_props = {
                        "vhost_tested": True,
                        "vhost_hidden": True,
                        "vhost_routing_layer": layer,
                        "vhost_status_code": finding.get("observed_status"),
                        "vhost_size_delta": finding.get("size_delta"),
                        "sni_routed": layer in ("L4", "both"),
                        "vhost_tested_at": detected_at,
                    }
                    sub_props = {k: v for k, v in sub_props.items() if v is not None}

                    is_child = _is_child_of(hostname, target_domain)

                    if is_child:
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $hostname, user_id: $uid,
                                                project_id: $pid})
                            ON CREATE SET s.source = 'vhost_sni_enum',
                                          s.has_dns_records = false,
                                          s.created_at = datetime()
                            SET s += $sprops,
                                s.updated_at = datetime()
                            WITH s
                            MATCH (v:Vulnerability {id: $id, user_id: $uid,
                                                    project_id: $pid})
                            MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            """,
                            hostname=hostname, uid=user_id, pid=project_id,
                            id=vuln_id, sprops=sub_props,
                        )
                        stats["subdomains_enriched"] += 1
                        stats["relationships_created"] += 1
                    else:
                        res_sub = session.run(
                            """
                            OPTIONAL MATCH (s:Subdomain {
                                name: $hostname, user_id: $uid, project_id: $pid
                            })
                            WITH s
                            MATCH (v:Vulnerability {
                                id: $id, user_id: $uid, project_id: $pid
                            })
                            FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
                                SET s += $sprops,
                                    s.updated_at = datetime()
                                MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            )
                            RETURN count(s) AS matched
                            """,
                            hostname=hostname, uid=user_id, pid=project_id,
                            id=vuln_id, sprops=sub_props,
                        )
                        if res_sub.single()["matched"] > 0:
                            stats["subdomains_enriched"] += 1
                            stats["relationships_created"] += 1
                        elif ip_addr:
                            res_anchor = session.run(
                                """
                                MATCH (i:IP {address: $addr, user_id: $uid,
                                             project_id: $pid})
                                MATCH (v:Vulnerability {id: $id, user_id: $uid,
                                                        project_id: $pid})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(i) AS matched
                                """,
                                addr=ip_addr, uid=user_id, pid=project_id, id=vuln_id,
                            )
                            if res_anchor.single()["matched"] > 0:
                                stats["relationships_created"] += 1

                    if is_child:
                        res_d = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (s:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:BELONGS_TO]->(d)
                            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                            RETURN count(d) AS matched
                            """,
                            domain=target_domain, hostname=hostname,
                            uid=user_id, pid=project_id,
                        )
                        if res_d.single()["matched"] > 0:
                            stats["relationships_created"] += 2

                    # No RESOLVES_TO: answering for a Host header says nothing
                    # about what a resolver would return, and behind a shared
                    # proxy it is routinely false.
                    #
                    # Releases before this wrote one anyway, so drop it for the
                    # pair in hand. record_type means a DNS writer corroborated
                    # the edge and it stays. A resolution only a property-less
                    # writer ever recorded is indistinguishable from ours and is
                    # removed here, then rewritten by the next DNS pass.
                    if ip_addr:
                        res_stale = session.run(
                            """
                            MATCH (s:Subdomain {name: $hostname, user_id: $uid,
                                                project_id: $pid})
                                  -[r:RESOLVES_TO]->
                                  (i:IP {address: $addr, user_id: $uid,
                                         project_id: $pid})
                            WHERE r.discovered_via = 'vhost_sni_enum'
                              AND r.record_type IS NULL
                            DELETE r
                            RETURN count(r) AS removed
                            """,
                            hostname=hostname, addr=ip_addr,
                            uid=user_id, pid=project_id,
                        )
                        stats["stale_dns_edges_removed"] += res_stale.single()["removed"]

                    # For host_header_bypass (L7 vs L4 disagreement) the IP is
                    # also a vulnerable surface — attach the same Vulnerability
                    # to the IP node so it surfaces in IP-level dashboards.
                    if finding.get("type") == "host_header_bypass" and ip_addr:
                        session.run(
                            """
                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            """,
                            addr=ip_addr, uid=user_id, pid=project_id, id=vuln_id,
                        )
                        stats["relationships_created"] += 1

                    # Attach to Domain too, when the hostname IS the apex.
                    if target_domain and hostname == target_domain:
                        session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
                            MERGE (d)-[:HAS_VULNERABILITY]->(v)
                            """,
                            domain=target_domain, uid=user_id, pid=project_id, id=vuln_id,
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"vhost_sni finding {finding.get('id', '?')} failed: {e}")

            # ----------------------------------------------------------
            # 3. BaseURLs for newly discovered hidden vhosts
            # ----------------------------------------------------------
            for url in discovered_baseurls:
                try:
                    hostname = _extract_hostname(url)
                    if not hostname:
                        continue
                    # Same rule as the findings above: an in-scope host owns its
                    # URL even when this run saw no finding for it, so the URL
                    # never lands in the graph with nobody pointing at it.
                    if _is_child_of(hostname, target_domain):
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $host, user_id: $uid,
                                                project_id: $pid})
                            ON CREATE SET s.source = 'vhost_sni_enum',
                                          s.has_dns_records = false,
                                          s.created_at = datetime()
                            SET s.updated_at = datetime()
                            """,
                            host=hostname, uid=user_id, pid=project_id,
                        )

                    res = session.run(
                        """
                        MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                        ON CREATE SET b.discovery_source = 'vhost_sni_enum',
                                      b.created_at = datetime(),
                                      b.scheme = $scheme,
                                      b.host = $host,
                                      b.port = $port
                        SET b.updated_at = datetime()
                        WITH b
                        OPTIONAL MATCH (s:Subdomain {
                            name: $host, user_id: $uid, project_id: $pid
                        })
                        FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
                            SET s.updated_at = datetime()
                            MERGE (s)-[:HAS_BASE_URL]->(b)
                        )
                        RETURN count(b) AS created, count(s) AS linked
                        """,
                        url=url, uid=user_id, pid=project_id,
                        scheme=_scheme(url), host=hostname, port=_port(url),
                    )
                    rec = res.single()
                    if rec["created"] > 0:
                        stats["baseurls_created"] += 1
                    if rec["linked"] > 0:
                        stats["relationships_created"] += 1
                    elif hostname in finding_ip_by_host:
                        # No Subdomain owns this URL (an out-of-scope vhost), so
                        # hang it off the service that served it rather than
                        # leaving it unreachable. The port has to come from the
                        # URL: a host found on several ports yields one BaseURL
                        # each, and they do not share a Service.
                        res_svc = session.run(
                            """
                            MATCH (svc:Service {ip_address: $addr, port_number: $port,
                                                user_id: $uid, project_id: $pid})
                            MATCH (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                            MERGE (svc)-[:SERVES_URL]->(b)
                            RETURN count(svc) AS matched
                            """,
                            addr=finding_ip_by_host[hostname], port=_port(url), url=url,
                            uid=user_id, pid=project_id,
                        )
                        stats["relationships_created"] += res_svc.single()["matched"]
                except Exception as e:
                    stats["errors"].append(f"vhost_sni baseurl {url} failed: {e}")

        if stats["vulnerabilities_created"] > 0 or stats["ips_enriched"] > 0:
            print(
                f"[+][graph-db] vhost_sni: {stats['vulnerabilities_created']} Vulnerability node(s), "
                f"{stats['subdomains_enriched']} Subdomain enriched, "
                f"{stats['ips_enriched']} IP enriched, "
                f"{stats['baseurls_created']} BaseURL created, "
                f"{stats['relationships_created']} relationship(s), "
                f"{stats['stale_dns_edges_removed']} stale DNS edge(s) removed"
            )
        if stats["errors"]:
            print(f"[!][graph-db] vhost_sni: {len(stats['errors'])} error(s) during graph update")

        return stats


# =============================================================================
# Helpers
# =============================================================================
def _build_url(hostname: str, port, scheme: str) -> str:
    if not hostname:
        return ""
    try:
        port_i = int(port) if port is not None else 0
    except (TypeError, ValueError):
        port_i = 0
    if (scheme == "https" and port_i == 443) or (scheme == "http" and port_i == 80) or port_i == 0:
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port_i}"


def _is_child_of(hostname: str, target_domain: str) -> bool:
    """True only for a real child of the engagement's domain. A bare endswith
    would also claim 'notexample.com' as part of 'example.com'."""
    if not hostname or not target_domain:
        return False
    return hostname.endswith("." + target_domain)


def _extract_hostname(url: str) -> str:
    if not url:
        return ""
    after_scheme = url.split("://", 1)[-1]
    host_part = after_scheme.split("/", 1)[0]
    return host_part.split(":", 1)[0].lower()


def _scheme(url: str) -> str:
    if "://" in url:
        return url.split("://", 1)[0].lower()
    return "https"


def _port(url: str) -> int:
    after_scheme = url.split("://", 1)[-1]
    host_part = after_scheme.split("/", 1)[0]
    if ":" in host_part:
        try:
            return int(host_part.split(":", 1)[1])
        except ValueError:
            pass
    return 443 if url.startswith("https://") else 80
