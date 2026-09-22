// Phase 2 fixture: an Endpoint as the pre-fix JS recon wrote it (third-party
// host, no BaseURL owner) carrying the work a person attaches to one. The next
// JS recon run must neither delete it nor fetch it again. Tenant-keyed on
// every node; run with -P "uid => '<user id>'" -P "pid => '<project id>'".
MERGE (e:Endpoint {path: '/graphql', method: 'POST', baseurl: 'https://legacy-vendor.test',
                   user_id: $uid, project_id: $pid})
  ON CREATE SET e.source = 'js_recon', e.id = 'endpoint-legacy-lab', e.updated_at = datetime()
MERGE (p:Parameter {name: 'query', position: 'body', endpoint_path: '/graphql',
                    baseurl: 'https://legacy-vendor.test', user_id: $uid, project_id: $pid})
MERGE (e)-[:HAS_PARAMETER]->(p)
MERGE (v:Vulnerability {id: 'vuln-legacy-lab', user_id: $uid, project_id: $pid})
  ON CREATE SET v.source = 'nuclei', v.name = 'legacy lab finding', v.severity = 'low',
                v.triage_source = 'human', v.updated_at = datetime()
SET v:Muted
MERGE (v)-[:FOUND_AT]->(e)
MERGE (c:ChainFinding {id: 'chainfinding-legacy-lab', user_id: $uid, project_id: $pid})
  ON CREATE SET c.title = 'legacy lab chain finding'
MERGE (c)-[:FINDING_AFFECTS_ENDPOINT]->(e);
