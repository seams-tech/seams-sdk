-- Guarded D1 batches abort by colliding with this immutable singleton when a
-- preceding compare-and-swap statement changes no row.
INSERT OR IGNORE INTO router_ab_yao_versioned_json_cas_guard (guard_id) VALUES (1);
