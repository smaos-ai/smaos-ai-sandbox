system "smaos_governance" {
  version = "1.1.0-production"
  egress_mode = "zero_egress"
  enforcement = "fail_closed"
}

tcb_enforcement_plane "strict" {
  jcs_digest_matching = true
  sqlite_nonce_ledger = true
  wire_observer_deterministic = true
  require_merkle_proof = true
  bpf_lsm_drop = true
}

advisory_enrichment_plane "diagnostic" {
  allow_gliner2_autoextractor = true
  allow_clm_offline_rank = true
  # INVARIANT: Models cannot upgrade transport dispositions
  override_wire_state = false
}

agent "payment_agent" {
  intent_lock_required = true
  max_transaction_value = 1000000.00
  allowed_currencies = ["EUR", "USD"]
  collision_avoidance = "foremerge_strict"
  disposition_fail_closed = "QUARANTINED_UNCONFIRMED"
}

network_boundary "local_mesh" {
  allowed_ports = [8079, 8080, 8081]
  drop_icmp = true
}

isolation "sqlite_wal" {
  cow_branching = true
  rollback_on_deny = true
  synchronous = "NORMAL"
  journal_mode = "WAL"
}

scitt_policy "eu_ai_act_art12" {
  profile = "draft-ietf-scitt-architecture-04"
  allowed_algs = ["EdDSA", "ES256"]
}
