system "smaos_governance" {
  version = "1.0.0"
  egress_mode = "zero_egress"
  enforcement = "fail_closed"
}

agent "payment_agent" {
  intent_lock_required = true
  max_transaction_value = 1000000.00
  allowed_currencies = ["EUR", "USD"]
  collision_avoidance = "foremerge_strict"
  disposition_fail_closed = "UNKNOWN"
}

network_boundary "local_mesh" {
  allowed_ports = [8079, 8080, 8081]
  bpf_lsm_drop = true
  drop_icmp = true
  max_ingress_rate_kbps = 10000
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
  require_merkle_proof = true
  min_tcb_svn = 4
}
