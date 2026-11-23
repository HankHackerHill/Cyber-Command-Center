CREATE TYPE engagement_state AS ENUM (
    'INIT_SCOPING', 'ROE_LOCKED', 'DISCOVERY_PASSIVE', 'ANALYTICAL_TRIAGE',
    'AWAITING_HITL_GATE', 'CONTROLLED_VALIDATION', 'EVIDENCE_VERIFICATION',
    'REMEDIATION_SYNTHESIS', 'RETEST_VERIFICATION', 'COMPLETED_ARCHIVED',
    'HALTED_KILLSWITCH'
);
CREATE TYPE actor_type AS ENUM ('HUMAN_OPERATOR', 'AI_AGENT', 'SYSTEM');
CREATE TYPE task_mode AS ENUM ('MANUAL_ONLY', 'AI_AUTONOMOUS_PASSIVE', 'AI_PROPOSED_HITL_GATED');
CREATE TYPE task_status AS ENUM ('QUEUED', 'RUNNING', 'PAUSED_HITL', 'DONE', 'REJECTED');
CREATE TYPE finding_status AS ENUM (
    'HYPOTHESIS', 'PENDING_VALIDATION', 'CONFIRMED', 'FALSE_POSITIVE', 'REMEDIATED'
);
CREATE TYPE edge_kind AS ENUM ('SECRET_REUSE', 'IAM_ASSUME', 'NET_REACH', 'K8S_RBAC');
CREATE TYPE blast_radius AS ENUM ('READ_ONLY', 'REVERSIBLE', 'DESTRUCTIVE');

CREATE TABLE engagements (
    id uuid PRIMARY KEY,
    current_state engagement_state NOT NULL DEFAULT 'INIT_SCOPING',
    roe_manifest jsonb,
    roe_signature_hash char(64) CHECK (roe_signature_hash ~ '^[0-9a-f]{64}$'),
    CHECK (roe_manifest IS NULL OR (
        jsonb_typeof(roe_manifest -> 'engagement_id') = 'string'
        AND (roe_manifest ->> 'engagement_id')::uuid = id
    ) IS TRUE)
);

CREATE TABLE asset_nodes (
    engagement_id uuid NOT NULL REFERENCES engagements (id),
    id uuid NOT NULL,
    asset_category text NOT NULL,
    canonical_identifier text NOT NULL,
    metadata jsonb NOT NULL CHECK (jsonb_typeof(metadata) = 'object'),
    discovered_by actor_type NOT NULL,
    PRIMARY KEY (engagement_id, id),
    UNIQUE (engagement_id, asset_category, canonical_identifier)
);

CREATE TABLE findings (
    engagement_id uuid NOT NULL REFERENCES engagements (id),
    id text NOT NULL,
    title text NOT NULL,
    confidence_score numeric(3,2) NOT NULL CHECK (confidence_score BETWEEN 0 AND 1),
    cvss_score numeric(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    status finding_status NOT NULL DEFAULT 'HYPOTHESIS',
    PRIMARY KEY (engagement_id, id)
);

CREATE TABLE asset_edges (
    engagement_id uuid NOT NULL REFERENCES engagements (id),
    id text NOT NULL,
    src_node uuid NOT NULL,
    dst_node uuid NOT NULL,
    edge_kind edge_kind NOT NULL,
    traversal_cost double precision NOT NULL
        CHECK (traversal_cost >= 0 AND traversal_cost < 'Infinity'::double precision),
    proven_by_finding text,
    PRIMARY KEY (engagement_id, id),
    FOREIGN KEY (engagement_id, src_node) REFERENCES asset_nodes (engagement_id, id),
    FOREIGN KEY (engagement_id, dst_node) REFERENCES asset_nodes (engagement_id, id),
    FOREIGN KEY (engagement_id, proven_by_finding) REFERENCES findings (engagement_id, id)
);

CREATE TABLE workflow_tasks (
    engagement_id uuid NOT NULL REFERENCES engagements (id),
    id text NOT NULL,
    mode task_mode NOT NULL,
    status task_status NOT NULL DEFAULT 'QUEUED',
    PRIMARY KEY (engagement_id, id)
);

-- Store an approval in the same JSON shape as Ed25519Signature.
CREATE DOMAIN ed25519_signature AS jsonb CHECK (
    VALUE IS NULL OR (
        jsonb_typeof(VALUE) = 'object'
        AND VALUE - 'signer_id' - 'signature' = '{}'::jsonb
        AND jsonb_typeof(VALUE -> 'signer_id') = 'string'
        AND VALUE ->> 'signer_id' <> ''
        AND jsonb_typeof(VALUE -> 'signature') = 'string'
        AND VALUE ->> 'signature' ~ '^[0-9a-f]{128}$'
    ) IS TRUE
);

CREATE TABLE validation_plans (
    engagement_id uuid NOT NULL REFERENCES engagements (id),
    id text NOT NULL CHECK (id <> ''),
    blast_radius blast_radius NOT NULL,
    approver_sig ed25519_signature,
    second_approver_sig ed25519_signature,
    PRIMARY KEY (engagement_id, id),
    CHECK (blast_radius <> 'DESTRUCTIVE' OR (
        approver_sig IS NOT NULL AND second_approver_sig IS NOT NULL
        AND approver_sig ->> 'signer_id' <> second_approver_sig ->> 'signer_id'
        AND approver_sig ->> 'signature' <> second_approver_sig ->> 'signature'
    ))
);

CREATE TABLE attack_chains (
    engagement_id uuid NOT NULL REFERENCES engagements (id),
    id text NOT NULL,
    path_node_ids uuid[] NOT NULL CHECK (
        array_ndims(path_node_ids) = 1 AND cardinality(path_node_ids) > 0
        AND array_position(path_node_ids, NULL) IS NULL
    ),
    PRIMARY KEY (engagement_id, id)
);

CREATE TABLE immutable_audit_log (
    seq_id bigserial PRIMARY KEY CHECK (seq_id > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    prev_record_hash char(64) NOT NULL CHECK (prev_record_hash ~ '^[0-9a-f]{64}$'),
    record_hash char(64) NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
    engagement_id uuid GENERATED ALWAYS AS ((payload->>'engagement_id')::uuid) STORED
        NOT NULL REFERENCES engagements(id)
);

CREATE INDEX immutable_audit_log_engagement_id_idx
    ON immutable_audit_log USING btree (engagement_id);

CREATE FUNCTION reject_audit_log_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'immutable_audit_log is append-only (%)', TG_OP
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_log_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON immutable_audit_log
FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_log_mutation();
