-- atlas:txmode file

-- Renaming enum labels preserves existing task rows and the enum sort order.
ALTER TYPE task_mode RENAME VALUE 'MANUAL' TO 'MANUAL_ONLY';
ALTER TYPE task_mode RENAME VALUE 'AUTONOMOUS_PASSIVE' TO 'AI_AUTONOMOUS_PASSIVE';
ALTER TYPE task_mode ADD VALUE 'AI_PROPOSED_HITL_GATED';

-- UUID casts must succeed for every engagement. If a legacy ID cannot be
-- represented, roll back the revision rather than rewrite signed JSON or hashes.
ALTER TABLE immutable_audit_log DROP COLUMN engagement_id;
ALTER TABLE asset_edges
    DROP CONSTRAINT asset_edges_engagement_id_fkey,
    DROP CONSTRAINT asset_edges_engagement_id_src_node_fkey,
    DROP CONSTRAINT asset_edges_engagement_id_dst_node_fkey,
    DROP CONSTRAINT asset_edges_engagement_id_proven_by_finding_fkey;
ALTER TABLE asset_nodes DROP CONSTRAINT asset_nodes_engagement_id_fkey;
ALTER TABLE findings DROP CONSTRAINT findings_engagement_id_fkey;
ALTER TABLE workflow_tasks DROP CONSTRAINT workflow_tasks_engagement_id_fkey;
ALTER TABLE validation_plans DROP CONSTRAINT validation_plans_engagement_id_fkey;
ALTER TABLE attack_chains DROP CONSTRAINT attack_chains_engagement_id_fkey;

ALTER TABLE engagements
    DROP CONSTRAINT engagements_id_check,
    DROP CONSTRAINT engagements_check,
    ALTER COLUMN id TYPE uuid USING id::uuid;
ALTER TABLE engagements ADD CHECK (roe_manifest IS NULL OR (
    jsonb_typeof(roe_manifest -> 'engagement_id') = 'string'
    AND (roe_manifest ->> 'engagement_id')::uuid = id
) IS TRUE);

ALTER TABLE asset_nodes ALTER COLUMN engagement_id TYPE uuid USING engagement_id::uuid;
ALTER TABLE findings ALTER COLUMN engagement_id TYPE uuid USING engagement_id::uuid;
ALTER TABLE asset_edges ALTER COLUMN engagement_id TYPE uuid USING engagement_id::uuid;
ALTER TABLE workflow_tasks ALTER COLUMN engagement_id TYPE uuid USING engagement_id::uuid;
ALTER TABLE validation_plans ALTER COLUMN engagement_id TYPE uuid USING engagement_id::uuid;
ALTER TABLE attack_chains ALTER COLUMN engagement_id TYPE uuid USING engagement_id::uuid;

ALTER TABLE asset_nodes ADD FOREIGN KEY (engagement_id) REFERENCES engagements(id);
ALTER TABLE findings ADD FOREIGN KEY (engagement_id) REFERENCES engagements(id);
ALTER TABLE asset_edges
    ADD FOREIGN KEY (engagement_id) REFERENCES engagements(id),
    ADD FOREIGN KEY (engagement_id, src_node) REFERENCES asset_nodes(engagement_id, id),
    ADD FOREIGN KEY (engagement_id, dst_node) REFERENCES asset_nodes(engagement_id, id),
    ADD FOREIGN KEY (engagement_id, proven_by_finding) REFERENCES findings(engagement_id, id);
ALTER TABLE workflow_tasks ADD FOREIGN KEY (engagement_id) REFERENCES engagements(id);
ALTER TABLE validation_plans ADD FOREIGN KEY (engagement_id) REFERENCES engagements(id);
ALTER TABLE attack_chains ADD FOREIGN KEY (engagement_id) REFERENCES engagements(id);

ALTER TABLE immutable_audit_log RENAME COLUMN event TO payload;
ALTER TABLE immutable_audit_log
    RENAME CONSTRAINT immutable_audit_log_event_check TO immutable_audit_log_payload_check;
ALTER TABLE immutable_audit_log
    ADD COLUMN engagement_id uuid GENERATED ALWAYS AS ((payload->>'engagement_id')::uuid) STORED
        NOT NULL REFERENCES engagements(id);

CREATE INDEX immutable_audit_log_engagement_id_idx
    ON immutable_audit_log USING btree (engagement_id);
