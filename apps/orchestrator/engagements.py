"""Engagement scope drafts and operator-facing contract listings."""

from hashlib import sha256
from typing import Annotated, LiteralString, TypeVar
from uuid import UUID

from contracts.findings import Finding
from contracts.plans import ValidationPlan
from contracts.roe import RoeManifest
from contracts.tasks import WorkflowTask
from fastapi import APIRouter, Depends, HTTPException
from psycopg.errors import UntranslatableCharacter
from psycopg.rows import dict_row
from pydantic import BaseModel
from pydantic_core import PydanticSerializationError

from deps import Services, services
from ledger import get_state
from state_machine import Reason, TransitionDenied, parse_engagement_id

router = APIRouter(prefix="/engagements")
Resources = Annotated[Services, Depends(services)]
RowModel = TypeVar("RowModel", bound=BaseModel)


class DraftReceipt(BaseModel):
    engagement_id: UUID
    manifest_hash: str


def _save_draft(resources: Services, manifest: RoeManifest, existing_id: UUID | None) -> DraftReceipt:
    owner = parse_engagement_id(manifest.engagement_id)
    if existing_id is not None and existing_id != owner:
        raise TransitionDenied(Reason.ENGAGEMENT_ID_MISMATCH, 422)
    # The registry hashes the frozen model's UTF-8 JSON, including signatures.
    try:
        document = manifest.model_dump_json()
    except PydanticSerializationError as exc:
        raise TransitionDenied(Reason.INVALID_MANIFEST, 422) from exc
    with resources.database.connection() as conn, conn.transaction():
        try:
            if existing_id is None:
                created = conn.execute(
                    """INSERT INTO engagements (id, roe_manifest) VALUES (%s, %s::jsonb)
                       ON CONFLICT (id) DO NOTHING""",
                    (owner, document),
                )
                if not created.rowcount:
                    raise HTTPException(409, "Engagement already exists")
            else:
                # PostgreSQL rechecks the predicate after acquiring the row lock,
                # including when a transition or stop was ahead of this update.
                updated = conn.execute(
                    """UPDATE engagements SET roe_manifest = %s::jsonb, roe_signature_hash = NULL
                       WHERE id = %s AND current_state = 'INIT_SCOPING'""",
                    (document, owner),
                )
                if not updated.rowcount:
                    get_state(conn, owner)  # Preserve 404 for an unknown engagement.
                    raise TransitionDenied(Reason.STATE_MISMATCH, 409)
        except UntranslatableCharacter as exc:
            raise TransitionDenied(Reason.INVALID_MANIFEST, 422) from exc
    return DraftReceipt(engagement_id=owner, manifest_hash=sha256(document.encode("utf-8")).hexdigest())


@router.post("", status_code=201)
def create_engagement(manifest: RoeManifest, resources: Resources) -> DraftReceipt:
    return _save_draft(resources, manifest, None)


@router.put("/{id}/roe")
def update_roe(id: UUID, manifest: RoeManifest, resources: Resources) -> DraftReceipt:
    return _save_draft(resources, manifest, id)


def _list_rows(resources: Services, engagement_id: UUID, query: LiteralString,
               model: type[RowModel]) -> list[RowModel]:
    with resources.database.connection() as conn:
        get_state(conn, engagement_id)
        with conn.cursor(row_factory=dict_row) as cursor:
            cursor.execute(query, (engagement_id,))
            return [model.model_validate(row) for row in cursor]


@router.get("/{id}/tasks")
def list_tasks(id: UUID, resources: Resources) -> list[WorkflowTask]:
    return _list_rows(resources, id, """
        SELECT id, engagement_id::text, mode, status
        FROM workflow_tasks WHERE engagement_id = %s ORDER BY id COLLATE "C"
    """, WorkflowTask)


@router.get("/{id}/findings")
def list_findings(id: UUID, resources: Resources) -> list[Finding]:
    return _list_rows(resources, id, """
        SELECT id, engagement_id::text, title, confidence_score, cvss_score, status
        FROM findings WHERE engagement_id = %s ORDER BY id COLLATE "C"
    """, Finding)


@router.get("/{id}/plans")
def list_plans(id: UUID, resources: Resources) -> list[ValidationPlan]:
    return _list_rows(resources, id, """
        SELECT id, engagement_id::text, blast_radius, approver_sig::jsonb, second_approver_sig::jsonb
        FROM validation_plans WHERE engagement_id = %s ORDER BY id COLLATE "C"
    """, ValidationPlan)
