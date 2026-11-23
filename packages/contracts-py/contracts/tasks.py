"""Workflow task records."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class TaskMode(StrEnum):
    MANUAL_ONLY = "MANUAL_ONLY"
    AI_AUTONOMOUS_PASSIVE = "AI_AUTONOMOUS_PASSIVE"
    AI_PROPOSED_HITL_GATED = "AI_PROPOSED_HITL_GATED"


class TaskStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED_HITL = "PAUSED_HITL"
    DONE = "DONE"
    REJECTED = "REJECTED"


class WorkflowTask(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    engagement_id: str
    mode: TaskMode
    status: TaskStatus = TaskStatus.QUEUED
