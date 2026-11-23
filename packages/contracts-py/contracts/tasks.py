"""Workflow task records."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class TaskMode(StrEnum):
    MANUAL = "MANUAL"
    AUTONOMOUS_PASSIVE = "AUTONOMOUS_PASSIVE"


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
