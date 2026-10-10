"""User submission endpoints (Stage 2)."""

import base64
import binascii
import hashlib
import re
from datetime import datetime
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from risk_radar.db.models import Brand, Submission, SubmissionType
from risk_radar.db.session import get_db

router = APIRouter(tags=["submissions"])

_HANDLE_PATTERN = re.compile(r"@[A-Za-z0-9_.]{1,50}")


def _is_http_url(value: str) -> bool:
    """Return True when the value parses as an http(s) URL with a host."""
    parts = urlsplit(value)
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def _is_image_data_uri(value: str) -> bool:
    """Return True for a non-empty base64 ``data:image/...`` URI."""
    prefix, separator, payload = value.partition(",")
    if not separator or not prefix.startswith("data:image/") or ";base64" not in prefix:
        return False
    if not payload.strip():
        return False
    try:
        base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        return False
    return True


class SubmissionCreate(BaseModel):
    """Payload used to store one piece of raw evidence."""

    submission_type: SubmissionType
    content: str = Field(min_length=1)
    source: str = Field(default="user", min_length=1, max_length=64)
    brand_id: int | None = None

    @model_validator(mode="after")
    def validate_content_for_type(self) -> "SubmissionCreate":
        """Reject content that does not match the declared submission type."""
        content = self.content
        kind = self.submission_type
        if kind == SubmissionType.URL and not _is_http_url(content):
            raise ValueError("content must be an http(s) URL")
        if kind == SubmissionType.SOCIAL_PROFILE and not (
            _is_http_url(content) or _HANDLE_PATTERN.fullmatch(content)
        ):
            raise ValueError("content must be an http(s) URL or an @handle")
        if kind == SubmissionType.SCREENSHOT and not (
            _is_http_url(content) or _is_image_data_uri(content)
        ):
            raise ValueError("content must be an http(s) image URL or a base64 data:image/... URI")
        if kind in {SubmissionType.MESSAGE, SubmissionType.APP_LISTING} and not content.strip():
            raise ValueError("content must not be blank")
        return self


class SubmissionResponse(BaseModel):
    """Stored submission returned to clients."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    submission_type: SubmissionType
    source: str
    content: str
    content_hash: str
    brand_id: int | None
    created_at: datetime


@router.post(
    "/submissions",
    response_model=SubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Store a user submission",
)
def create_submission(
    payload: SubmissionCreate, db: Annotated[Session, Depends(get_db)]
) -> Submission:
    """Persist raw evidence with its timestamp, content hash and optional brand."""
    if payload.brand_id is not None and db.get(Brand, payload.brand_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brand not found")
    submission = Submission(
        submission_type=payload.submission_type.value,
        source=payload.source,
        content=payload.content,
        content_hash=hashlib.sha256(payload.content.encode("utf-8")).hexdigest(),
        brand_id=payload.brand_id,
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    return submission


@router.get(
    "/submissions/{submission_id}",
    response_model=SubmissionResponse,
    summary="Read a stored submission",
)
def read_submission(submission_id: int, db: Annotated[Session, Depends(get_db)]) -> Submission:
    """Return one stored submission, proving it became a stored candidate."""
    submission = db.get(Submission, submission_id)
    if submission is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")
    return submission
