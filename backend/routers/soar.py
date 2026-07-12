"""SOAR containment: list active blocks and manual unblock override."""
from fastapi import APIRouter

from database import SessionLocal, SecurityRule
from actions import orchestrator

router = APIRouter()


@router.post("/unblock/{entity}")
async def unblock_entity(entity: str):
    """Manual analyst override to unblock an IP/Domain"""
    return orchestrator.trigger_unblock(entity)


@router.get("/blocked")
async def list_blocked_entities():
    """Returns a list of all currently active SOAR blocks"""
    with SessionLocal() as db:
        return db.query(SecurityRule).filter(SecurityRule.is_active == True).all()

