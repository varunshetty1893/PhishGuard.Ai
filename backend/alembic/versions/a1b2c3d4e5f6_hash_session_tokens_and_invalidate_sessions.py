"""hash session tokens and invalidate existing sessions

Revision ID: a1b2c3d4e5f6
Revises: 9ddc59dc1b66
Create Date: 2026-11-01 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '9ddc59dc1b66'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Invalidates all legacy plaintext session tokens in user_sessions
    as the system transitions to storing HMAC-SHA256 hashed session tokens at rest.
    """
    op.execute("DELETE FROM user_sessions;")


def downgrade() -> None:
    """Downgrade schema."""
    pass

