"""expand column lengths for predicted_class, algorithm, and user_agent

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-11-02 19:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('scan_history') as batch_op:
        batch_op.alter_column('predicted_class', existing_type=sa.String(20), type_=sa.String(100), existing_nullable=False)

    with op.batch_alter_table('model_metadata') as batch_op:
        batch_op.alter_column('algorithm', existing_type=sa.String(100), type_=sa.String(255), existing_nullable=False)

    with op.batch_alter_table('user_sessions') as batch_op:
        batch_op.alter_column('user_agent', existing_type=sa.String(255), type_=sa.String(500), existing_nullable=True)


def downgrade() -> None:
    with op.batch_alter_table('scan_history') as batch_op:
        batch_op.alter_column('predicted_class', existing_type=sa.String(100), type_=sa.String(20), existing_nullable=False)

    with op.batch_alter_table('model_metadata') as batch_op:
        batch_op.alter_column('algorithm', existing_type=sa.String(255), type_=sa.String(100), existing_nullable=False)

    with op.batch_alter_table('user_sessions') as batch_op:
        batch_op.alter_column('user_agent', existing_type=sa.String(500), type_=sa.String(255), existing_nullable=True)
