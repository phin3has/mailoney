"""Initial migration

Revision ID: 1a5b9822e49c
Revises: 
Create Date: 2025-04-08 23:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a5b9822e49c'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create smtp_sessions table
    op.create_table('smtp_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('ip_address', sa.String(length=255), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('server_name', sa.String(length=255), nullable=True),
        sa.Column('session_data', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create credentials table
    op.create_table('credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('session_id', sa.Integer(), nullable=True),
        sa.Column('auth_string', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['smtp_sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('credentials')
    op.drop_table('smtp_sessions')
