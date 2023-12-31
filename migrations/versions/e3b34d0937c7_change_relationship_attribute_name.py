"""Change relationship attribute name

Revision ID: e3b34d0937c7
Revises: df59045a441a
Create Date: 2023-09-08 14:45:17.015168

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e3b34d0937c7'
down_revision = 'df59045a441a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        
        batch_op.create_unique_constraint(None)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('phonenumber')

    # ### end Alembic commands ###
