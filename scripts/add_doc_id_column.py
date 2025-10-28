"""Script de migración ligero para añadir la columna `doc_id` a la tabla `users`.

- Lee `DATABASE_URL` desde variables de entorno (.env si existe)
- Para MySQL intentará ALTER TABLE ADD COLUMN, crear índice único y rellenar doc_id para filas existentes
- Para SQLite hará ALTER TABLE compatible (nota: SQLite permite ADD COLUMN simple)

USO:
  python scripts\add_doc_id_column.py

Advertencia: prueba primero en una copia de la BD o asegúrate de tener backup.
"""
import os
from urllib.parse import urlparse
from dotenv import load_dotenv
import sqlalchemy as sa

load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError('Falta DATABASE_URL en entorno')

engine = sa.create_engine(DATABASE_URL)
conn = engine.connect()

inspector = sa.inspect(engine)

if 'users' not in inspector.get_table_names():
    print('No existe la tabla users, saliendo')
    conn.close()
    raise SystemExit(1)

cols = [c['name'] for c in inspector.get_columns('users')]
if 'doc_id' in cols:
    print('La columna doc_id ya existe. Nada que hacer.')
    conn.close()
    raise SystemExit(0)

# Agregar columna según motor
drivername = urlparse(DATABASE_URL).scheme
print('Driver detected:', drivername)

try:
    if 'mysql' in drivername:
        # ALTER TABLE para MySQL
        conn.execute(sa.text("ALTER TABLE users ADD COLUMN doc_id VARCHAR(50) NOT NULL"))
        # rellenar doc_id con valores generados para filas existentes
        conn.execute(sa.text("UPDATE users SET doc_id = CONCAT('doc_', id) WHERE doc_id IS NULL OR doc_id = ''"))
        # crear índice único
        conn.execute(sa.text("ALTER TABLE users ADD UNIQUE INDEX ux_users_doc_id (doc_id)"))
        print('Columna doc_id añadida y poblada (MySQL).')
    elif 'sqlite' in drivername:
        conn.execute(sa.text("ALTER TABLE users ADD COLUMN doc_id VARCHAR(50) DEFAULT '' NOT NULL"))
        conn.execute(sa.text("UPDATE users SET doc_id = 'doc_' || id WHERE doc_id IS NULL OR doc_id = ''"))
        print('Columna doc_id añadida y poblada (SQLite).')
    else:
        # intento genérico
        conn.execute(sa.text("ALTER TABLE users ADD COLUMN doc_id VARCHAR(50)"))
        conn.execute(sa.text("UPDATE users SET doc_id = 'doc_' || id WHERE doc_id IS NULL OR doc_id = ''"))
        print('Columna doc_id añadida y poblada (generic).')
finally:
    conn.close()

print('Listo. Revisa la tabla users.')
