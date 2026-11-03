"""Request-scoped SQLite connections and a non-destructive setup command."""

import sqlite3

import click
from flask import current_app, g
from flask.cli import with_appcontext


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        # SQLite requires foreign keys to be enabled on every connection.
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Create missing tables without deleting existing accounts."""
    with current_app.open_resource("schema.sql") as schema:
        get_db().executescript(schema.read().decode("utf-8"))
    click.echo("Database ready. Existing records were preserved.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
