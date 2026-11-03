"""Public pages, accessible without an account."""

from flask import Blueprint, render_template

bp = Blueprint("public", __name__)


@bp.get("/")
def home():
    return render_template("home.html")
