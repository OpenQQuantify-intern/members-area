"""Server-side form validation; Flask-WTF supplies CSRF protection."""

from email_validator import EmailNotValidError, validate_email
from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, HiddenField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, InputRequired, Length, Regexp, ValidationError


def normalize_email(value):
    return value.strip().lower() if value else ""


def valid_email(form, field):
    try:
        result = validate_email(
            field.data, check_deliverability=False, allow_smtputf8=False,
        )
    except EmailNotValidError as error:
        raise ValidationError("Enter a valid email address.") from error
    # One canonical ASCII value, including IDNA domains, for signup and login.
    field.data = result.ascii_email.lower()


class RegistrationForm(FlaskForm):
    email = EmailField(
        "Email address", filters=[normalize_email],
        validators=[InputRequired(), Length(max=254), valid_email],
    )
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(
            min=15, max=128, message="Use between 15 and 128 characters. A passphrase works well.",
        )],
    )
    confirm_password = PasswordField(
        "Confirm password", validators=[InputRequired(), EqualTo(
            "password", message="The passwords must match.",
        )],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = EmailField(
        "Email address", filters=[normalize_email],
        validators=[InputRequired(), Length(max=254), valid_email],
    )
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(max=128)],
    )
    submit = SubmitField("Log in")


class ChangeEmailForm(FlaskForm):
    new_email = EmailField(
        "New email address", filters=[normalize_email],
        validators=[InputRequired(), Length(max=254), valid_email],
    )
    current_password = PasswordField(
        "Current password", id="email-current-password",
        validators=[InputRequired(), Length(max=128)],
    )
    submit = SubmitField("Update email")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current password", id="password-current-password",
        validators=[InputRequired(), Length(max=128)],
    )
    new_password = PasswordField(
        "New password", validators=[InputRequired(), Length(
            min=15, max=128, message="Use between 15 and 128 characters. A passphrase works well.",
        )],
    )
    confirm_password = PasswordField(
        "Confirm new password", id="password-confirm-password",
        validators=[InputRequired(), EqualTo("new_password", message="The passwords must match.")],
    )
    submit = SubmitField("Update password")


class DeleteAccountForm(FlaskForm):
    current_password = PasswordField(
        "Current password", id="delete-current-password",
        validators=[InputRequired(), Length(max=128)],
    )
    confirm_delete = BooleanField(
        "I understand that my account will be permanently deleted.",
        validators=[DataRequired(message="Confirm that you want to permanently delete your account.")],
    )
    submit = SubmitField("Delete my account")


class ForgotPasswordForm(FlaskForm):
    email = EmailField(
        "Email address", filters=[normalize_email],
        validators=[InputRequired(), Length(max=254), valid_email],
    )
    submit = SubmitField("Send reset link")


class ResetPasswordForm(FlaskForm):
    token = HiddenField(validators=[InputRequired(), Regexp(r"^[A-Za-z0-9_-]{43}$")])
    new_password = PasswordField(
        "New password", validators=[InputRequired(), Length(
            min=15, max=128, message="Use between 15 and 128 characters. A passphrase works well.",
        )],
    )
    confirm_password = PasswordField(
        "Confirm new password", validators=[InputRequired(), EqualTo(
            "new_password", message="The passwords must match.",
        )],
    )
    submit = SubmitField("Reset password")
