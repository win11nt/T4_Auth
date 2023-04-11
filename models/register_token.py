import logging
import secrets
import string
from base64 import urlsafe_b64decode as b64decode
from base64 import urlsafe_b64encode as b64encode
from datetime import datetime, timedelta
from random import choices
from typing import Any

import werkzeug.urls  # type: ignore
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from odoo import _, api, fields, models
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


def __derive(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return b64encode(kdf.derive(password.encode()))


def encrypt_message(message: str, password: str) -> str:
    salt = secrets.token_bytes(16)
    key = __derive(password, salt)
    token = b64encode(Fernet(key).encrypt(message.encode()))
    return b64encode(b"%b%b" % (salt, b64decode(token))).decode()


def decrypt_message(enc_message: str, password: str):
    try:
        decoded = b64decode(enc_message.encode())
        salt, cipher_text = decoded[:16], decoded[16:]
        key = __derive(password, salt)
        return Fernet(key).decrypt(cipher_text).decode()
    except InvalidToken:
        return None


class Encryptor:
    def __init__(self, password: str) -> None:
        self.__password = password

    def encrypt(self, data: str):
        if not data:
            return ""
        return encrypt_message(data, self.__password)

    def decrypt(self, enc_data: str):
        if not enc_data:
            return ""
        return decrypt_message(enc_data, self.__password)


def now(**kwargs):
    return datetime.now() + timedelta(**kwargs)


# Random Token
def generate_radom(size=32):
    return "".join(choices(string.ascii_letters + string.digits, k=size))


class TokenT4Auth(models.Model):
    _name = "t4.auth.token"

    email = fields.Char(string="email")

    token = fields.Char(copy=False, string="token", groups="base.group_erp_manager")

    expiration = fields.Datetime(copy=False, groups="base.group_erp_manager")

    url = fields.Char(compute="_compute_signup_url", string="Signup URL")

    valid = fields.Boolean(
        compute="_compute_signup_valid", string="Signup Token is Valid"
    )

    @api.depends("token", "expiration")
    def _compute_signup_valid(self):
        dt = now()
        token: Any
        token_sudo: Any
        for token, token_sudo in zip(self, self.sudo()):
            token.valid = bool(token_sudo.token) and (
                not token_sudo.expiration or dt <= token_sudo.expiration
            )

    def _compute_signup_url(self):
        t4_token: Any
        for t4_token in self:
            t4_token.url = self._get_signin_url_for_action()

    def _get_signin_url_for_action(self):
        t4_token: Any
        result = ""
        for t4_token in self:
            base_url = t4_token.get_base_url()
            query = {"db": self.env.cr.dbname, "s_token": t4_token.token}
            register_url = "/web/signup/process?%s" % (werkzeug.urls.url_encode(query))
            result = werkzeug.urls.url_join(base_url, register_url)
            _logger.info(result)
        return result

    def create_token(self, email=None):
        if not email:
            raise UserError(_("email is empty ; please provide information again"))
        data = dict()
        data["email"] = email
        data["token"] = self.prepare_token()
        data["expiration"] = now(days=+1)
        return self.create(data)

    def prepare_token(self):
        token = generate_radom()
        while self.search([("token", "=", token)]):
            token = generate_radom()
        return token

    def _clean_email_token(self, email: str):
        if email:
            for t in self.search([("email", "=", email)]):  # type: ignore
                t.unlink()

    def _send_register_link(self, email: str):
        self._clean_email_token(email)

        template = self.env.ref("t4_auth.signup_mail", raise_if_not_found=False)
        token: Any = self.create_token(email)

        email_values = {
            "email_cc": False,
            "auto_delete": True,
            "message_type": "user_notification",
            "recipient_ids": [],
            "partner_ids": [],
            "scheduled_date": False,
        }

        email_values["email_to"] = email

        with self.env.cr.savepoint():
            template.send_mail(
                token.id,
                force_send=True,
                raise_exception=True,
                email_values=email_values,
            )

        return True

    def send_register_link(self, email: str):
        return self._send_register_link(email)
