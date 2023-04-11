import logging
from typing import Any

from dateutil import parser  # type: ignore

from odoo import _, api, fields, models
from odoo.exceptions import AccessDenied, UserError

from .register_token import generate_radom, now

_logger = logging.getLogger(__name__)

from .register_token import Encryptor


class ResUser(models.Model):
    _inherit = "res.users"

    email_change_ss = fields.Char("Email Change Session", copy=False, default="")
    email_change_code = fields.Char("Email Change Code", copy=False)
    email_change_pre_email = fields.Char("Prepare email", copy=False)

    def _begin_email_change_ss(self, email):
        self.ensure_one()
        for user in self:
            data = {
                "email_change_pre_email": email,
                "email_change_ss": generate_radom(64),
            }
            user.write(data)

        return True

    def _end_email_change_ss(self):
        return self.__update_session(False, email_change_pre_email="")

    def _update_email_change_ss(self):
        return self.__update_session(True)

    def _confirm_change_email_ss(self):
        user: Any
        self.ensure_one()
        for user in self:
            user.sudo().write({"email": user.email_change_pre_email})
            self.env.cr.commit()

        return True

    def _check_email_ss(self, email_ss):
        user: Any
        self.ensure_one()
        for user in self:
            return bool(user.email_change_ss == email_ss)

        return False

    def __update_session(self, update=None, **context):
        self.ensure_one()
        for user in self:
            data = {
                "email_change_ss": generate_radom(64) if update else "",
            }
            if context:
                data |= context
            user.write(data)

        return True

    def _get_email_ss(self):
        user: Any
        self.ensure_one()
        for user in self:
            if user.email_change_valid:
                return user.email_change_ss

        return False

    def _init_email_code(self):
        self.ensure_one()
        for user in self:
            code = generate_radom(6).upper()
            email_dt_code = Encryptor(code).encrypt(str(now(minutes=+5)))
            user.write({"email_change_code": email_dt_code})

            return code

    def _send_email_verified_code(self, email):
        self.ensure_one()
        template = self.env.ref(
            "t4_auth.email_change_verify_code", raise_if_not_found=False
        ).sudo()

        code = self._init_email_code()

        email_values = {
            "email_to": email,
            "email_cc": False,
            "auto_delete": True,
            "recipient_ids": [],
            "partner_ids": [],
            "scheduled_date": False,
        }
        context = {"code": code, "exp": 5}

        with self.env.cr.savepoint():
            template.with_context(**context).send_mail(
                self.id, force_send=True, raise_exception=True, email_values=email_values, email_layout_xmlid="mail.mail_notification_light"  # type: ignore
            )

        return True

    def _check_email_verified_code(self: Any, code):
        dt = now()

        if edt := Encryptor(code).decrypt(self.email_change_code):
            if dt <= parser.parse(edt):
                return True
        else:
            raise AccessDenied(_("Token invalid"))

        return False


# TODO: move ResUserMail to t4_contact_dms
class ResUserMail(models.AbstractModel):
    """support bcdn"""

    _name = "t4.users.mail.bcdn"

    def res_users(self):
        return self.env["res.users"]

    def __execute_reset_password_mail(self, user, company_mail: str):
        expiration = False
        user.mapped("partner_id").signup_prepare(
            signup_type="reset", expiration=expiration
        )

        template = False

        template = self.env.ref(
            "auth_signup.set_password_email", raise_if_not_found=False
        )

        assert template._name == "mail.template"

        email_values = {
            "email_cc": False,
            "auto_delete": True,
            "message_type": "user_notification",
            "recipient_ids": [],
            "partner_ids": [],
            "scheduled_date": False,
        }

        if user and company_mail:
            email_values["email_to"] = company_mail

            with self.env.cr.savepoint():
                template.send_mail(
                    user.id,
                    force_send=True,
                    raise_exception=True,
                    email_values=email_values,
                )
            _logger.info(
                "Password reset email sent for user <%s> to <%s>",
                user.login,
                user.email,
            )

    def _execute_set_password_mail(self, user, company_mail):
        return self.__execute_reset_password_mail(user, company_mail)

    def mass_send_invite_mail(self, users, company_mail):
        for user in users:
            self._execute_set_password_mail(user, company_mail)

        return True
