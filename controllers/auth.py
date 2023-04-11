# -*- coding: utf-8 -*-
import logging

import werkzeug  # type: ignore
from werkzeug.urls import url_encode  # type: ignore

from odoo import _, http
from odoo.addons.auth_signup.controllers import main
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.addons.web.controllers.home import SIGN_UP_REQUEST_PARAMS
from odoo.exceptions import UserError
from odoo.http import request

_logger = logging.getLogger(__name__)


class T4Signup(main.AuthSignupHome):
    def prepare_partner(self, name, email):
        data = {
            "name": name,
            "email": email,
        }

        partner = http.request.env["res.partner"].sudo().create(data)
        return partner

    def prepare_email_from_s_token(self, qcontext):
        token = qcontext.get("s_token")
        T4Token = http.request.env["t4.auth.token"]
        t = T4Token.sudo().search([("token", "=", token)], limit=1)
        if not t:
            qcontext["error"] = "Invalid token"
        elif not t.valid:
            qcontext["error"] = "Token Expiration"
        else:
            qcontext["email"] = t.email
        return qcontext

    def cleanup_s_token(self, qcontext):
        s_token = qcontext.pop("s_token")
        http.request.env["t4.auth.token"].search(
            [("token", "=", s_token)]
        ).sudo().unlink()

    # SIGNUP PROCESS
    @http.route(
        "/web/signup/process", type="http", auth="public", website=True, sitemap=False
    )
    def web_auth_signup(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()

        _logger.info(f"T4: Qcontext {qcontext}")

        if (
            not qcontext.get("token")
            and not qcontext.get("s_token")
            # and not qcontext.get("signup_enabled")
        ):
            raise werkzeug.exceptions.NotFound()

        if qcontext.get("s_token"):
            qcontext = self.prepare_email_from_s_token(qcontext)

        if "error" not in qcontext and request.httprequest.method == "POST":
            try:
                if e := qcontext.get("email", "").strip():
                    partner = self.prepare_partner(qcontext.get("name", ""), e)
                    qcontext["partner_id"] = partner.id

                if qcontext.get("s_token"):
                    self.cleanup_s_token(qcontext)

                self.do_signup(qcontext)

                # Send an account creation confirmation email
                if qcontext.get("token"):
                    User = request.env["res.users"]
                    user_sudo = User.sudo().search(
                        User._get_login_domain(qcontext.get("login")),
                        order=User._get_login_order(),
                        limit=1,
                    )
                    template = request.env.ref(
                        "auth_signup.mail_template_user_signup_account_created",
                        raise_if_not_found=False,
                    )
                    if user_sudo and template:
                        template.sudo().send_mail(user_sudo.id, force_send=True)
                return self.web_login(*args, **kw)
            except UserError as e:
                qcontext["error"] = e.args[0]
            except (SignupError, AssertionError) as e:
                if (
                    request.env["res.users"]
                    .sudo()
                    .search([("login", "=", qcontext.get("login"))])
                ):
                    qcontext["error"] = _(
                        "Another user is already registered using this email address."
                    )
                else:
                    _logger.error("%s", e)
                    qcontext["error"] = _("Could not create a new account.")

        elif "signup_email" in qcontext:
            user = (
                request.env["res.users"]
                .sudo()
                .search(
                    [
                        ("email", "=", qcontext.get("signup_email")),
                        ("state", "!=", "new"),
                    ],
                    limit=1,
                )
            )
            if user:
                return request.redirect(
                    "/web/login?%s"
                    % url_encode({"login": user.login, "redirect": "/web"})
                )

        response = request.render("auth_signup.signup", qcontext)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        return response

    # SIGNUP
    @http.route("/web/signup", type="http", auth="public", website=True, sitemap=False)
    def t4_web_signup(self, *args, **kw):
        qcontext = {
            k: v for (k, v) in request.params.items() if k in SIGN_UP_REQUEST_PARAMS
        }
        # TODO: Handling logic here
        if request.httprequest.method == "POST":
            if email := qcontext.get("email", "").strip():
                is_exists = bool(
                    request.env["res.users"]
                    .sudo()
                    .search_count([("email", "=", email)])
                )
                if not is_exists:
                    request.env["t4.auth.token"].sudo().send_register_link(email)
                    qcontext["message"] = _(
                        "Registration instructions sent to your email"
                    )
                else:
                    qcontext["error"] = _("Already exists")
            else:
                qcontext["error"] = _("Please input email")

        response = request.render("t4_auth.signup", qcontext)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        return response

    def _prepare_signup_values(self, qcontext):
        values = super()._prepare_signup_values(qcontext)
        values["email"] = qcontext.get("email", "")

        return values

    def get_auth_signup_qcontext(self):
        qcontext = super().get_auth_signup_qcontext()
        if s_token := request.params.get("s_token", ""):
            qcontext.update({"s_token": s_token})

        if login := qcontext.get("login"):
            u = http.request.env["res.users"].sudo().search([("login", "=", login)])
            if u.email:
                qcontext["email"] = u.email

        return qcontext

    # RESET PASSWORD
    @http.route()
    def web_auth_reset_password(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()
        _logger.info(f"t4: Qcontext {qcontext}")

        if not qcontext.get("token") and not qcontext.get("reset_password_enabled"):
            raise werkzeug.exceptions.NotFound()

        if "error" not in qcontext and request.httprequest.method == "POST":
            try:
                if qcontext.get("token"):
                    self.do_signup(qcontext)
                    return self.web_login(*args, **kw)
                else:
                    email = qcontext.get("email")
                    assert email, _("No email.")
                    # _logger.info(
                    #     "Password reset attempt for <%s> by user <%s> from %s",
                    #     login,
                    #     request.env.user.login,
                    #     request.httprequest.remote_addr,
                    # )
                if login := qcontext.get("login"):
                    user = (
                        request.env["res.users"]
                        .sudo()
                        .search([("email", "=", email), ("login", "=", login)])
                    )
                    if user:
                        request.env["res.users"].sudo().reset_password(user.login)
                    else:
                        qcontext["error"] = "Account not found"
                else:
                    users = (
                        request.env["res.users"].sudo().search([("email", "=", email)])
                    )
                    if users:
                        for user in users:
                            request.env["res.users"].sudo().reset_password(user.login)
                            qcontext["message"] = _(
                                "Password reset instructions sent to your email"
                            )
                    else:
                        qcontext["error"] = "Account not found"

            except UserError as e:
                qcontext["error"] = e.args[0]
            except SignupError:
                qcontext["error"] = _("Could not reset your password")
                _logger.exception("error when resetting password")
            except Exception as e:
                qcontext["error"] = str(e)

        elif "signup_email" in qcontext:
            user = (
                request.env["res.users"]
                .sudo()
                .search(
                    [
                        ("email", "=", qcontext.get("signup_email")),
                        ("state", "!=", "new"),
                    ],
                    limit=1,
                )
            )
            if user:
                return request.redirect(
                    "/web/login?%s"
                    % url_encode({"login": user.login, "redirect": "/web"})
                )

        response = request.render("t4_auth.reset_password", qcontext)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        return response
