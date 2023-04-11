import logging

from odoo import _, exceptions, http
from odoo.addons.portal.controllers.portal import CustomerPortal
from odoo.http import request

_logger = logging.getLogger(__name__)

# TODO: Features: Change Email

EMAIL_CHANGE_SS_FIELDS = {"email_process_ss", "email", "email_code"}


class UserProfile(CustomerPortal):
    @http.route()
    def account(self, redirect=None, **post):
        post["email"] = request.env.user.email
        return super().account(redirect, **post)

    @http.route(
        "/my/security/email/change", auth="user", website=True, methods=["GET", "POST"]
    )
    def change_email(self, **kw):
        qcontext = self._prepare_email_ss_values()
        if request.httprequest.method == "POST":
            try:
                request.env.user._check_credentials(
                    request.params["password"], {"interactive": True}
                )
                qcontext["verified"] = True

                email = qcontext.get("email")

                # Call Send Mail Here
                request.env.user.sudo()._begin_email_change_ss(email)
                request.env.user._send_email_verified_code(email)

                qcontext.update({"email_process_ss": request.env.user.email_change_ss})

            except exceptions.AccessDenied as e:
                if e.args == exceptions.AccessDenied().args:
                    qcontext["error"] = _("Wrong password")
                else:
                    qcontext["error"] = e.args[0]  # type: ignore

        _logger.info(qcontext)
        response = request.render("t4_auth.t4_change_email", qcontext)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        return response

    @http.route(
        "/my/security/email/change/confirm",
        auth="user",
        website=True,
        methods=["POST"],
    )
    def confirm_change_email(self):
        qcontext = self._prepare_email_ss_values()
        if request.httprequest.method == "POST":
            user = request.env.user
            if email_process_ss := qcontext.get("email_process_ss"):
                if user._check_email_ss(email_process_ss):
                    code = qcontext.get("email_code")
                    try:
                        if user._check_email_verified_code(code):
                            user._confirm_change_email_ss()
                            qcontext["message"] = "Your email has been changed"
                    except exceptions.AccessDenied:
                        qcontext["error"] = "Error Invalid"
                    finally:
                        user._end_email_change_ss()
                else:
                    qcontext["error"] = "Something went wrong... please try again..."
            else:
                qcontext["error"] = "Invalid"

        response = request.render("t4_auth.t4_change_email_confirm", qcontext)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
        return response

    def _get_user_email_value(self):
        user = http.request.env.user
        data = {"email": user.email if user else ""}
        return data

    def _prepare_email_ss_values(self):
        qcontext = {
            k: v for (k, v) in request.params.items() if k in EMAIL_CHANGE_SS_FIELDS
        }
        return qcontext

    @http.route()
    def security(self, **post):
        response = super().security(**post)
        data = self._get_user_email_value()
        response.qcontext.update(data)
        return response
