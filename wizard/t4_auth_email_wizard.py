from odoo import fields, models


class T4AuthEmail(models.TransientModel):
    _name = "t4.auth.email.wizard"
    _description = "Verified email"

    user_id = fields.Many2one("res.users", string="User")
    verify_code = fields.Char("Verify Code")
