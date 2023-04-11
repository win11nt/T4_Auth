# -*- coding: utf-8 -*-
{
    "name": "T4 Auth",
    "summary": """Override Auth SIgnup""",
    "description": """
        Tối thui luôn, đen thùi lùi.
    """,
    "author": "T4Tek Team",
    "website": "https://t4tek.co/",
    "category": "T4/Authentication",
    "version": "16.0.1.0.0",
    "depends": ["t4", "auth_signup"],
    "data": [
        "data/mail_templates.xml",
        "security/sign_up.xml",
        "security/ir.model.access.csv",
        "views/auth_templates.xml",
        "views/signup_templates.xml",
        "views/user_templates.xml",
        "wizard/t4_auth_email_views.xml",
    ],
    "assets": {
        "web.assets_frontend": [
            "t4_auth/static/src/js/**/*",
        ],
         "web.assets_frontend_css": [
            "t4_auth/static/src/css/input.css"
        ]
    },
    "license": "LGPL-3",
}
