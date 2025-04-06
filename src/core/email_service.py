from pathlib import Path
from fastapi.templating import Jinja2Templates


class EmailTemplateManager:
    def __init__(self):
        self.template_dir = Path(__file__).parent.parent / "email_templates"
        self.templates = Jinja2Templates(directory=str(self.template_dir))

        # Configure default context
        self.default_context = {
            "image_url": "https://cyberhoot.com/wp-content/uploads/2019/12/Difference-B_T-Encryption-Decryption-1024x485.jpeg",
            "support_email": "support@edapp.com",
            "expiration_time": 2
        }

    def render_verification_email(self, context: dict) -> str:
        template_context = {**self.default_context, **context}
        return self.templates.TemplateResponse(
            "verification_email.html",
            {"request": None, **template_context}
        ).body.decode("utf-8")