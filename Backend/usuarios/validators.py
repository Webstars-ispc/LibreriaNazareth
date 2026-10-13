from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class RobustPasswordValidator:
    """Valida la política de contraseña segura del proyecto.

    Reglas (ver Política de Seguridad):
      - mínimo 8 caracteres
      - al menos una letra
      - al menos un dígito
      - al menos un carácter especial (no alfanumérico)
    """

    message = _(
        'La contraseña debe tener al menos 8 caracteres y combinar '
        'letras, números y al menos un carácter especial.'
    )
    special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?/"\'\\~`'

    def validate(self, password, user=None):
        if len(password) < 8:
            raise ValidationError(self.message, code='password_too_short')

        if not any(char.isalpha() for char in password):
            raise ValidationError(self.message, code='password_no_letter')

        if not any(char.isdigit() for char in password):
            raise ValidationError(self.message, code='password_no_digit')

        if not any(char in self.special_chars for char in password):
            raise ValidationError(self.message, code='password_no_special')

    def get_help_text(self):
        return _(
            'Usá al menos 8 caracteres combinando letras, números y un '
            'carácter especial (!@#$%...).'
        )
