import logging

from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, PermissionDenied

logger = logging.getLogger('seguridad')


def excepciones_de_seguridad(exc, context):
    """Handle de DRF que loguea eventos de seguridad (401/403) sin exponer datos sensibles."""
    response = drf_exception_handler(exc, context)

    if response is None:
        return response

    request = context.get('request')
    if request is None:
        return response

    status = response.status_code
    evento_guardable = (
        status == 403
        or status == 401
        or isinstance(exc, (AuthenticationFailed, NotAuthenticated, PermissionDenied))
    )

    if not evento_guardable:
        return response

    user = request.user
    nombre_usuario = getattr(user, 'username', None) or 'anonimo'

    if not (user and getattr(user, 'is_authenticated', False)):
        nombre_usuario = 'anonimo'

    logger.info(
        'Acceso denegado',
        extra={
            'usuario': nombre_usuario,
            'accion': request.method,
            'recurso': request.path,
            'resultado': 'denegado',
            'ip': request.META.get('REMOTE_ADDR', '-'),
            'mensaje': 'HTTP %s' % status,
        },
    )

    return response