from rest_framework import serializers
from django.contrib.auth.models import User, Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

import logging

logger = logging.getLogger('seguridad')


def _log_auditoria(request, accion, recurso, resultado, email, motivo=''):
    """Registro único de auditoría de seguridad."""
    ip = request.META.get('REMOTE_ADDR', '-') if request else '-'
    logger.info(
        'Auditoría de seguridad',
        extra={
            'usuario': email or 'desconocido',
            'accion': accion,
            'recurso': recurso,
            'resultado': resultado,
            'ip': ip,
            'mensaje': motivo or '-',
        },
    )


def _log_login_fallido(request, email, motivo):
    ip = request.META.get('REMOTE_ADDR', '-') if request else '-'
    logger.info(
        'Login fallido',
        extra={
            'usuario': email or 'desconocido',
            'accion': 'login',
            'recurso': '/api/auth/login/',
            'resultado': 'rechazado',
            'ip': ip,
            'mensaje': motivo,
        },
    )


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, required=False)
    # nombre/apellido se guardan en first_name/last_name del User de Django
    nombre = serializers.CharField(source='first_name', required=False, allow_blank=True)
    apellido = serializers.CharField(source='last_name', required=False, allow_blank=True)
    role = serializers.ChoiceField(
        choices=['Administrador', 'Empleado'],
        write_only=True,
        required=False
    )

    class Meta:
        model = User
        fields = ('username', 'nombre', 'apellido', 'email', 'password', 'role')

    def to_representation(self, instance):
        data = super().to_representation(instance)
        group = instance.groups.first()
        data['role'] = group.name if group else None
        return data

    def validate(self, attrs):
        # La contraseña es obligatoria al crear, pero opcional al editar.
        password = attrs.get('password')

        if self.instance is None and not password:
            raise serializers.ValidationError(
                {'password': 'La contraseña es obligatoria.'}
            )

        # Política de contraseña segura (letras + números + especial, ≥ 8).
        if password:
            try:
                validate_password(password, self.instance)
            except DjangoValidationError as exc:
                raise serializers.ValidationError(
                    {'password': list(exc.messages)}
                )

        return attrs

    def create(self, validated_data):
        role = validated_data.pop('role', 'Empleado')
        user = User.objects.create_user(**validated_data)
        if role == 'Administrador':
            user.is_staff = True
            user.save()
        group = Group.objects.get(name=role)
        user.groups.add(group)

        _log_auditoria(
            self.context.get('request'),
            'registro_usuario',
            '/api/auth/register/',
            'aceptado',
            user.email,
            'Alta de usuario con rol ' + role,
        )
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        role = validated_data.pop('role', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        if role:
            instance.groups.clear()
            group = Group.objects.get(name=role)
            instance.groups.add(group)

        instance.save()

        _log_auditoria(
            self.context.get('request'),
            'edicion_usuario',
            '/api/auth/usuarios/' + str(instance.pk) + '/',
            'aceptado',
            instance.email,
            'Edición de usuario'
            + (' con cambio de contraseña' if password else ''),
        )
        return instance


class UserSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()
    nombre = serializers.CharField(source='first_name', required=False)
    apellido = serializers.CharField(source='last_name', required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'nombre', 'apellido', 'email', 'role')

    def get_role(self, obj):
        # Devuelve el primer grupo del usuario (o None si no tiene)
        group = obj.groups.first()
        return group.name if group else None
    
class EmailTokenObtainPairSerializer(TokenObtainPairSerializer):
    #forzamos que busque por email (tiene por defecto username)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Reemplazamos el campo username por email
        self.fields['email'] = serializers.CharField(required=True)
        self.fields.pop('username', None)

    def validate(self, attrs):
        # Attrs ya tiene 'email' y 'password'
        email = attrs.get('email')
        password = attrs.get('password')

        # Buscamos al usuario por email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            _log_login_fallido(self.context.get('request'), email, 'email inexistente')
            raise serializers.ValidationError('Credenciales inválidas.')

        # Verificamos la contraseña
        if not user.check_password(password):
            _log_login_fallido(self.context.get('request'), email, 'contrasena incorrecta')
            raise serializers.ValidationError('Credenciales inválidas.')

        if not user.is_active:
            _log_login_fallido(self.context.get('request'), email, 'usuario inactivo')
            raise serializers.ValidationError('Usuario inactivo.')

        # Generamos los tokens
        refresh = self.get_token(user)
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        _log_auditoria(
            self.context.get('request'),
            'login',
            '/api/auth/login/',
            'aceptado',
            email,
            'Autenticación correcta',
        )
        return data