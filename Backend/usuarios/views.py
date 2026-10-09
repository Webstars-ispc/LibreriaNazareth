from rest_framework import generics, permissions, serializers
from django.contrib.auth.models import User
from .serializers import RegisterSerializer, UserSerializer, EmailTokenObtainPairSerializer
from .permissions import IsAdminUser
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

import logging

logger = logging.getLogger('seguridad')

#CRUD Usuario
class RegisterView(generics.CreateAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

class LoginView(TokenObtainPairView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = EmailTokenObtainPairSerializer

class RefreshView(TokenRefreshView):
    permission_classes = (permissions.AllowAny,)
    
class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user
    
#CRUD Administrador (para que cree, modifique y elimine empleados)
class AdminUserListView(generics.ListAPIView):
    """Lista todos los usuarios"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAdminUser,)

class AdminUserCreateView(generics.CreateAPIView):
    """Crear un nuevo usuario"""
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = (IsAdminUser,)

class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Ver, modificar o eliminar un usuario específico"""
    queryset = User.objects.all()
    permission_classes = (IsAdminUser,)

    def get_serializer_class(self):
        # Para actualizar usamos el RegisterSerializer (permite cambiar contraseña y rol)
        if self.request.method in ('PUT', 'PATCH'):
            return RegisterSerializer
        # Para ver detalles usamos el UserSerializer (sin contraseña)
        return UserSerializer

    def perform_destroy(self, instance):
        # Evita que un administrador se elimine a sí mismo
        if instance == self.request.user:
            logger.info(
                'Intento de autoeliminacion bloqueado',
                extra={
                    'usuario': self.request.user.username,
                    'accion': 'DELETE',
                    'recurso': self.request.path,
                    'resultado': 'bloqueado',
                    'ip': self.request.META.get('REMOTE_ADDR', '-'),
                    'mensaje': 'Un administrador intento eliminarse a si mismo',
                },
            )
            raise serializers.ValidationError("No podés eliminar tu propio usuario.")
        instance.delete()