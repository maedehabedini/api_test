from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
from django.db.models import Q
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .decorators import auth_permission
from .models import CustomUser, Token
from .serializers import CustomUserSerializer
from .tokens import account_activation_token
from rest_framework import status
from django_q.tasks import async_task, result
from .tasks import create_log
from django.utils.decorators import method_decorator


class Authentication(viewsets.ViewSet):
    @action(detail=False, methods=['POST'])
    def register(self, request):
        data = request.data
        user_serializer = CustomUserSerializer(data=data)
        user_serializer.is_valid(raise_exception=True)
        user = user_serializer.save()
        token = account_activation_token.make_token(user)
        url = f"http://127.0.0.1:9000/active?ac_id={token}&user_uuid={user.user_uuid}"
        send_mail(message=f"{url}", from_email=settings.EMAIL_HOST_USER, recipient_list=[user.email],
                  fail_silently=False, subject="auth email")
        data = {
            "login_time": timezone.now(),
            "user_ip": request.META.get('REMOTE_ADDR'),
            "user": user.user_uuid
        }
        async_task(create_log, data=data)


        return Response({"url": url})

    @action(detail=False, methods=['POST'])
    def activation(self, request):
        user_uuid = request.data.get("user_uuid")
        ac_id = request.data.get("ac_id")
        try:
            user = CustomUser.objects.get(user_uuid=user_uuid)
            check_token = account_activation_token.check_token(user, ac_id)
            if not check_token:
                raise ValueError
            user.is_active = True
            user.save()
            user_token = Token.objects.create(user=user)
            return Response(data={"token": user_token.token,
                                  "user": user}, status=status.HTTP_202_ACCEPTED)

        except (CustomUser.DoesNotExist, ValueError, ValidationError):
            return Response(data={"message": "user not found!"}, status=404)

    @action(detail=False, methods=['POST'])
    def login(self, request):
        user_name = request.data.get('user_name')
        password = request.data.get('password')
        try:
            user = CustomUser.objects.get(user_name=user_name)
        except CustomUser.DoesNotExist:
            return Response(data={"message": "this user does not exist!"}, status=status.HTTP_400_BAD_REQUEST)
        if check_password(password, user.password):
            serializer = CustomUserSerializer(user)
            user_login_token = Token.objects.create(user=user)
            user_info = {
                "user": serializer.data,
                "token": user_login_token.token
            }
            return Response(data=user_info, status=status.HTTP_202_ACCEPTED)
        return Response(data={"message": "this user does not exist!"}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['PATCH'])  # permission
    def profile(self, request):
        user = request.user
        user_serializer = CustomUserSerializer(instance=user, data=request.data, partial=True)
        user_serializer.is_valid(raise_exception=True)
        user_serializer.save()
        return Response(data={"user": user_serializer.data})

    @method_decorator(auth_permission)
    @action(detail=False, methods=["DELETE"])
    def logout(self, request):
        print("somthinngggg")
        request.token.delete()
        return Response(status=204)

    @action(detail=False, methods=['POST'])
    def forgot_password(self, request):
        user = request.data.get("user")
        try:
            user = CustomUser.objects.filter(Q(user_name__exact=user) | Q(email__exact=user)).first()
            user.change_password = False
            user.save()
        except CustomUser.DoesNotExist:
            return Response(data={"message": "this user does not exist!"}, status=status.HTTP_400_BAD_REQUEST)
        token = account_activation_token.make_token(user)
        url = f"http://127.0.0.1:9000/vertification?ac_id={token}&user_uuid={user.user_uuid}"
        send_mail(message=f"{url}", from_email=settings.EMAIL_HOST_USER, recipient_list=[user.email],
                  fail_silently=False, subject="auth email")
        return Response({"url": url})

    @action(detail=False, methods=['POST'])
    def change_password(self, request):
        ac_id = request.data.get("user_name")
        user_uuid = request.data.get("user_uuid")
        password = request.data.get("password")
        confirm = request.data.get("confirm")
        try:
            user = CustomUser.objects.get(user_uuid=user_uuid)
            check_token = account_activation_token.check_token(user, ac_id)
            if not check_token:
                return ValueError
            if password == confirm:
                user.password = make_password(password)
                user.change_password = True
                user.save()
                user_token = Token.objects.create(user=user)
                data = {
                    "user": user,
                    "token": user_token.token
                }
                return Response(data=data)
        except (CustomUser.DoesNotExist, ValueError, ValidationError):
            return Response(data={"message": "user not found!"}, status=404)
