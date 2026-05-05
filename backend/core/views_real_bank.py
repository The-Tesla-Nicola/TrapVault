"""
Real Bank Views
"""

import json
import logging
import hashlib
import time
from datetime import timedelta
from decimal import Decimal

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from .models_siem import RealBankUser

logger = logging.getLogger("honeypot.real_bank")


@method_decorator(csrf_exempt, name="dispatch")
class RealBankLoginView(APIView):
    """
    Secure login endpoint for legitimate bank customers.
    Issues JWT tokens after successful authentication.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                return Response(
                    {"error": "Username and password required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                user = RealBankUser.objects.get(username=username)
            except RealBankUser.DoesNotExist:
                logger.warning(
                    f"Real bank login attempt for non-existent user: {username}"
                )
                return Response(
                    {"error": "Invalid credentials"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.check_password(password):
                logger.warning(f"Real bank failed password for user: {username}")
                return Response(
                    {"error": "Invalid credentials"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not user.is_active:
                return Response(
                    {"error": "Account disabled"}, status=status.HTTP_403_FORBIDDEN
                )

            refresh = RefreshToken.for_user(user)

            logger.info(f"Real bank login successful: {username}")

            return Response(
                {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user": {
                        "id": str(user.id),
                        "username": user.username,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                    },
                }
            )

        except Exception as e:
            logger.error(f"Real bank login error: {e}")
            return Response(
                {"error": "Authentication failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@method_decorator(csrf_exempt, name="dispatch")
class RealBankRegisterView(APIView):
    """
    Registration endpoint for new legitimate bank customers.
    Requires approval in production.
    """

    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data

            required_fields = [
                "username",
                "password",
                "email",
                "first_name",
                "last_name",
            ]
            for field in required_fields:
                if not data.get(field):
                    return Response(
                        {"error": f"{field} is required"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if RealBankUser.objects.filter(username=data["username"]).exists():
                return Response(
                    {"error": "Username already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if RealBankUser.objects.filter(email=data["email"]).exists():
                return Response(
                    {"error": "Email already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = RealBankUser.objects.create_user(
                username=data["username"],
                password=data["password"],
                email=data["email"],
                first_name=data["first_name"],
                last_name=data["last_name"],
            )

            logger.info(f"New real bank user registered: {user.username}")

            return Response(
                {"message": "Registration successful", "user_id": str(user.id)},
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Real bank registration error: {e}")
            return Response(
                {"error": "Registration failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RealBankDashboardView(APIView):
    """
    Dashboard data for authenticated bank customers.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        return Response(
            {
                "user": {
                    "id": str(user.id),
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "account_number": getattr(user, "account_number", ""),
                    "balance": getattr(user, "balance", 0.0),
                },
                "transactions": [],
                "alerts": [],
            }
        )


class RealBankAccountView(APIView):
    """
    Account details for authenticated bank customers.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        account_data = {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "date_joined": user.date_joined.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }

        additional_fields = [
            "account_number",
            "account_type",
            "balance",
            "currency",
            "is_verified",
            "is_active",
        ]

        for field in additional_fields:
            if hasattr(user, field):
                account_data[field] = getattr(user, field, None)

        return Response(account_data)


class RealBankTransferView(APIView):
    """
    Secure fund transfer for legitimate customers.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = request.data
            amount = Decimal(str(data.get("amount", 0)))
            recipient = data.get("recipient", "")
            description = data.get("description", "")

            if amount <= 0:
                return Response(
                    {"error": "Amount must be positive"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not recipient:
                return Response(
                    {"error": "Recipient required"}, status=status.HTTP_400_BAD_REQUEST
                )

            logger.info(
                f"Transfer initiated: {request.user.username} -> {recipient}: {amount}"
            )

            return Response(
                {
                    "message": "Transfer initiated successfully",
                    "transaction_id": hashlib.sha256(
                        f"{time.time()}".encode()
                    ).hexdigest()[:16],
                    "amount": str(amount),
                    "recipient": recipient,
                    "status": "pending",
                }
            )

        except Exception as e:
            logger.error(f"Transfer error: {e}")
            return Response(
                {"error": "Transfer failed"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RealBankLogoutView(APIView):
    """
    Logout endpoint for bank customers.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.info(f"Real bank logout: {request.user.username}")
        return Response({"message": "Logged out successfully"})


def create_real_bank_jwt(user):
    """Create JWT tokens for real bank user."""
    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }
