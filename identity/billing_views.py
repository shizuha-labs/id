"""Authenticated free-v1 onboarding and mock upgrade-interest endpoints."""

from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .billing import (
    STARTER_PREVIEW_CODE,
    account_payload,
    ensure_free_v1_for_user,
    payment_provider,
    plan_catalog,
    validate_interest_context,
)


class BillingAccountView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        account, grant = ensure_free_v1_for_user(request.user)
        return Response({
            'billing_account': account_payload(account, grant),
            'plans': plan_catalog(),
            'payment_provider': 'mock',
            'checkout_available': False,
        })


class UpgradeInterestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        allowed = {'source', 'meter', 'target_plan'}
        unknown = sorted(set(request.data) - allowed) if isinstance(request.data, dict) else []
        if unknown:
            return Response(
                {field: ['Unexpected field'] for field in unknown},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            source, meter = validate_interest_context(
                request.data.get('source', 'id'),
                request.data.get('meter', ''),
            )
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        target_plan = request.data.get('target_plan') or STARTER_PREVIEW_CODE
        if target_plan != STARTER_PREVIEW_CODE:
            return Response(
                {'error': 'Only the Starter preview accepts notifications'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        account, grant = ensure_free_v1_for_user(request.user)
        result = payment_provider().notify_interest(
            account=account,
            target_plan=target_plan,
            source=source,
            meter=meter,
        )
        return Response({
            'notified': True,
            'created': result.created,
            'target_plan': target_plan,
            'billing_account': account_payload(account, grant),
            'payment_provider': 'mock',
            'checkout_created': False,
        }, status=status.HTTP_201_CREATED if result.created else status.HTTP_200_OK)
