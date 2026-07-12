import graphene
import jwt
from django.core.exceptions import ValidationError
from graphene.types.generic import GenericScalar

from .....account.error_codes import AccountErrorCode
from .....core.jwt import get_user_from_access_payload
from ....core import ResolveInfo
from ....core.doc_category import DOC_CATEGORY_AUTH
from ....core.mutations import BaseMutation
from ....core.types import AccountError
from ...types import User
from .utils import get_payload


class VerifyToken(BaseMutation):
    """Mutation that confirms if token is valid and also returns user data."""

    user = graphene.Field(User, description="User assigned to token.")
    is_valid = graphene.Boolean(
        required=True,
        default_value=False,
        description="Determine if token is valid or not.",
    )
    payload = GenericScalar(description="JWT payload.")

    class Arguments:
        token = graphene.String(required=True, description="JWT token to validate.")

    class Meta:
        description = "Verify JWT token."
        doc_category = DOC_CATEGORY_AUTH
        error_type_class = AccountError
        error_type_field = "account_errors"

    @classmethod
    def get_payload(cls, token):
        try:
            payload = get_payload(token)
        except ValidationError as e:
            raise ValidationError({"token": e}) from e
        return payload

    @classmethod
    def get_user(cls, payload):
        """Resolve the token's user, accepting only access (or thirdparty) tokens.

        A refresh token must never verify here -- it carries a longer lifetime
        and is meant only for the `tokenRefresh` flow, not as proof of a live
        authenticated session.
        """
        try:
            user = get_user_from_access_payload(payload)
        except jwt.InvalidTokenError as e:
            raise ValidationError(
                {
                    "token": ValidationError(
                        str(e), code=AccountErrorCode.JWT_INVALID_TOKEN.value
                    )
                }
            ) from e
        if not user:
            raise ValidationError(
                {
                    "token": ValidationError(
                        "Invalid token", code=AccountErrorCode.JWT_INVALID_TOKEN.value
                    )
                }
            )
        return user

    @classmethod
    def perform_mutation(  # type: ignore[override]
        cls, _root, _info: ResolveInfo, /, *, token
    ):
        payload = cls.get_payload(token)
        user = cls.get_user(payload)
        return cls(errors=[], user=user, is_valid=True, payload=payload)
