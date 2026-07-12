from ......account.error_codes import AccountErrorCode
from ......core.jwt import (
    PERMISSIONS_FIELD,
    create_access_token,
    create_access_token_for_app,
    create_refresh_token,
)
from .....tests.utils import get_graphql_content

MUTATION_TOKEN_VERIFY = """
    mutation tokenVerify($token: String!){
        tokenVerify(token: $token){
            isValid
            user{
              email
              userPermissions{
                code
              }
            }
            errors{
              code
            }
        }
    }
"""


def test_verify_access_token(api_client, customer_user):
    variables = {"token": create_access_token(customer_user)}
    response = api_client.post_graphql(MUTATION_TOKEN_VERIFY, variables)
    content = get_graphql_content(response)
    data = content["data"]["tokenVerify"]
    assert data["isValid"] is True
    user_email = content["data"]["tokenVerify"]["user"]["email"]
    assert customer_user.email == user_email


def test_verify_access_token_with_permissions(
    api_client, staff_user, permission_manage_users, permission_manage_gift_card
):
    staff_user.user_permissions.add(permission_manage_gift_card)
    staff_user.user_permissions.add(permission_manage_users)
    assigned_permissions = ["MANAGE_ORDERS"]
    additional_payload = {PERMISSIONS_FIELD: assigned_permissions}
    variables = {"token": create_access_token(staff_user, additional_payload)}
    response = api_client.post_graphql(MUTATION_TOKEN_VERIFY, variables)
    content = get_graphql_content(response)
    data = content["data"]["tokenVerify"]
    assert data["isValid"] is True
    user_email = content["data"]["tokenVerify"]["user"]["email"]
    user_permissions = content["data"]["tokenVerify"]["user"]["userPermissions"]
    assert len(user_permissions) == 1
    assert user_permissions[0]["code"] == assigned_permissions[0]
    assert staff_user.email == user_email


def test_verify_access_app_token(api_client, staff_user, app):
    variables = {"token": create_access_token_for_app(app, staff_user)}
    response = api_client.post_graphql(MUTATION_TOKEN_VERIFY, variables)
    content = get_graphql_content(response)
    data = content["data"]["tokenVerify"]
    assert data["isValid"] is True
    user_email = content["data"]["tokenVerify"]["user"]["email"]
    assert staff_user.email == user_email


def test_verify_token_incorrect_token(api_client):
    variables = {"token": "incorrect_token"}
    response = api_client.post_graphql(MUTATION_TOKEN_VERIFY, variables)
    content = get_graphql_content(response)
    data = content["data"]["tokenVerify"]
    errors = data["errors"]
    assert len(errors) == 1
    assert errors[0]["code"] == AccountErrorCode.JWT_DECODE_ERROR.name
    assert data["isValid"] is False
    assert not data["user"]


def test_verify_token_rejects_refresh_token(api_client, customer_user):
    """A refresh token must not verify as a valid authenticated session token.

    Only access (or thirdparty-access) tokens are meant to confirm a live
    session; accepting a refresh token here would let a caller who only holds
    a refresh token be treated as holding a valid access session.
    """
    variables = {"token": create_refresh_token(customer_user)}
    response = api_client.post_graphql(MUTATION_TOKEN_VERIFY, variables)
    content = get_graphql_content(response)
    data = content["data"]["tokenVerify"]
    errors = data["errors"]

    assert data["isValid"] is False
    assert not data["user"]
    assert len(errors) == 1
    assert errors[0]["code"] == AccountErrorCode.JWT_INVALID_TOKEN.name


def test_verify_token_invalidated_by_user(api_client, customer_user):
    variables = {"token": create_access_token(customer_user)}
    customer_user.jwt_token_key = "new token"
    customer_user.save()
    response = api_client.post_graphql(MUTATION_TOKEN_VERIFY, variables)
    content = get_graphql_content(response)
    data = content["data"]["tokenVerify"]
    errors = data["errors"]

    assert data["isValid"] is False
    assert len(errors) == 1
    assert errors[0]["code"] == AccountErrorCode.JWT_INVALID_TOKEN.name
