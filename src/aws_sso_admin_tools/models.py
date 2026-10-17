"""Data models and exceptions for AWS SSO Admin Tools."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PrincipalType(Enum):
    """Principal type for account assignments."""
    USER = "USER"
    GROUP = "GROUP"


class TargetType(Enum):
    """Target type for account assignments."""
    AWS_ACCOUNT = "AWS_ACCOUNT"



@dataclass
class AccountAssignment:
    """Represents an account assignment in AWS Identity Center."""
    principal_type: PrincipalType
    principal_id: str
    permission_set_arn: str
    account_id: str
    principal_name: Optional[str] = None
    permission_set_name: Optional[str] = None
    account_name: Optional[str] = None



# Custom exceptions
class AWSClientError(Exception):
    """Base exception for AWS client errors."""
    pass


class ResourceNotFoundError(AWSClientError):
    """Exception raised when a resource is not found."""
    pass


class AccessDeniedError(AWSClientError):
    """Exception raised when access is denied."""
    pass


class ValidationError(AWSClientError):
    """Exception raised when input validation fails."""
    pass
