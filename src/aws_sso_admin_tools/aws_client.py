"""AWS client management for AWS SSO Admin Tools."""

import boto3
from typing import Optional, Dict, Any
from botocore.exceptions import ClientError

from .models import AWSClientError


class AWSClient:
    """Manages AWS client connections and caching."""

    def __init__(self, session: Optional[boto3.Session] = None):
        """
        Initialize AWS client manager.

        Args:
            session: Optional boto3 session. If not provided, uses default session.
        """
        self.session = session or boto3.Session()
        self._clients: Dict[str, Any] = {}
        self._instance_arn: Optional[str] = None
        self._identitystore_id: Optional[str] = None


    def get_client(self, service_name: str) -> Any:
        """
        Get or create a boto3 client for the specified service.

        Args:
            service_name: AWS service name (e.g., 'sso-admin', 'identitystore')

        Returns:
            Boto3 client for the specified service
        """
        if service_name not in self._clients:
            self._clients[service_name] = self.session.client(service_name)
        return self._clients[service_name]


    @property
    def instance_arn(self) -> str:
        """
        Get the SSO instance ARN (lazy loaded).

        Returns:
            SSO instance ARN

        Raises:
            AWSClientError: If unable to retrieve instance information
        """
        if self._instance_arn is None:
            self._load_instance_info()
        return self._instance_arn

    @property
    def identitystore_id(self) -> str:
        """
        Get the Identity Store ID (lazy loaded).

        Returns:
            Identity Store ID

        Raises:
            AWSClientError: If unable to retrieve instance information
        """
        if self._identitystore_id is None:
            self._load_instance_info()
        return self._identitystore_id


    def _load_instance_info(self) -> None:
        """
        Load SSO instance information from AWS.

        Raises:
            AWSClientError: If unable to retrieve instance information
        """
        try:
            sso_admin_client = self.get_client('sso-admin')
            response = sso_admin_client.list_instances(MaxResults=1)

            if not response.get('Instances'):
                raise AWSClientError("No SSO instances found")

            instance = response['Instances'][0]
            self._instance_arn = instance['InstanceArn']
            self._identitystore_id = instance['IdentityStoreId']

        except ClientError as e:
            raise AWSClientError(f"Failed to retrieve SSO instance: {str(e)}")
        except Exception as e:
            raise AWSClientError(f"Unexpected error retrieving SSO instance: {str(e)}")
