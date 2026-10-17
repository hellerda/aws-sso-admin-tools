"""Utility functions for AWS SSO Admin Tools."""

import json
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError

from .aws_client import AWSClient
from .models import ResourceNotFoundError, AccessDeniedError


# --------------------------------------------------------------------------------------------------
# Permission Set Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_permission_set_arn_by_name(client: AWSClient, ps_name: str) -> Optional[str]:
    """
    Get permission set ARN from name.

    Args:
        client: AWS client manager
        ps_name: Permission set name

    Returns:
        Permission set ARN or None if not found
    """
    ps = get_permission_set_desc_by_name(client, ps_name)
    if ps is not None:
        return ps['PermissionSetArn']
    return None


def get_permission_set_name_by_arn(client: AWSClient, ps_arn: str) -> Optional[str]:
    """
    Get permission set name from ARN.

    Args:
        client: AWS client manager
        ps_arn: Permission set ARN

    Returns:
        Permission set name or None if not found
    """
    ps = get_permission_set_desc_by_arn(client, ps_arn)
    if ps is not None:
        return ps['Name']
    return None


def get_permission_set_desc_by_name(client: AWSClient, ps_name: str) -> Optional[Dict[str, Any]]:
    """
    Get permission set description by name.

    Args:
        client: AWS client manager
        ps_name: Permission set name

    Returns:
        Permission set description dict or None if not found
    """
    sso_admin = client.get_client('sso-admin')
    paginator = sso_admin.get_paginator('list_permission_sets')

    for page in paginator.paginate(InstanceArn=client.instance_arn):
        for ps_arn in page['PermissionSets']:
            ps = sso_admin.describe_permission_set(
                InstanceArn=client.instance_arn,
                PermissionSetArn=ps_arn
            )
            if ps['PermissionSet']['Name'] == ps_name:
                return ps['PermissionSet']

    return None


def get_permission_set_desc_by_arn(client: AWSClient, ps_arn: str) -> Optional[Dict[str, Any]]:
    """
    Get permission set description by ARN.

    Args:
        client: AWS client manager
        ps_arn: Permission set ARN

    Returns:
        Permission set description dict or None if not found
    """
    try:
        sso_admin = client.get_client('sso-admin')
        ps = sso_admin.describe_permission_set(
            InstanceArn=client.instance_arn,
            PermissionSetArn=ps_arn
        )
        return ps['PermissionSet']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return None
        else:
            raise


# --------------------------------------------------------------------------------------------------
# User Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_user_id_by_name(client: AWSClient, user_name: str) -> Optional[str]:
    """
    Get user ID from username.

    Args:
        client: AWS client manager
        user_name: Username

    Returns:
        User ID or None if not found
    """
    try:
        identitystore = client.get_client('identitystore')
        response = identitystore.get_user_id(
            IdentityStoreId=client.identitystore_id,
            AlternateIdentifier={
                'UniqueAttribute': {
                    'AttributePath': 'userName',
                    'AttributeValue': user_name
                }
            }
        )
        return response['UserId']
    except:
        return None


def get_user_name_by_id(client: AWSClient, user_id: str) -> Optional[str]:
    """
    Get username from user ID.

    Args:
        client: AWS client manager
        user_id: User ID

    Returns:
        Username or None if not found
    """
    try:
        identitystore = client.get_client('identitystore')
        response = identitystore.describe_user(
            IdentityStoreId=client.identitystore_id,
            UserId=user_id
        )
        return response['UserName']
    except:
        return None


# --------------------------------------------------------------------------------------------------
# Group Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_group_id_by_name(client: AWSClient, group_name: str) -> Optional[str]:
    """
    Get group ID from group name.

    Args:
        client: AWS client manager
        group_name: Group display name

    Returns:
        Group ID or None if not found
    """
    try:
        identitystore = client.get_client('identitystore')
        response = identitystore.get_group_id(
            IdentityStoreId=client.identitystore_id,
            AlternateIdentifier={
                'UniqueAttribute': {
                    'AttributePath': 'displayName',
                    'AttributeValue': group_name
                }
            }
        )
        return response['GroupId']
    except:
        return None


def get_group_name_by_id(client: AWSClient, group_id: str) -> Optional[str]:
    """
    Get group name from group ID.

    Args:
        client: AWS client manager
        group_id: Group ID

    Returns:
        Group display name or None if not found
    """
    try:
        identitystore = client.get_client('identitystore')
        response = identitystore.describe_group(
            IdentityStoreId=client.identitystore_id,
            GroupId=group_id
        )
        return response['DisplayName']
    except:
        return None


# --------------------------------------------------------------------------------------------------
# Account Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_acct_id_by_name(client: AWSClient, acct_name: str) -> Optional[str]:
    """
    Get account ID from account name.

    Args:
        client: AWS client manager
        acct_name: Account name

    Returns:
        Account ID or None if not found
    """
    acct = get_acct_desc_by_name(client, acct_name)
    if acct is not None:
        return acct['Id']
    return None


def get_acct_name_by_id(client: AWSClient, acct_id: str) -> Optional[str]:
    """
    Get account name from account ID.

    Args:
        client: AWS client manager
        acct_id: Account ID

    Returns:
        Account name or None if not found
    """
    acct = get_acct_desc_by_id(client, acct_id)
    if acct is not None:
        return acct['Name']
    return None


def get_acct_desc_by_name(client: AWSClient, acct_name: str) -> Optional[Dict[str, Any]]:
    """
    Get account description by name.

    Args:
        client: AWS client manager
        acct_name: Account name

    Returns:
        Account description dict or None if not found
    """
    organizations = client.get_client('organizations')

    try:
        for page in organizations.get_paginator('list_accounts').paginate():
            for acct in page['Accounts']:
                if acct['Name'] == acct_name:
                    return acct
        return None
    except:
        return None


def get_acct_desc_by_id(client: AWSClient, acct_id: str) -> Optional[Dict[str, Any]]:
    """
    Get account description by ID.

    Args:
        client: AWS client manager
        acct_id: Account ID

    Returns:
        Account description dict or None if not found
    """
    organizations = client.get_client('organizations')

    try:
        acct = organizations.describe_account(AccountId=acct_id)
        return acct['Account']
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccountNotFoundException':
            return None
        else:
            raise


# --------------------------------------------------------------------------------------------------
# OU Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_organizational_root(client: AWSClient) -> Dict[str, str]:
    """
    Get organizational root information.

    Args:
        client: AWS client manager

    Returns:
        Dict with Name, RootId, OrgId, MgmtAcctId, Arn

    Raises:
        ValueError: If organizational root not found
    """
    organizations = client.get_client('organizations')

    try:
        for page in organizations.get_paginator('list_roots').paginate():
            for item in page['Roots']:
                if item['Name'] == 'Root':
                    # Parse ARN: arn:aws:organizations::123456789012:root/o-abcdefghij/r-abcd
                    arn_parts = item['Arn'].split('/')
                    org_id = arn_parts[-2]
                    root_id = arn_parts[-1]
                    mgmt_acct_id = item['Arn'].split(':')[4]

                    return {
                        'Name': item['Name'],
                        'RootId': root_id,
                        'OrgId': org_id,
                        'MgmtAcctId': mgmt_acct_id,
                        'Arn': item['Arn']
                    }

        raise ValueError('Organizational root not found.')
    except Exception as e:
        raise ValueError(f'Error getting organizational root: {e}')


def get_ou_id_by_name(client: AWSClient, ou_name: str) -> Optional[str]:
    """
    Get OU ID from OU name (searches entire hierarchy).

    Args:
        client: AWS client manager
        ou_name: OU name

    Returns:
        OU ID or None if not found
    """
    organizations = client.get_client('organizations')

    def search_recursive(parent_id: str) -> Optional[str]:
        for page in organizations.get_paginator('list_organizational_units_for_parent').paginate(
            ParentId=parent_id
        ):
            for item in page['OrganizationalUnits']:
                if item['Name'] == ou_name:
                    return item['Id']
                result = search_recursive(item['Id'])
                if result:
                    return result
        return None

    return search_recursive(get_organizational_root(client)['RootId'])


def get_ou_arn_by_name(client: AWSClient, ou_name: str) -> Optional[str]:
    """
    Get OU ARN from OU name (searches entire hierarchy).

    Args:
        client: AWS client manager
        ou_name: OU name

    Returns:
        OU ARN or None if not found
    """
    organizations = client.get_client('organizations')

    def search_recursive(parent_id: str) -> Optional[str]:
        for page in organizations.get_paginator('list_organizational_units_for_parent').paginate(
            ParentId=parent_id
        ):
            for item in page['OrganizationalUnits']:
                if item['Name'] == ou_name:
                    return item['Arn']
                result = search_recursive(item['Id'])
                if result:
                    return result
        return None

    return search_recursive(get_organizational_root(client)['RootId'])


def get_ou_name_by_id(client: AWSClient, ou_id: str) -> Optional[str]:
    """
    Get OU name from OU ID (searches entire hierarchy).

    Args:
        client: AWS client manager
        ou_id: OU ID

    Returns:
        OU name or None if not found
    """
    organizations = client.get_client('organizations')

    def search_recursive(parent_id: str) -> Optional[str]:
        for page in organizations.get_paginator('list_organizational_units_for_parent').paginate(
            ParentId=parent_id
        ):
            for item in page['OrganizationalUnits']:
                if item['Id'] == ou_id:
                    return item['Name']
                result = search_recursive(item['Id'])
                if result:
                    return result
        return None

    return search_recursive(get_organizational_root(client)['RootId'])


def get_account_parent_ou(client: AWSClient, account_id: str) -> Optional[Dict[str, str]]:
    """
    Find the parent OU for a given account.

    Args:
        client: AWS client manager
        account_id: Account ID

    Returns:
        Dict with Type, Id, Name, Arn or None if not found
    """
    organizations = client.get_client('organizations')

    try:
        response = organizations.list_parents(ChildId=account_id)
        parent = response['Parents'][0]  # Account has only one parent

        if parent['Type'] == 'ROOT':
            org_root = get_organizational_root(client)
            return {
                'Type': 'ROOT',
                'Id': parent['Id'],
                'Name': 'Root',
                'Arn': org_root['Arn']
            }
        else:
            ou_response = organizations.describe_organizational_unit(
                OrganizationalUnitId=parent['Id']
            )
            ou = ou_response['OrganizationalUnit']
            return {
                'Type': 'ORGANIZATIONAL_UNIT',
                'Id': ou['Id'],
                'Name': ou['Name'],
                'Arn': ou['Arn']
            }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if 'NotFound' in error_code:
            return None
        else:
            raise


# --------------------------------------------------------------------------------------------------
# Application Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_application_arn_by_name(client: AWSClient, app_name: str) -> Optional[str]:
    """
    Get application ARN from name.

    Args:
        client: AWS client manager
        app_name: Application name

    Returns:
        Application ARN or None if not found
    """
    sso_admin = client.get_client('sso-admin')
    paginator = sso_admin.get_paginator('list_applications')

    for page in paginator.paginate(InstanceArn=client.instance_arn):
        for item in page['Applications']:
            if item['Name'] == app_name:
                return item['ApplicationArn']

    return None


def get_application_name_by_arn(client: AWSClient, app_arn: str) -> Optional[str]:
    """
    Get application name from ARN.

    Args:
        client: AWS client manager
        app_arn: Application ARN

    Returns:
        Application name or None if not found
    """
    try:
        sso_admin = client.get_client('sso-admin')
        app = sso_admin.describe_application(ApplicationArn=app_arn)
        return app['Name']
    except:
        return None


# --------------------------------------------------------------------------------------------------
# TTI Lookup Functions
# --------------------------------------------------------------------------------------------------

def get_tti_arn_by_name(client: AWSClient, tti_name: str) -> Optional[str]:
    """
    Get trusted token issuer ARN from name.

    Args:
        client: AWS client manager
        tti_name: TTI name

    Returns:
        TTI ARN or None if not found
    """
    sso_admin = client.get_client('sso-admin')
    paginator = sso_admin.get_paginator('list_trusted_token_issuers')

    for page in paginator.paginate(InstanceArn=client.instance_arn):
        for item in page['TrustedTokenIssuers']:
            if item['Name'] == tti_name:
                return item['TrustedTokenIssuerArn']

    return None


def get_tti_name_by_arn(client: AWSClient, tti_arn: str) -> Optional[str]:
    """
    Get trusted token issuer name from ARN.

    Args:
        client: AWS client manager
        tti_arn: TTI ARN

    Returns:
        TTI name or None if not found
    """
    try:
        sso_admin = client.get_client('sso-admin')
        tti = sso_admin.describe_trusted_token_issuer(
            TrustedTokenIssuerArn=tti_arn
        )
        return tti['Name']
    except:
        return None


# --------------------------------------------------------------------------------------------------
# Group Membership Functions
# --------------------------------------------------------------------------------------------------

def get_group_memberships_for_user(client: AWSClient, user_id: str) -> List[Dict[str, Any]]:
    """
    Get all group memberships for a user.

    Args:
        client: AWS client manager
        user_id: User ID

    Returns:
        List of group description dicts
    """
    identitystore = client.get_client('identitystore')
    found_groups = []

    try:
        paginator = identitystore.get_paginator('list_group_memberships_for_member')

        for page in paginator.paginate(
            IdentityStoreId=client.identitystore_id,
            MemberId={'UserId': user_id}
        ):
            for member in page['GroupMemberships']:
                response = identitystore.describe_group(
                    IdentityStoreId=client.identitystore_id,
                    GroupId=member['GroupId']
                )
                found_groups.append(response)

        return found_groups
    except Exception as e:
        raise ValueError(f'Error getting group memberships: {e}')


# --------------------------------------------------------------------------------------------------
# Input Parsing Functions
# --------------------------------------------------------------------------------------------------

def parse_tags_from_input(input_str: str) -> List[Dict[str, str]]:
    """
    Parse tags from command-line input.

    Supports:
    - Key=Value,Key2=Value2
    - JSON array: [{"Key":"K","Value":"V"}]
    - File: file:///path/to/tags.json

    Args:
        input_str: Input string

    Returns:
        List of tag dictionaries with Key and Value
    """
    # Handle file:// prefix
    if input_str.startswith('file://'):
        file_path = input_str[7:]
        with open(file_path, 'r') as f:
            input_str = f.read()

    # Try JSON first
    try:
        tags = json.loads(input_str)
        if isinstance(tags, list):
            return tags
    except json.JSONDecodeError:
        pass

    # Parse as key=value pairs
    tags = []
    for pair in input_str.split(','):
        if '=' in pair:
            key, value = pair.split('=', 1)
            tags.append({'Key': key.strip(), 'Value': value.strip()})

    return tags


def parse_policy_from_input(input_str: str) -> str:
    """
    Parse policy document from command-line input.

    Supports:
    - Inline JSON string
    - File: file:///path/to/policy.json

    Args:
        input_str: Input string

    Returns:
        Policy document as JSON string
    """
    # Handle file:// prefix
    if input_str.startswith('file://'):
        file_path = input_str[7:]
        with open(file_path, 'r') as f:
            return f.read()

    return input_str


def parse_policy_arns_from_input(input_str: str) -> List[str]:
    """
    Parse policy ARNs from command-line input.

    Supports:
    - Single ARN
    - Comma-separated ARNs
    - JSON array: ["arn1","arn2"]
    - File: file:///path/to/arns.json

    Args:
        input_str: Input string

    Returns:
        List of policy ARNs
    """
    # Handle file:// prefix
    if input_str.startswith('file://'):
        file_path = input_str[7:]
        with open(file_path, 'r') as f:
            input_str = f.read()

    # Try JSON first
    try:
        arns = json.loads(input_str)
        if isinstance(arns, list):
            return arns
    except json.JSONDecodeError:
        pass

    # Parse as comma-separated values
    return [arn.strip() for arn in input_str.split(',') if arn.strip()]


def parse_cm_policies_from_input(input_str: str) -> List[Dict[str, str]]:
    """
    Parse customer-managed policy references from command-line input.

    Supports:
    - Name=Path,Name2=Path2
    - JSON array: [{"Name":"N","Path":"P"}]
    - File: file:///path/to/policies.json

    Args:
        input_str: Input string

    Returns:
        List of customer-managed policy reference dictionaries with Name and Path
    """
    # Handle file:// prefix
    if input_str.startswith('file://'):
        file_path = input_str[7:]
        with open(file_path, 'r') as f:
            input_str = f.read()

    # Try JSON first
    try:
        policies = json.loads(input_str)
        if isinstance(policies, list):
            return policies
    except json.JSONDecodeError:
        pass

    # Parse as name=path pairs
    policies = []
    for pair in input_str.split(','):
        if '=' in pair:
            name, path = pair.split('=', 1)
            policies.append({'Name': name.strip(), 'Path': path.strip()})

    return policies


# --------------------------------------------------------------------------------------------------
# Assume-Role Target ARNs Functions (Custom Feature)
# --------------------------------------------------------------------------------------------------

def get_target_arns_for_ps(client: AWSClient, ps_arn: str) -> List[str]:
    """
    Extract assume-role target ARNs from a permission set's inline policy.

    This is a custom feature (not native to AWS) that parses the inline policy
    of a permission set to extract ARNs of conventional IAM roles that can be
    assumed from Identity Center roles.

    The function looks for:
    - An inline policy with "sts:AssumeRole" action
    - A single Statement (not a list of statements)
    - Resource field containing IAM role ARN(s)

    Limitations (intentional simplifications):
    - Only checks inline policies (not attached managed policies)
    - Only handles policies with a single Statement object
    - Does not handle Statement arrays

    Args:
        client: AWS client manager
        ps_arn: Permission set ARN

    Returns:
        List of IAM role ARNs that can be assumed, or empty list if:
        - Permission set has no inline policy
        - Policy doesn't match expected structure
        - Policy is not an AssumeRole policy
        - Any parsing errors occur
    """
    import logging

    sso_admin = client.get_client('sso-admin')

    try:
        response = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=client.instance_arn,
            PermissionSetArn=ps_arn
        )

        # PS has no inline policy
        if not response.get('InlinePolicy') or response['InlinePolicy'] == '':
            return []

        # Parse the policy JSON
        policy = json.loads(response['InlinePolicy'])

        # Check if Statement is a single dict (not a list)
        # This is an intentional limitation - we don't handle Statement arrays
        if not isinstance(policy.get('Statement'), dict):
            logging.info(f'Not a simple permissions policy (Statement is not a dict) in PS arn "{ps_arn}"')
            return []

        statement = policy['Statement']

        # Check if this is an AssumeRole policy
        if statement.get('Action') != 'sts:AssumeRole':
            logging.info(f'Not an AssumeRole permissions policy in PS arn "{ps_arn}"')
            return []

        # Extract the Resource field
        arns_list = statement.get('Resource', [])

        # Ensure Resource is a list
        if not isinstance(arns_list, list):
            logging.info(f'Resource field is not a list in PS arn "{ps_arn}"')
            return []

        return arns_list

    except Exception as e:
        logging.error(f'Error in get_target_arns_for_ps(): {e}')
        return []
