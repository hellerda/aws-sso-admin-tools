"""User and group commands for AWS SSO Admin Tools."""

import json
from argparse import ArgumentParser
from typing import List, Dict, Any

from .base import BaseCommand
from ..aws_client import AWSClient
from ..output import OutputHandler
from .. import utils


def load_user_list(file_path: str) -> List[Dict[str, str]]:
    """
    Load user list from JSON file.

    Expected format:
    [
        {
            "FamilyName": "Newton",
            "GivenName": "Isaac",
            "Email": "isaac@brainstorm.org"
        },
        ...
    ]

    Args:
        file_path: Path to JSON file containing user list

    Returns:
        List of user dictionaries
    """
    with open(file_path, 'r') as f:
        return json.load(f)


# --------------------------------------------------------------------------------------------------
# Group CRUD Commands
# --------------------------------------------------------------------------------------------------

class CreateGroupCommand(BaseCommand):
    """Create a new group."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--group-desc',
            help='Group description'
        )

    def execute(self) -> None:
        """Execute the command."""
        identitystore = self.client.get_client('identitystore')

        params = {
            'IdentityStoreId': self.client.identitystore_id,
            'DisplayName': self.args.group_name,
        }

        if self.args.group_desc:
            params['Description'] = self.args.group_desc

        try:
            response = identitystore.create_group(**params)
            response.pop('ResponseMetadata', None)

            # Always output JSON (no separate HR mode)
            self.output.print_json(response)

        except identitystore.exceptions.ConflictException:
            self.output.print_error(f'Group "{self.args.group_name}" already exists.')
            raise SystemExit(1)


class DeleteGroupCommand(BaseCommand):
    """Delete a group."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-id',
            help='Group ID'
        )
        parser.add_argument(
            '--group-name',
            help='Group name'
        )

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.group_id and not self.args.group_name:
            self.output.print_error('No group specified; use one of: --group-id, --group-name.')
            raise SystemExit(1)

        if self.args.group_id:
            group_id = self.args.group_id
        else:
            group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
            if group_id is None:
                self.output.print_error(f'Group "{self.args.group_name}" not found.')
                raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')
        identitystore.delete_group(
            IdentityStoreId=self.client.identitystore_id,
            GroupId=group_id
        )

        if not self.output.json_output:
            group_name = self.args.group_name or group_id
            print(f'Deleted group: "{group_name}" with ID: {group_id}')


class DescribeGroupCommand(BaseCommand):
    """Describe a group."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-id',
            help='Group ID'
        )
        parser.add_argument(
            '--group-name',
            help='Group name'
        )

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.group_id and not self.args.group_name:
            self.output.print_error('No group specified; use one of: --group-id, --group-name.')
            raise SystemExit(1)

        # Store what the user passed for the header
        user_input = self.args.group_name if self.args.group_name else self.args.group_id

        if self.args.group_id:
            group_id = self.args.group_id
        else:
            group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
            if group_id is None:
                self.output.print_error(f'Group "{self.args.group_name}" not found.')
                raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')
        response = identitystore.describe_group(
            IdentityStoreId=self.client.identitystore_id,
            GroupId=group_id
        )
        response.pop('ResponseMetadata', None)

        if self.output.json_output:
            self.output.print_json(response)
        else:
            # Human-readable output with header
            print(f'Group: "{user_input}":')
            print(f'- DisplayName: {response["DisplayName"]}')
            print(f'- GroupId: {response["GroupId"]}')

            # Get first ExternalId if available
            external_ids = response.get('ExternalIds', [])
            if external_ids:
                external_id = external_ids[0].get('Id', 'N/A')
                print(f'- ExternalId: {external_id}')
            else:
                print('- ExternalId: N/A')


class ListGroupsCommand(BaseCommand):
    """List all groups."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        pass

    def execute(self) -> None:
        """Execute the command."""
        identitystore = self.client.get_client('identitystore')
        paginator = identitystore.get_paginator('list_groups')

        groups = []
        for page in paginator.paginate(IdentityStoreId=self.client.identitystore_id):
            for group in page['Groups']:
                groups.append(group)

                if not self.output.json_output:
                    descr = group.get('Description', '-')

                    # Check if created via SCIM or locally
                    cb = 'SCIM' if 'ExternalIds' in group else 'LOCAL'

                    print(f'Group: "{group["DisplayName"]}"  Description: "{descr}" ({cb})')

        if self.output.json_output:
            self.output.print_json(groups)


# --------------------------------------------------------------------------------------------------
# User Commands
# --------------------------------------------------------------------------------------------------

class DescribeUserCommand(BaseCommand):
    """Describe a user."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--user-id',
            help='User ID'
        )
        parser.add_argument(
            '--user-name',
            help='User name'
        )

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.user_id and not self.args.user_name:
            self.output.print_error('No user specified; use one of: --user-id, --user-name.')
            raise SystemExit(1)

        # Store what the user passed for the header
        user_input = self.args.user_name if self.args.user_name else self.args.user_id

        if self.args.user_id:
            user_id = self.args.user_id
        else:
            user_id = utils.get_user_id_by_name(self.client, self.args.user_name)
            if user_id is None:
                self.output.print_error(f'User "{self.args.user_name}" not found.')
                raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')
        response = identitystore.describe_user(
            IdentityStoreId=self.client.identitystore_id,
            UserId=user_id
        )
        response.pop('ResponseMetadata', None)

        if self.output.json_output:
            self.output.print_json(response)
        else:
            # Human-readable output with header
            print(f'User: "{user_input}":')
            print(f'- DisplayName: {response.get("DisplayName", "N/A")}')
            print(f'- UserName: {response.get("UserName", "N/A")}')
            print(f'- UserId: {response["UserId"]}')

            # Get first ExternalId if available
            external_ids = response.get('ExternalIds', [])
            if external_ids:
                external_id = external_ids[0].get('Id', 'N/A')
                print(f'- ExternalId: {external_id}')
            else:
                print('- ExternalId: N/A')

            # Get Title if available
            title = response.get('Title', 'N/A')
            print(f'- Title: {title}')


class CreateUsersCommand(BaseCommand):
    """Create users from a JSON file (bulk operation)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--user-file',
            required=True,
            help='Path to JSON file containing user list (file:///path/to/users.json)'
        )

    def execute(self) -> None:
        """Execute the command."""
        # Handle file:// prefix
        file_path = self.args.user_file
        if file_path.startswith('file://'):
            file_path = file_path[7:]

        user_list = load_user_list(file_path)
        identitystore = self.client.get_client('identitystore')

        for user_data in user_list:
            family_name = user_data['FamilyName']
            given_name = user_data['GivenName']
            email = user_data['Email']
            user_name = email

            try:
                response = identitystore.create_user(
                    IdentityStoreId=self.client.identitystore_id,
                    UserName=user_name,
                    Name={
                        'FamilyName': family_name,
                        'GivenName': given_name
                    },
                    DisplayName=f'{given_name} {family_name}',
                    Emails=[
                        {
                            'Value': email,
                            'Type': 'work',
                            'Primary': True
                        },
                    ]
                )
                print(f'Created user: "{user_name}" ("{given_name} {family_name}") with UserId: {response["UserId"]}')

            except identitystore.exceptions.ConflictException:
                print(f'User: "{user_name}" already exists')


class DeleteUsersCommand(BaseCommand):
    """Delete users from a JSON file (bulk operation)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--user-file',
            required=True,
            help='Path to JSON file containing user list (file:///path/to/users.json)'
        )

    def execute(self) -> None:
        """Execute the command."""
        # Handle file:// prefix
        file_path = self.args.user_file
        if file_path.startswith('file://'):
            file_path = file_path[7:]

        user_list = load_user_list(file_path)
        identitystore = self.client.get_client('identitystore')

        for user_data in user_list:
            email = user_data['Email']
            user_name = email

            user_id = utils.get_user_id_by_name(self.client, user_name)
            if user_id is None:
                print(f'User "{user_name}" not found.')
                continue

            identitystore.delete_user(
                IdentityStoreId=self.client.identitystore_id,
                UserId=user_id
            )
            print(f'User: "{user_name}" deleted.')


class GetUsersCommand(BaseCommand):
    """Get users from a JSON file (bulk operation)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--user-file',
            required=True,
            help='Path to JSON file containing user list (file:///path/to/users.json)'
        )

    def execute(self) -> None:
        """Execute the command."""
        # Handle file:// prefix
        file_path = self.args.user_file
        if file_path.startswith('file://'):
            file_path = file_path[7:]

        user_list = load_user_list(file_path)
        identitystore = self.client.get_client('identitystore')

        for user_data in user_list:
            email = user_data['Email']
            user_name = email

            user_id = utils.get_user_id_by_name(self.client, user_name)
            if user_id is None:
                print(f'User "{user_name}" not found.')
                continue

            response = identitystore.describe_user(
                IdentityStoreId=self.client.identitystore_id,
                UserId=user_id
            )
            print(f'Found user: "{user_name}" ("{response["DisplayName"]}") with UserId: {response["UserId"]}')


class ListUsersCommand(BaseCommand):
    """List all users."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        pass

    def execute(self) -> None:
        """Execute the command."""
        identitystore = self.client.get_client('identitystore')
        paginator = identitystore.get_paginator('list_users')

        users = []
        for page in paginator.paginate(IdentityStoreId=self.client.identitystore_id):
            for user in page['Users']:
                users.append(user)

                if not self.output.json_output:
                    title = user.get('Title', '-')
                    print(f'User: {user["UserName"]} ({user["DisplayName"]}) Title: {title}')

        if self.output.json_output:
            self.output.print_json(users)


# --------------------------------------------------------------------------------------------------
# Group Membership Commands
# --------------------------------------------------------------------------------------------------

class CreateGroupMembershipCommand(BaseCommand):
    """Create a group membership for a single user."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--user-name',
            required=True,
            help='User name'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        user_id = utils.get_user_id_by_name(self.client, self.args.user_name)
        if user_id is None:
            self.output.print_error(f'User "{self.args.user_name}" not found.')
            raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')

        try:
            response = identitystore.create_group_membership(
                IdentityStoreId=self.client.identitystore_id,
                GroupId=group_id,
                MemberId={'UserId': user_id}
            )

            if self.output.json_output:
                self.output.print_json(response)
            else:
                print(f'Added user "{self.args.user_name}" to group "{self.args.group_name}"')

        except identitystore.exceptions.ConflictException:
            print(f'User "{self.args.user_name}" is already a member of group "{self.args.group_name}"')


class CreateGroupMembershipsCommand(BaseCommand):
    """Create group memberships for users from a JSON file (bulk operation)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--user-file',
            required=True,
            help='Path to JSON file containing user list (file:///path/to/users.json)'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        # Handle file:// prefix
        file_path = self.args.user_file
        if file_path.startswith('file://'):
            file_path = file_path[7:]

        user_list = load_user_list(file_path)
        identitystore = self.client.get_client('identitystore')

        for user_data in user_list:
            email = user_data['Email']
            user_name = email

            user_id = utils.get_user_id_by_name(self.client, user_name)
            if user_id is None:
                print(f'User "{user_name}" not found.')
                continue

            try:
                response = identitystore.create_group_membership(
                    IdentityStoreId=self.client.identitystore_id,
                    GroupId=group_id,
                    MemberId={'UserId': user_id}
                )
                print(f'Added user "{user_name}" to group "{self.args.group_name}"')

            except identitystore.exceptions.ConflictException:
                print(f'User "{user_name}" is already a member of group "{self.args.group_name}"')


class GetGroupMembershipCommand(BaseCommand):
    """Get group membership for a single user."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--user-name',
            required=True,
            help='User name'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        user_id = utils.get_user_id_by_name(self.client, self.args.user_name)
        if user_id is None:
            self.output.print_error(f'User "{self.args.user_name}" not found.')
            raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')
        paginator = identitystore.get_paginator('list_group_memberships')

        found = False
        for page in paginator.paginate(
            IdentityStoreId=self.client.identitystore_id,
            GroupId=group_id
        ):
            for membership in page['GroupMemberships']:
                if membership['MemberId'].get('UserId') == user_id:
                    found = True
                    if self.output.json_output:
                        self.output.print_json(membership)
                    else:
                        print(f'User "{self.args.user_name}" is a member of group "{self.args.group_name}"')
                        print(f'MembershipId: {membership["MembershipId"]}')
                    break
            if found:
                break

        if not found:
            print(f'User "{self.args.user_name}" is not a member of group "{self.args.group_name}"')


class GetGroupMembershipsCommand(BaseCommand):
    """Get group memberships for users from a JSON file (bulk operation)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--user-file',
            required=True,
            help='Path to JSON file containing user list (file:///path/to/users.json)'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        # Handle file:// prefix
        file_path = self.args.user_file
        if file_path.startswith('file://'):
            file_path = file_path[7:]

        user_list = load_user_list(file_path)
        identitystore = self.client.get_client('identitystore')

        for user_data in user_list:
            email = user_data['Email']
            user_name = email

            user_id = utils.get_user_id_by_name(self.client, user_name)
            if user_id is None:
                print(f'User "{user_name}" not found.')
                continue

            paginator = identitystore.get_paginator('list_group_memberships')

            found = False
            for page in paginator.paginate(
                IdentityStoreId=self.client.identitystore_id,
                GroupId=group_id
            ):
                for membership in page['GroupMemberships']:
                    if membership['MemberId'].get('UserId') == user_id:
                        found = True
                        print(f'User "{user_name}" is a member of group "{self.args.group_name}"')
                        break
                if found:
                    break

            if not found:
                print(f'User "{user_name}" is not a member of group "{self.args.group_name}"')


class DeleteGroupMembershipCommand(BaseCommand):
    """Delete a group membership for a single user."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--user-name',
            required=True,
            help='User name'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        user_id = utils.get_user_id_by_name(self.client, self.args.user_name)
        if user_id is None:
            self.output.print_error(f'User "{self.args.user_name}" not found.')
            raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')
        paginator = identitystore.get_paginator('list_group_memberships')

        membership_id = None
        for page in paginator.paginate(
            IdentityStoreId=self.client.identitystore_id,
            GroupId=group_id
        ):
            for membership in page['GroupMemberships']:
                if membership['MemberId'].get('UserId') == user_id:
                    membership_id = membership['MembershipId']
                    break
            if membership_id:
                break

        if membership_id is None:
            print(f'User "{self.args.user_name}" is not a member of group "{self.args.group_name}"')
            return

        identitystore.delete_group_membership(
            IdentityStoreId=self.client.identitystore_id,
            MembershipId=membership_id
        )

        if not self.output.json_output:
            print(f'Removed user "{self.args.user_name}" from group "{self.args.group_name}"')


class DeleteGroupMembershipsCommand(BaseCommand):
    """Delete group memberships for users from a JSON file (bulk operation)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )
        parser.add_argument(
            '--user-file',
            required=True,
            help='Path to JSON file containing user list (file:///path/to/users.json)'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        # Handle file:// prefix
        file_path = self.args.user_file
        if file_path.startswith('file://'):
            file_path = file_path[7:]

        user_list = load_user_list(file_path)
        identitystore = self.client.get_client('identitystore')

        for user_data in user_list:
            email = user_data['Email']
            user_name = email

            user_id = utils.get_user_id_by_name(self.client, user_name)
            if user_id is None:
                print(f'User "{user_name}" not found.')
                continue

            paginator = identitystore.get_paginator('list_group_memberships')

            membership_id = None
            for page in paginator.paginate(
                IdentityStoreId=self.client.identitystore_id,
                GroupId=group_id
            ):
                for membership in page['GroupMemberships']:
                    if membership['MemberId'].get('UserId') == user_id:
                        membership_id = membership['MembershipId']
                        break
                if membership_id:
                    break

            if membership_id is None:
                print(f'User "{user_name}" is not a member of group "{self.args.group_name}"')
                continue

            identitystore.delete_group_membership(
                IdentityStoreId=self.client.identitystore_id,
                MembershipId=membership_id
            )
            print(f'Removed user "{user_name}" from group "{self.args.group_name}"')


class ListGroupMembershipsCommand(BaseCommand):
    """List all memberships for a group."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-name',
            required=True,
            help='Group name'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_id = utils.get_group_id_by_name(self.client, self.args.group_name)
        if group_id is None:
            self.output.print_error(f'Group "{self.args.group_name}" not found.')
            raise SystemExit(1)

        identitystore = self.client.get_client('identitystore')
        paginator = identitystore.get_paginator('list_group_memberships')

        memberships = []
        for page in paginator.paginate(
            IdentityStoreId=self.client.identitystore_id,
            GroupId=group_id
        ):
            for membership in page['GroupMemberships']:
                memberships.append(membership)

                if not self.output.json_output:
                    user_id = membership['MemberId'].get('UserId')
                    if user_id:
                        user_name = utils.get_user_name_by_id(self.client, user_id)
                        print(f'User: {user_name} (UserId: {user_id})')

        if self.output.json_output:
            self.output.print_json(memberships)


class ListAllGroupMembershipsForUserCommand(BaseCommand):
    """List all group memberships for a user."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--user-name',
            required=True,
            help='User name'
        )

    def execute(self) -> None:
        """Execute the command."""
        user_id = utils.get_user_id_by_name(self.client, self.args.user_name)
        if user_id is None:
            self.output.print_error(f'User "{self.args.user_name}" not found.')
            raise SystemExit(1)

        groups = utils.get_group_memberships_for_user(self.client, user_id)

        if self.output.json_output:
            self.output.print_json(groups)
        else:
            for group in groups:
                print(f'Group: {group["DisplayName"]} (GroupId: {group["GroupId"]})')
