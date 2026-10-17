"""Account assignment commands for AWS SSO Admin Tools."""

import json
from argparse import ArgumentParser

from .base import BaseCommand
from .. import utils


# --------------------------------------------------------------------------------------------------
# Assignment CRUD Commands
# --------------------------------------------------------------------------------------------------

class CreateAccountAssignmentCommand(BaseCommand):
    """Create an account assignment."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--acct-id', required=True, help='Account ID')
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--group-name', help='Group name')

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.user_name and not self.args.group_name:
            self.output.print_error('Specify either --user-name or --group-name.')
            raise SystemExit(1)

        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        if self.args.user_name:
            principal_type = 'USER'
            principal_id = utils.get_user_id_by_name(self.client, self.args.user_name)
            if principal_id is None:
                self.output.print_error(f'User "{self.args.user_name}" not found.')
                raise SystemExit(1)
        else:
            principal_type = 'GROUP'
            principal_id = utils.get_group_id_by_name(self.client, self.args.group_name)
            if principal_id is None:
                self.output.print_error(f'Group "{self.args.group_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.create_account_assignment(
            InstanceArn=self.client.instance_arn,
            TargetId=self.args.acct_id,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=ps_arn,
            PrincipalType=principal_type,
            PrincipalId=principal_id
        )

        # Output full API response structure with top-level key
        self.output.print_json({
            'AccountAssignmentCreationStatus': response['AccountAssignmentCreationStatus']
        })


class DeleteAccountAssignmentCommand(BaseCommand):
    """Delete an account assignment."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--acct-id', required=True, help='Account ID')
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--group-name', help='Group name')

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.user_name and not self.args.group_name:
            self.output.print_error('Specify either --user-name or --group-name.')
            raise SystemExit(1)

        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        if self.args.user_name:
            principal_type = 'USER'
            principal_id = utils.get_user_id_by_name(self.client, self.args.user_name)
            if principal_id is None:
                self.output.print_error(f'User "{self.args.user_name}" not found.')
                raise SystemExit(1)
        else:
            principal_type = 'GROUP'
            principal_id = utils.get_group_id_by_name(self.client, self.args.group_name)
            if principal_id is None:
                self.output.print_error(f'Group "{self.args.group_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.delete_account_assignment(
            InstanceArn=self.client.instance_arn,
            TargetId=self.args.acct_id,
            TargetType='AWS_ACCOUNT',
            PermissionSetArn=ps_arn,
            PrincipalType=principal_type,
            PrincipalId=principal_id
        )

        # Output full API response structure with top-level key
        self.output.print_json({
            'AccountAssignmentDeletionStatus': response['AccountAssignmentDeletionStatus']
        })


# --------------------------------------------------------------------------------------------------
# Listing Commands
# --------------------------------------------------------------------------------------------------

class ListAssignedPrincipalsForPsInAccountCommand(BaseCommand):
    """List assigned principals for a permission set in an account."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', help='Permission set name')
        parser.add_argument('--ps-arn', help='Permission set ARN')
        parser.add_argument('--acct-id', required=True, help='Account ID')

    def execute(self) -> None:
        """Execute the command."""
        # Validate that exactly one of --ps-name or --ps-arn is provided
        if not self.args.ps_name and not self.args.ps_arn:
            self.output.print_error('Specify either --ps-name or --ps-arn.')
            raise SystemExit(1)

        if self.args.ps_name and self.args.ps_arn:
            self.output.print_error('Specify either --ps-name or --ps-arn, not both.')
            raise SystemExit(1)

        # Determine PS ARN and display name
        if self.args.ps_name:
            ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
            if ps_arn is None:
                self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
                raise SystemExit(1)
            ps_display_name = self.args.ps_name
        else:
            ps_arn = self.args.ps_arn
            # Extract name from ARN: arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx
            ps_display_name = ps_arn.split('/')[-1] if '/' in ps_arn else ps_arn

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_account_assignments')

        assignments = []

        # Print header
        if not self.output.json_output:
            print(f'Listing assigned principals for PS "{ps_display_name}" in account: {self.args.acct_id}...')

        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            AccountId=self.args.acct_id,
            PermissionSetArn=ps_arn
        ):
            for item in page['AccountAssignments']:
                assignments.append(item)

                if not self.output.json_output:
                    if item['PrincipalType'] == 'USER':
                        pn = utils.get_user_name_by_id(self.client, item['PrincipalId'])
                        print(f'* USER: {pn or item["PrincipalId"]}')
                    elif item['PrincipalType'] == 'GROUP':
                        pn = utils.get_group_name_by_id(self.client, item['PrincipalId'])
                        print(f'* GROUP: {pn or item["PrincipalId"]}')

        if self.output.json_output:
            self.output.print_json(assignments)


class ListAccountsForProvisionedPsCommand(BaseCommand):
    """List accounts for a provisioned permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', help='Permission set name')
        parser.add_argument('--ps-arn', help='Permission set ARN')
        parser.add_argument('--show-acct-names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names (faster)')

    def execute(self) -> None:
        """Execute the command."""
        # Validate that exactly one of --ps-name or --ps-arn is provided
        if not self.args.ps_name and not self.args.ps_arn:
            self.output.print_error('Specify either --ps-name or --ps-arn.')
            raise SystemExit(1)

        if self.args.ps_name and self.args.ps_arn:
            self.output.print_error('Specify either --ps-name or --ps-arn, not both.')
            raise SystemExit(1)

        # Determine PS ARN and display name
        if self.args.ps_name:
            ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
            if ps_arn is None:
                self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
                raise SystemExit(1)
            ps_display_name = self.args.ps_name
        else:
            ps_arn = self.args.ps_arn
            # Extract name from ARN: arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx
            ps_display_name = ps_arn.split('/')[-1] if '/' in ps_arn else ps_arn

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_accounts_for_provisioned_permission_set')

        account_ids = []
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        ):
            account_ids.extend(page['AccountIds'])

        if self.output.json_output:
            self.output.print_json(account_ids)
        else:
            # Print header
            print(f'Listing assigned accounts for PS "{ps_display_name}"...')

            for acct_id in account_ids:
                if self.args.show_acct_names:
                    acct_name = utils.get_acct_name_by_id(self.client, acct_id)
                    print(f'- {acct_id} -- ("{acct_name or acct_id}")')
                else:
                    print(f'- {acct_id}')


class ListAllAcctAssignmentsForProvisionedPsCommand(BaseCommand):
    """List all account assignments for a provisioned permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', help='Permission set name')
        parser.add_argument('--ps-arn', help='Permission set ARN')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names (faster)')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')

    def execute(self) -> None:
        """Execute the command."""
        # Validate that exactly one of --ps-name or --ps-arn is provided
        if not self.args.ps_name and not self.args.ps_arn:
            self.output.print_error('Specify either --ps-name or --ps-arn.')
            raise SystemExit(1)

        if self.args.ps_name and self.args.ps_arn:
            self.output.print_error('Specify either --ps-name or --ps-arn, not both.')
            raise SystemExit(1)

        # Determine PS ARN and display name
        if self.args.ps_name:
            ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
            if ps_arn is None:
                self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
                raise SystemExit(1)
            ps_display_name = self.args.ps_name
        else:
            ps_arn = self.args.ps_arn
            # Extract PS ID from ARN for display
            ps_display_name = ps_arn.split('/')[-1] if '/' in ps_arn else ps_arn

        sso_admin = self.client.get_client('sso-admin')

        # Get accounts where PS is provisioned
        paginator = sso_admin.get_paginator('list_accounts_for_provisioned_permission_set')
        account_ids = []
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        ):
            account_ids.extend(page['AccountIds'])

        all_assignments = []

        # Print header
        if not self.output.json_output:
            print(f'Listing assigned accounts for PS "{ps_display_name}"...')

            # Optionally show assume-role targets
            if self.args.show_target_arns:
                target_arns = utils.get_target_arns_for_ps(self.client, ps_arn)
                if target_arns:
                    print('- Assume-role targets for this PS:')
                    for arn in sorted(target_arns):
                        print('  * %s' % arn)

        for acct_id in sorted(account_ids):
            paginator = sso_admin.get_paginator('list_account_assignments')

            # Track if we've printed the account header for this account
            account_header_printed = False

            for page in paginator.paginate(
                InstanceArn=self.client.instance_arn,
                AccountId=acct_id,
                PermissionSetArn=ps_arn
            ):
                for item in page['AccountAssignments']:
                    all_assignments.append(item)

                    if not self.output.json_output:
                        # Print account header on first assignment for this account
                        if not account_header_printed:
                            if self.args.show_acct_names:
                                acct_name = utils.get_acct_name_by_id(self.client, acct_id)
                                print(f'ACCT: {acct_id} --- ("{acct_name or acct_id}")...')
                            else:
                                print(f'ACCT: {acct_id}...')
                            account_header_printed = True

                        # Print principal
                        if self.args.show_principal_names:
                            if item['PrincipalType'] == 'USER':
                                pn = utils.get_user_name_by_id(self.client, item['PrincipalId'])
                                print(f'* USER: {pn or item["PrincipalId"]}')
                            elif item['PrincipalType'] == 'GROUP':
                                pn = utils.get_group_name_by_id(self.client, item['PrincipalId'])
                                print(f'* GROUP: {pn or item["PrincipalId"]}')
                        else:
                            # Just show principal type and ID
                            print(f'* {item["PrincipalType"]}: {item["PrincipalId"]}')

        if self.output.json_output:
            self.output.print_json(all_assignments)


# --------------------------------------------------------------------------------------------------
# Principal View Commands
# --------------------------------------------------------------------------------------------------

class ListAllAcctAssignmentsForUserCommand(BaseCommand):
    """List all account assignments for a user (accepts any principal options)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--user-id', help='User ID')
        parser.add_argument('--group-name', help='Group name')
        parser.add_argument('--group-id', help='Group ID')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')
        parser.add_argument('--compact', dest='compact', action='store_true', default=True,
                          help='Show compact output (default)')
        parser.add_argument('--no-compact', dest='compact', action='store_false',
                          help='Show expanded output')

    def execute(self) -> None:
        """Execute the command - delegates to shared implementation."""
        _execute_list_all_acct_assignments_for_principal(self)


class ListAllAcctAssignmentsForGroupCommand(BaseCommand):
    """List all account assignments for a group (accepts any principal options)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--user-id', help='User ID')
        parser.add_argument('--group-name', help='Group name')
        parser.add_argument('--group-id', help='Group ID')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')
        parser.add_argument('--compact', dest='compact', action='store_true', default=True,
                          help='Show compact output (default)')
        parser.add_argument('--no-compact', dest='compact', action='store_false',
                          help='Show expanded output')

    def execute(self) -> None:
        """Execute the command - delegates to shared implementation."""
        _execute_list_all_acct_assignments_for_principal(self)


class ListAllAcctAssignmentsForPrincipalCommand(BaseCommand):
    """List all account assignments for a principal (user or group - accepts any principal options)."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--user-id', help='User ID')
        parser.add_argument('--group-name', help='Group name')
        parser.add_argument('--group-id', help='Group ID')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')
        parser.add_argument('--compact', dest='compact', action='store_true', default=True,
                          help='Show compact output (default)')
        parser.add_argument('--no-compact', dest='compact', action='store_false',
                          help='Show expanded output')

    def execute(self) -> None:
        """Execute the command - delegates to shared implementation."""
        _execute_list_all_acct_assignments_for_principal(self)


# --------------------------------------------------------------------------------------------------
# Shared implementation for principal-based commands
# --------------------------------------------------------------------------------------------------

def _execute_list_all_acct_assignments_for_principal(cmd: BaseCommand) -> None:
    """
    Shared implementation for list-all-acct-assignments-for-{user,group,principal} commands.
    These three commands are aliases and accept all principal options.
    """
    # Determine principal from any of the four possible options
    principal_id = None
    principal_type = None
    principal_display_name = None

    if cmd.args.user_id:
        principal_id = cmd.args.user_id
        principal_type = 'USER'
        if cmd.args.show_principal_names:
            principal_display_name = utils.get_user_name_by_id(cmd.client, principal_id)
            if principal_display_name is None:
                cmd.output.print_error(f'User with ID "{principal_id}" not found.')
                raise SystemExit(1)
        else:
            principal_display_name = principal_id
    elif cmd.args.user_name:
        principal_id = utils.get_user_id_by_name(cmd.client, cmd.args.user_name)
        if principal_id is None:
            cmd.output.print_error(f'User "{cmd.args.user_name}" not found.')
            raise SystemExit(1)
        principal_type = 'USER'
        principal_display_name = cmd.args.user_name
    elif cmd.args.group_id:
        principal_id = cmd.args.group_id
        principal_type = 'GROUP'
        if cmd.args.show_principal_names:
            principal_display_name = utils.get_group_name_by_id(cmd.client, principal_id)
            if principal_display_name is None:
                cmd.output.print_error(f'Group with ID "{principal_id}" not found.')
                raise SystemExit(1)
        else:
            principal_display_name = principal_id
    elif cmd.args.group_name:
        principal_id = utils.get_group_id_by_name(cmd.client, cmd.args.group_name)
        if principal_id is None:
            cmd.output.print_error(f'Group "{cmd.args.group_name}" not found.')
            raise SystemExit(1)
        principal_type = 'GROUP'
        principal_display_name = cmd.args.group_name
    else:
        cmd.output.print_error('Specify one of: --user-name, --user-id, --group-name, --group-id.')
        raise SystemExit(1)

    sso_admin = cmd.client.get_client('sso-admin')

    # Build assignment structure: acct_id -> ps_name -> (ps_desc, [principals], [target_arns])
    assignments = {}

    # Get all assignments for this principal
    paginator = sso_admin.get_paginator('list_account_assignments_for_principal')
    for page in paginator.paginate(
        InstanceArn=cmd.client.instance_arn,
        PrincipalId=principal_id,
        PrincipalType=principal_type
    ):
        for acct_asst in page['AccountAssignments']:
            # Note: These refer to the assignment returned, not the principal we queried
            acct_id = acct_asst['AccountId']
            ps_arn = acct_asst['PermissionSetArn']
            asst_principal_id = acct_asst['PrincipalId']
            asst_principal_type = acct_asst['PrincipalType']

            # Get PS details
            ps = sso_admin.describe_permission_set(
                InstanceArn=cmd.client.instance_arn,
                PermissionSetArn=ps_arn
            )
            ps_name = ps['PermissionSet']['Name']
            ps_desc = ps['PermissionSet'].get('Description', '-')

            # Get principal name if requested
            asst_principal_name = ''
            if cmd.args.show_principal_names:
                if asst_principal_type == 'USER':
                    asst_principal_name = utils.get_user_name_by_id(cmd.client, asst_principal_id)
                elif asst_principal_type == 'GROUP':
                    asst_principal_name = utils.get_group_name_by_id(cmd.client, asst_principal_id)

                if asst_principal_name is None:
                    raise SystemExit(f'Principal with id "{asst_principal_id}" not found.')

            # Get target ARNs if requested
            target_arns = []
            if cmd.args.show_target_arns:
                target_arns = sorted(utils.get_target_arns_for_ps(cmd.client, ps_arn))

            # Build nested dict structure: acct -> ps -> (desc, principals, target_arns)
            if acct_id not in assignments:
                assignments[acct_id] = {}

            if ps_name not in assignments[acct_id]:
                assignments[acct_id][ps_name] = ('', [], [])

            # Append principal to list
            assignments[acct_id][ps_name][1].append((asst_principal_type, asst_principal_name))

            # Update PS description and target ARNs
            assignments[acct_id][ps_name] = (
                ps_desc, assignments[acct_id][ps_name][1], target_arns
            )

    if cmd.output.json_output:
        # For JSON output, flatten structure
        json_assignments = []
        for acct_id, ps_dict in assignments.items():
            for ps_name, (ps_desc, principals, target_arns) in ps_dict.items():
                for principal_type, principal_name in principals:
                    json_assignments.append({
                        'AccountId': acct_id,
                        'PermissionSetName': ps_name,
                        'PrincipalType': principal_type,
                        'PrincipalName': principal_name
                    })
        cmd.output.print_json(json_assignments)
        return

    # Human-readable output
    print(f'Listing all Account assignments for "{principal_display_name}"...')

    # Print assignments grouped by account, then by PS
    for acct_id in sorted(assignments.keys()):
        # Print account header
        if cmd.args.show_acct_names:
            acct_name = utils.get_acct_name_by_id(cmd.client, acct_id)
            print(f'- Assigned access in account "{acct_id}" --- ("{acct_name}")...')
        else:
            print(f'- Assigned access in account "{acct_id}"...')

        # Print PS assignments within this account
        for ps_name in sorted(assignments[acct_id].keys(), key=lambda x: x.lower()):
            ps_desc, principal_list, target_arns = assignments[acct_id][ps_name]

            # Build PS description string
            ps_desc_str = ''
            if cmd.args.show_ps_desc:
                ps_desc_str = f' ("{ps_desc}")'

            # Build principal list string for compact mode
            principal_list_str = ''
            if cmd.args.show_principal_names and cmd.args.compact:
                principal_list_str = ' ' + str([p[1] for p in principal_list])

            # Print PS line
            print(f'  * {ps_name}{ps_desc_str}{principal_list_str}')

            # Print principals in expanded mode
            if cmd.args.show_principal_names and not cmd.args.compact:
                for principal_type, principal_name in principal_list:
                    print(f'    * {principal_type}: {principal_name}')

            # Print target ARNs
            if target_arns:
                for arn in target_arns:
                    print(f'    - {arn}')


# --------------------------------------------------------------------------------------------------
# Organization View Commands (Simplified)
# --------------------------------------------------------------------------------------------------

class ListAllAcctAssignmentsForPsInOrgCommand(BaseCommand):
    """List all account assignments for all permission sets in the organization."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')

        # Print header
        if not self.output.json_output:
            print('Listing all Permission Set assignments in the Organization...')

        # Collect all permission sets
        paginator = sso_admin.get_paginator('list_permission_sets')
        ps_list = []

        for page in paginator.paginate(InstanceArn=self.client.instance_arn):
            for ps_arn in page['PermissionSets']:
                ps_desc_obj = sso_admin.describe_permission_set(
                    InstanceArn=self.client.instance_arn,
                    PermissionSetArn=ps_arn
                )
                ps = ps_desc_obj['PermissionSet']
                ps_name = ps['Name']
                ps_dura = ps['SessionDuration']
                ps_desc = ps.get('Description', '-')

                ps_list.append((ps_name, ps_arn, ps_desc, ps_dura))

                # Show progress indicator (overwritten on each iteration)
                if not self.output.json_output:
                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

        if self.output.json_output:
            # For JSON output, collect all assignments
            all_assignments = []
            for ps_name, ps_arn, ps_desc, ps_dura in ps_list:
                # Get accounts for this PS
                acct_paginator = sso_admin.get_paginator('list_accounts_for_provisioned_permission_set')
                for acct_page in acct_paginator.paginate(
                    InstanceArn=self.client.instance_arn,
                    PermissionSetArn=ps_arn
                ):
                    for acct_id in acct_page['AccountIds']:
                        # Get assignments for this PS in this account
                        asst_paginator = sso_admin.get_paginator('list_account_assignments')
                        for asst_page in asst_paginator.paginate(
                            InstanceArn=self.client.instance_arn,
                            AccountId=acct_id,
                            PermissionSetArn=ps_arn
                        ):
                            for item in asst_page['AccountAssignments']:
                                all_assignments.append({
                                    'PermissionSetName': ps_name,
                                    'PermissionSetArn': ps_arn,
                                    'AccountId': acct_id,
                                    'PrincipalType': item['PrincipalType'],
                                    'PrincipalId': item['PrincipalId']
                                })
            self.output.print_json(all_assignments)
            return

        # Human-readable output - iterate through sorted PS list
        for ps_name, ps_arn, ps_desc, ps_dura in sorted(ps_list, key=lambda x: x[0].lower()):

            # Print PS header
            if self.args.show_ps_desc:
                print('Listing assignments for PS "%s": ("%s") (%s)...' % (ps_name, ps_desc, ps_dura))
            else:
                print('Listing assignments for PS: "%s"...' % ps_name)

            # Optionally show assume-role targets
            if self.args.show_target_arns:
                target_arns = utils.get_target_arns_for_ps(self.client, ps_arn)
                if target_arns:
                    print('- Assume-role targets for this PS:')
                    for arn in sorted(target_arns):
                        print('  * %s' % arn)

            # Get accounts where this PS is provisioned
            acct_paginator = sso_admin.get_paginator('list_accounts_for_provisioned_permission_set')
            for acct_page in acct_paginator.paginate(
                InstanceArn=self.client.instance_arn,
                PermissionSetArn=ps_arn
            ):
                for acct_id in acct_page['AccountIds']:
                    # Print account header
                    if self.args.show_acct_names:
                        acct_name = utils.get_acct_name_by_id(self.client, acct_id)
                        print('- ACCT: %s --- ("%s")...' % (acct_id, acct_name))
                    else:
                        print('- ACCT: %s...' % acct_id)

                    # List principals assigned to this PS in this account
                    if self.args.show_principal_names:
                        asst_paginator = sso_admin.get_paginator('list_account_assignments')
                        for asst_page in asst_paginator.paginate(
                            InstanceArn=self.client.instance_arn,
                            AccountId=acct_id,
                            PermissionSetArn=ps_arn
                        ):
                            for item in asst_page['AccountAssignments']:
                                if item['PrincipalType'] == 'USER':
                                    pn = utils.get_user_name_by_id(self.client, item['PrincipalId'])
                                    print('  * USER: %s' % (pn or item['PrincipalId']))
                                elif item['PrincipalType'] == 'GROUP':
                                    pn = utils.get_group_name_by_id(self.client, item['PrincipalId'])
                                    print('  * GROUP: %s' % (pn or item['PrincipalId']))


class ListAllPsInOrgCommand(BaseCommand):
    """List all permission sets in the organization."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_permission_sets')

        ps_list = []

        # Print header
        if not self.output.json_output:
            print('Listing all Permission Sets in the Organization...')

        for page in paginator.paginate(InstanceArn=self.client.instance_arn):
            for ps_arn in page['PermissionSets']:
                ps_desc = utils.get_permission_set_desc_by_arn(self.client, ps_arn)
                if ps_desc:
                    ps_list.append(ps_desc)
                    # Show progress indicator (overwritten on each iteration)
                    if not self.output.json_output:
                        print('Checking permission set "%s"...' % ps_desc['Name'], ' '*30, end='\r')

        if self.output.json_output:
            self.output.print_json(ps_list)
            return

        # Human-readable output - sort by name
        for ps in sorted(ps_list, key=lambda x: x['Name'].lower()):
            ps_name = ps['Name']
            ps_desc = ps.get('Description', '-')
            ps_dura = ps['SessionDuration']

            # Print PS info
            if self.args.show_ps_desc:
                print('PS: "%s"  Description: "%s" (%s)' % (ps_name, ps_desc, ps_dura))
            else:
                print('PS: "%s"' % ps_name)

            # Optionally show assume-role targets
            if self.args.show_target_arns:
                target_arns = utils.get_target_arns_for_ps(self.client, ps['PermissionSetArn'])
                if target_arns:
                    print('- Assume-role targets for this PS:')
                    for arn in sorted(target_arns):
                        print('  * %s' % arn)


# --------------------------------------------------------------------------------------------------
# Account View Commands
# --------------------------------------------------------------------------------------------------

class ListPsProvisionedToAccountCommand(BaseCommand):
    """List permission sets provisioned to an account."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--acct-id', required=True, help='Account ID')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')
        parser.add_argument('--compact', dest='compact', action='store_true', default=True,
                          help='Show compact output (default)')
        parser.add_argument('--no-compact', '--expand', dest='compact', action='store_false',
                          help='Show expanded output')

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_permission_sets_provisioned_to_account')

        ps_list = []
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            AccountId=self.args.acct_id
        ):
            for ps_arn in page['PermissionSets']:
                # Get PS details
                ps_desc_obj = sso_admin.describe_permission_set(
                    InstanceArn=self.client.instance_arn,
                    PermissionSetArn=ps_arn
                )
                ps = ps_desc_obj['PermissionSet']
                ps_name = ps['Name']
                ps_desc = ps.get('Description', '-')
                ps_dura = ps['SessionDuration']

                ps_list.append((ps_name, ps_arn, ps_desc, ps_dura))

                # Show progress indicator (overwritten on each iteration)
                if not self.output.json_output:
                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

        if self.output.json_output:
            # Return just the ARNs for JSON output
            self.output.print_json([ps_arn for _, ps_arn, _, _ in ps_list])
            return

        # Get account name for header if requested
        acct_display = self.args.acct_id
        if self.args.show_acct_names:
            acct_name = utils.get_acct_name_by_id(self.client, self.args.acct_id)
            if acct_name:
                acct_display = f'{self.args.acct_id} -- ("{acct_name}")'

        print(f'Listing Permission Sets provisioned to account: {acct_display}...')

        # Display PS in sorted order
        for ps_name, ps_arn, ps_desc, ps_dura in sorted(ps_list, key=lambda x: x[0].lower()):

            # Print PS info based on compact vs expanded mode
            if self.args.compact:
                if self.args.show_ps_desc:
                    print('- PS: "%s"  Description: "%s" (%s)' % (ps_name, ps_desc, ps_dura))
                else:
                    print('- PS: "%s"' % ps_name)
            else:
                # Expanded mode - each item on its own line
                print('- PS: "%s"' % ps_name)
                if self.args.show_ps_desc:
                    print('  Description: "%s"' % ps_desc)
                    print('  Duration: %s' % ps_dura)

            # Optionally show assume-role targets
            if self.args.show_target_arns:
                target_arns = utils.get_target_arns_for_ps(self.client, ps_arn)
                if target_arns:
                    print('  - Assume-role targets for this PS:')
                    for arn in sorted(target_arns):
                        print('    * %s' % arn)


class ListAllPsAssignmentsInAccountCommand(BaseCommand):
    """List all permission set assignments in an account."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--acct-id', required=True, help='Account ID')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')

        # Get account name for header if requested
        acct_display = self.args.acct_id
        if self.args.show_acct_names:
            acct_name = utils.get_acct_name_by_id(self.client, self.args.acct_id)
            if acct_name:
                acct_display = f'{self.args.acct_id} -- ("{acct_name}")'

        if not self.output.json_output:
            print(f'Listing all PS assignments in account: {acct_display}...')

        # Get all PS provisioned to account
        paginator = sso_admin.get_paginator('list_permission_sets_provisioned_to_account')
        ps_list = []
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            AccountId=self.args.acct_id
        ):
            for ps_arn in page['PermissionSets']:
                # Get PS details
                ps_desc_obj = sso_admin.describe_permission_set(
                    InstanceArn=self.client.instance_arn,
                    PermissionSetArn=ps_arn
                )
                ps = ps_desc_obj['PermissionSet']
                ps_name = ps['Name']
                ps_dura = ps['SessionDuration']
                ps_desc = ps.get('Description', '-')

                ps_list.append((ps_name, ps_arn, ps_dura, ps_desc))

                # Show progress indicator (overwritten on each iteration)
                if not self.output.json_output:
                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

        # Collect all assignments for later display or JSON output
        all_assignments = []
        for ps_name, ps_arn, ps_dura, ps_desc in ps_list:
            asst_paginator = sso_admin.get_paginator('list_account_assignments')
            for page in asst_paginator.paginate(
                InstanceArn=self.client.instance_arn,
                AccountId=self.args.acct_id,
                PermissionSetArn=ps_arn
            ):
                for item in page['AccountAssignments']:
                    all_assignments.append({
                        'PermissionSetName': ps_name,
                        'PermissionSetArn': ps_arn,
                        'PrincipalType': item['PrincipalType'],
                        'PrincipalId': item['PrincipalId']
                    })

        if self.output.json_output:
            self.output.print_json(all_assignments)
            return

        # Human-readable output - display by PS (sorted by name)
        for ps_name, ps_arn, ps_dura, ps_desc in sorted(ps_list, key=lambda x: x[0].lower()):

            # Print PS header with dash bullet
            if self.args.show_ps_desc:
                print('- PS: "%s"  Description: "%s" (%s)' % (ps_name, ps_desc, ps_dura))
            else:
                print('- PS: "%s"' % ps_name)

            # List principals for this PS (before target ARNs to match legacy order)
            if self.args.show_principal_names:
                # Get assignments for this specific PS
                for item in all_assignments:
                    if item['PermissionSetName'] == ps_name:
                        if item['PrincipalType'] == 'USER':
                            pn = utils.get_user_name_by_id(self.client, item['PrincipalId'])
                            print('  * USER: %s' % (pn or item['PrincipalId']))
                        elif item['PrincipalType'] == 'GROUP':
                            pn = utils.get_group_name_by_id(self.client, item['PrincipalId'])
                            print('  * GROUP: %s' % (pn or item['PrincipalId']))

            # Optionally show assume-role targets (after principals)
            if self.args.show_target_arns:
                target_arns = utils.get_target_arns_for_ps(self.client, ps_arn)
                if target_arns:
                    print('  - Assume-role targets for this PS:')
                    for arn in sorted(target_arns):
                        print('    * %s' % arn)

        if self.output.json_output:
            self.output.print_json(all_assignments)


class ListAllPsAssignmentsInOuCommand(BaseCommand):
    """List all permission set assignments in an OU."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ou-name', required=True, help='OU name')
        parser.add_argument('--show-acct-names', dest='show_acct_names', action='store_true', default=True,
                          help='Show account names (default)')
        parser.add_argument('--no-show-acct-names', dest='show_acct_names', action='store_false',
                          help='Do not show account names')
        parser.add_argument('--show-principal-names', dest='show_principal_names', action='store_true', default=True,
                          help='Show user/group names (default)')
        parser.add_argument('--no-show-principal-names', dest='show_principal_names', action='store_false',
                          help='Do not show user/group names')
        parser.add_argument('--show-ps-desc', dest='show_ps_desc', action='store_true', default=True,
                          help='Show permission set descriptions (default)')
        parser.add_argument('--no-show-ps-desc', dest='show_ps_desc', action='store_false',
                          help='Do not show permission set descriptions')
        parser.add_argument('--show-target-arns', dest='show_target_arns', action='store_true', default=False,
                          help='Show assume-role target ARNs')
        parser.add_argument('--no-show-target-arns', dest='show_target_arns', action='store_false',
                          help='Do not show assume-role target ARNs (default)')

    def execute(self) -> None:
        """Execute the command."""
        # Get OU ID from name
        ou_id = utils.get_ou_id_by_name(self.client, self.args.ou_name)
        if ou_id is None:
            self.output.print_error(f'Organizational Unit "{self.args.ou_name}" not found.')
            raise SystemExit(1)

        if not self.output.json_output:
            print(f'Listing all Permission Set assignments in OU: {self.args.ou_name}...')

        organizations = self.client.get_client('organizations')
        sso_admin = self.client.get_client('sso-admin')

        # Get all accounts in this OU
        acct_list = []
        paginator = organizations.get_paginator('list_accounts_for_parent')
        for page in paginator.paginate(ParentId=ou_id):
            for acct in page['Accounts']:
                acct_list.append((acct['Id'], acct['Name']))

        if self.output.json_output:
            # Collect all assignments for JSON output
            all_assignments = []
            for acct_id, acct_name in acct_list:
                # Get PS provisioned to this account
                ps_paginator = sso_admin.get_paginator('list_permission_sets_provisioned_to_account')
                for ps_page in ps_paginator.paginate(
                    InstanceArn=self.client.instance_arn,
                    AccountId=acct_id
                ):
                    for ps_arn in ps_page['PermissionSets']:
                        # Get PS details
                        ps_desc_obj = sso_admin.describe_permission_set(
                            InstanceArn=self.client.instance_arn,
                            PermissionSetArn=ps_arn
                        )
                        ps_name = ps_desc_obj['PermissionSet']['Name']

                        # Get assignments
                        asst_paginator = sso_admin.get_paginator('list_account_assignments')
                        for asst_page in asst_paginator.paginate(
                            InstanceArn=self.client.instance_arn,
                            AccountId=acct_id,
                            PermissionSetArn=ps_arn
                        ):
                            for item in asst_page['AccountAssignments']:
                                all_assignments.append({
                                    'OuName': self.args.ou_name,
                                    'AccountId': acct_id,
                                    'AccountName': acct_name,
                                    'PermissionSetName': ps_name,
                                    'PermissionSetArn': ps_arn,
                                    'PrincipalType': item['PrincipalType'],
                                    'PrincipalId': item['PrincipalId']
                                })
            self.output.print_json(all_assignments)
            return

        # Human-readable output - sort accounts by name or ID
        sort_key = 1 if self.args.show_acct_names else 0
        for acct_id, acct_name in sorted(acct_list, key=lambda x: x[sort_key].lower()):

            # Print account header
            if self.args.show_acct_names:
                print(f'Listing all Permission Set assignments in account: {acct_id} -- ("{acct_name}")...')
            else:
                print(f'Listing all Permission Set assignments in account: {acct_id}...')

            # Get PS provisioned to this account
            ps_list = []
            ps_paginator = sso_admin.get_paginator('list_permission_sets_provisioned_to_account')
            for ps_page in ps_paginator.paginate(
                InstanceArn=self.client.instance_arn,
                AccountId=acct_id
            ):
                for ps_arn in ps_page['PermissionSets']:
                    # Get PS details
                    ps_desc_obj = sso_admin.describe_permission_set(
                        InstanceArn=self.client.instance_arn,
                        PermissionSetArn=ps_arn
                    )
                    ps = ps_desc_obj['PermissionSet']
                    ps_name = ps['Name']
                    ps_dura = ps['SessionDuration']
                    ps_desc = ps.get('Description', '-')

                    ps_list.append((ps_name, ps_arn, ps_dura, ps_desc))

            # Display PS in sorted order
            for ps_name, ps_arn, ps_dura, ps_desc in sorted(ps_list, key=lambda x: x[0].lower()):

                # Print PS info with dash bullet
                if self.args.show_ps_desc:
                    print('- PS: "%s"  Description: "%s" (%s)' % (ps_name, ps_desc, ps_dura))
                else:
                    print('- PS: "%s"' % ps_name)

                # Optionally show assume-role targets (indented by 2 more spaces)
                if self.args.show_target_arns:
                    target_arns = utils.get_target_arns_for_ps(self.client, ps_arn)
                    if target_arns:
                        print('  - Assume-role targets for this PS:')
                        for arn in sorted(target_arns):
                            print('    * %s' % arn)

                # List principals if requested (indented by 2 spaces)
                if self.args.show_principal_names:
                    asst_paginator = sso_admin.get_paginator('list_account_assignments')
                    for asst_page in asst_paginator.paginate(
                        InstanceArn=self.client.instance_arn,
                        AccountId=acct_id,
                        PermissionSetArn=ps_arn
                    ):
                        for item in asst_page['AccountAssignments']:
                            if item['PrincipalType'] == 'USER':
                                pn = utils.get_user_name_by_id(self.client, item['PrincipalId'])
                                print('  * USER: %s' % (pn or item['PrincipalId']))
                            elif item['PrincipalType'] == 'GROUP':
                                pn = utils.get_group_name_by_id(self.client, item['PrincipalId'])
                                print('  * GROUP: %s' % (pn or item['PrincipalId']))


# --------------------------------------------------------------------------------------------------
# Utility Commands
# --------------------------------------------------------------------------------------------------

class DescribeAccountCommand(BaseCommand):
    """Describe an account."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--acct-id', help='Account ID')
        parser.add_argument('--acct-name', help='Account name')

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.acct_id and not self.args.acct_name:
            self.output.print_error('Specify either --acct-id or --acct-name.')
            raise SystemExit(1)

        if self.args.acct_id:
            acct = utils.get_acct_desc_by_id(self.client, self.args.acct_id)
        else:
            acct = utils.get_acct_desc_by_name(self.client, self.args.acct_name)

        if acct is None:
            acct_identifier = self.args.acct_id or self.args.acct_name
            self.output.print_error(f'Account "{acct_identifier}" not found.')
            raise SystemExit(1)

        # Get parent OU information
        try:
            parent_ou = utils.get_account_parent_ou(self.client, acct['Id'])
            if parent_ou:
                acct['Parent'] = parent_ou
            else:
                acct['Parent'] = {
                    'Type': 'UNKNOWN', 'Name': 'Unknown', 'Id': 'Unknown', 'Arn': None
                }
        except Exception as e:
            from botocore.exceptions import ClientError
            if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDeniedException':
                acct['Parent'] = {
                    'Type': 'ACCESS_DENIED', 'Name': 'AccessDenied', 'Id': 'AccessDenied', 'Arn': None
                }
            else:
                # If we can't get parent, just skip it
                acct['Parent'] = {
                    'Type': 'UNKNOWN', 'Name': 'Unknown', 'Id': 'Unknown', 'Arn': None
                }

        # Get account tags
        try:
            organizations = self.client.get_client('organizations')
            tags_response = organizations.list_tags_for_resource(ResourceId=acct['Id'])
            acct['Tags'] = tags_response['Tags']
        except Exception as e:
            from botocore.exceptions import ClientError
            if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDeniedException':
                acct['Tags'] = [{'Key': 'NoTags', 'Value': 'AccessDenied'}]
            else:
                # If we can't get tags, just skip them
                acct['Tags'] = []

        if self.output.json_output:
            self.output.print_json(acct)
        else:
            # Display account info
            print(f'Account: {acct["Id"]} ("{acct["Name"]}"): email: {acct["Email"]} '
                  f'{acct.get("State", "UNKNOWN")} {acct["JoinedMethod"]} on: {str(acct["JoinedTimestamp"]).split()[0]}')

            # Display org/OU info
            parent = acct.get('Parent', {})
            if parent.get('Type') == 'ROOT':
                print(f'- Parent: Organizational root {parent["Name"]} ({parent["Id"]}) - ({parent["Arn"]})')
            elif parent.get('Type') == 'ORGANIZATIONAL_UNIT':
                print(f'- Parent: OU {parent["Name"]} ({parent["Id"]}) - ({parent["Arn"]})')
            elif parent.get('Type') == 'ACCESS_DENIED':
                print('- Parent: AccessDenied')

            # Display tags
            if acct.get('Tags'):
                print('- Tags:')
                for tag in acct['Tags']:
                    print(f'  - {tag["Key"]}: {tag["Value"]}')


class ListAccountsCommand(BaseCommand):
    """List all accounts in the AWS organization."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        # No arguments needed - lists all accounts
        pass

    def execute(self) -> None:
        """Execute the command."""
        organizations = self.client.get_client('organizations')

        accounts = []

        # Get all accounts using paginator
        try:
            paginator = organizations.get_paginator('list_accounts')
            for page in paginator.paginate():
                for acct in page['Accounts']:
                    # Get parent OU information for each account
                    try:
                        parent_ou = utils.get_account_parent_ou(self.client, acct['Id'])
                        if parent_ou:
                            acct['Parent'] = parent_ou
                        else:
                            acct['Parent'] = {
                                'Type': 'UNKNOWN', 'Name': 'Unknown', 'Id': 'Unknown', 'Arn': None
                            }
                    except Exception as e:
                        from botocore.exceptions import ClientError
                        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDeniedException':
                            acct['Parent'] = {
                                'Type': 'ACCESS_DENIED', 'Name': 'AccessDenied', 'Id': 'AccessDenied', 'Arn': None
                            }
                        else:
                            acct['Parent'] = {
                                'Type': 'UNKNOWN', 'Name': 'Unknown', 'Id': 'Unknown', 'Arn': None
                            }

                    # Get account tags (handle AccessDenied like describe-account)
                    try:
                        tags_response = organizations.list_tags_for_resource(ResourceId=acct['Id'])
                        acct['Tags'] = tags_response['Tags']
                    except Exception as e:
                        from botocore.exceptions import ClientError
                        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDeniedException':
                            acct['Tags'] = [{'Key': 'NoTags', 'Value': 'AccessDenied'}]
                        else:
                            acct['Tags'] = []

                    accounts.append(acct)

        except Exception as e:
            self.output.print_error(f'Error listing accounts: {e}')
            raise SystemExit(1)

        if self.output.json_output:
            self.output.print_json(accounts)
        else:
            # Human-readable output
            if not accounts:
                print('No accounts found.')
            else:
                for acct in accounts:
                    print(f'Account: {acct["Id"]} ("{acct["Name"]}"): email: {acct["Email"]} '
                          f'{acct.get("State", "UNKNOWN")} {acct["JoinedMethod"]} on: {str(acct["JoinedTimestamp"]).split()[0]}')

                    # Display org/OU info
                    parent = acct.get('Parent', {})
                    if parent.get('Type') == 'ROOT':
                        print(f'- Parent: Organizational root {parent["Name"]} ({parent["Id"]}) - ({parent["Arn"]})')
                    elif parent.get('Type') == 'ORGANIZATIONAL_UNIT':
                        print(f'- Parent: OU {parent["Name"]} ({parent["Id"]}) - ({parent["Arn"]})')
                    elif parent.get('Type') == 'ACCESS_DENIED':
                        print('- Parent: AccessDenied')

                    # Display tags
                    if acct.get('Tags'):
                        print('- Tags:')
                        for tag in acct['Tags']:
                            print(f'  - {tag["Key"]}: {tag["Value"]}')

                    print()  # Blank line between accounts


class ListAllAccountsInOuCommand(BaseCommand):
    """List all accounts in an OU with hierarchical tree display."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ou-name', help='OU name or "Root" for organization root')
        parser.add_argument('--ou-id', help='OU or Organization ID')
        parser.add_argument('--full-tree', action='store_true', help='Show full organizational tree recursively')
        parser.add_argument('--ou-tree', action='store_true', help='Show only organizational units, suppress account listings')
        parser.add_argument('--stats', action='store_true', help='Stats only - show only statistics summary')
        parser.add_argument('--ascii', action='store_true', help='Use ASCII characters only for output')

    def execute(self) -> None:
        """Execute the command."""
        # Initialize statistics tracking
        # Track all AWS account states: PENDING_ACTIVATION, ACTIVE, SUSPENDED, PENDING_CLOSED, CLOSED
        self.stats = {
            'ou_count': 0,
            'account_total': 0,
            'account_pending_activation': 0,
            'account_active': 0,
            'account_suspended': 0,
            'account_pending_closed': 0,
            'account_closed': 0,
            'account_other': 0
        }

        # Determine parent ID based on input type
        parent_id = None
        parent_display_name = ''
        org_info = None

        if self.args.ou_id:
            if self.args.ou_id.startswith('o-'):
                # User passed an Org ID
                org_info = utils.get_organizational_root(self.client)
                if org_info['OrgId'] != self.args.ou_id:
                    self.output.print_error('Org ID is not from the current organization')
                    raise SystemExit(1)
                parent_id = org_info['RootId']
                parent_display_name = 'Root'
            elif self.args.ou_id.startswith('ou-'):
                # User passed an OU ID
                parent_id = self.args.ou_id
                parent_display_name = utils.get_ou_name_by_id(self.client, self.args.ou_id) or self.args.ou_id
            else:
                self.output.print_error('Invalid OU or Org ID.')
                raise SystemExit(1)
        elif self.args.ou_name:
            if self.args.ou_name == 'Root':
                org_info = utils.get_organizational_root(self.client)
                parent_id = org_info['RootId']
                parent_display_name = 'Root'
            else:
                parent_id = utils.get_ou_id_by_name(self.client, self.args.ou_name)
                parent_display_name = self.args.ou_name
        else:
            # Default to organizational root if no identifier provided
            org_info = utils.get_organizational_root(self.client)
            parent_id = org_info['RootId']
            parent_display_name = 'Root'

        if parent_id is None:
            self.output.print_error(f'Organizational Unit "{self.args.ou_name or self.args.ou_id}" not found.')
            raise SystemExit(1)

        # Check for mutually exclusive options
        if self.args.full_tree and self.args.ou_tree:
            self.output.print_error('Options --full-tree and --ou-tree are mutually exclusive.')
            raise SystemExit(1)

        if self.args.stats and (self.args.full_tree or self.args.ou_tree):
            self.output.print_error('Option --stats is mutually exclusive with --full-tree and --ou-tree.')
            raise SystemExit(1)

        # Additionally show Org Id in header where appropriate
        org_suffix = ''
        if org_info:
            org_suffix = ' (%s)' % org_info['OrgId']

        # Track whether we're in ou_tree mode for statistics display
        ou_tree_mode = False
        stats_only_mode = self.args.stats

        # If stats-only mode, print header and gather statistics without displaying tree
        if stats_only_mode:
            print('Stats for: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
            # Gather statistics using full-tree logic (recursive) but don't print tree
            self._gather_stats_recursive(parent_id)
        elif self.args.full_tree:
            print('Organizational tree for: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
            self._display_org_tree_recursive(parent_id, parent_display_name, 0, False, '', self.args.ascii)
        elif self.args.ou_tree:
            ou_tree_mode = True
            print('Organizational tree for: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
            self._display_org_tree_recursive(parent_id, parent_display_name, 0, True, '', self.args.ascii)
        else:
            print('Contents of: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
            self._display_org_tree_single_level(parent_id, False, self.args.ascii)

        # Display statistics - always show
        # Indent by 2 spaces for --stats mode, 4 spaces for tree modes
        if stats_only_mode:
            indent = '  '
        else:
            indent = '    '

        if ou_tree_mode:
            # In ou-tree mode, we don't have status breakdown
            print('%sSTATS: Child OUs: %d / Accounts: %d TOTAL' % (
                indent,
                self.stats['ou_count'],
                self.stats['account_total']
            ))
        else:
            # In full-tree, single-level, or stats-only mode, show status breakdown
            # Build state breakdown in AWS order: PENDING_ACTIVATION, ACTIVE, SUSPENDED, PENDING_CLOSED, CLOSED, OTHER
            # Always show ACTIVE, only show others if count > 0
            state_parts = []

            # Always show ACTIVE first (most common state)
            state_parts.append('%d ACTIVE' % self.stats['account_active'])

            # Only show other states if they have accounts, in AWS order
            if self.stats['account_pending_activation'] > 0:
                state_parts.append('%d PENDING_ACTIVATION' % self.stats['account_pending_activation'])
            if self.stats['account_suspended'] > 0:
                state_parts.append('%d SUSPENDED' % self.stats['account_suspended'])
            if self.stats['account_pending_closed'] > 0:
                state_parts.append('%d PENDING_CLOSED' % self.stats['account_pending_closed'])
            if self.stats['account_closed'] > 0:
                state_parts.append('%d CLOSED' % self.stats['account_closed'])
            if self.stats['account_other'] > 0:
                state_parts.append('%d OTHER' % self.stats['account_other'])

            state_breakdown = ', '.join(state_parts)
            print('%sSTATS: Child OUs: %d / Accounts: %d TOTAL (%s)' % (
                indent,
                self.stats['ou_count'],
                self.stats['account_total'],
                state_breakdown
            ))

    def _gather_stats_recursive(self, parent_id):
        """
        Recursively gather statistics without displaying anything.
        Used for --stats mode to collect counts like --full-tree would.
        """
        accounts, ous = self._list_accounts_and_ous_in_parent(parent_id)

        # Update OU count
        self.stats['ou_count'] += len(ous)

        # Update account statistics
        for account in accounts:
            self.stats['account_total'] += 1
            state = account.get('State', 'UNKNOWN')
            if state == 'PENDING_ACTIVATION':
                self.stats['account_pending_activation'] += 1
            elif state == 'ACTIVE':
                self.stats['account_active'] += 1
            elif state == 'SUSPENDED':
                self.stats['account_suspended'] += 1
            elif state == 'PENDING_CLOSED':
                self.stats['account_pending_closed'] += 1
            elif state == 'CLOSED':
                self.stats['account_closed'] += 1
            else:
                self.stats['account_other'] += 1

        # Recursively process child OUs
        for ou in ous:
            self._gather_stats_recursive(ou['Id'])

    def _list_accounts_and_ous_in_parent(self, parent_id):
        """
        List all accounts and child OUs in a parent (OU or Root).
        Returns tuple of (accounts_list, ous_list)
        """
        organizations = self.client.get_client('organizations')

        accounts = []
        ous = []

        try:
            # Get accounts
            paginator = organizations.get_paginator('list_accounts_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                for acct in page['Accounts']:
                    accounts.append({
                        'Name': acct['Name'],
                        'Id': acct['Id'],
                        'JoinedTimestamp': acct['JoinedTimestamp'],
                        'Email': acct['Email'],
                        'State': acct.get('State', 'UNKNOWN')  # Use State (not deprecated Status)
                    })

            # Get child OUs
            paginator = organizations.get_paginator('list_organizational_units_for_parent')
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page['OrganizationalUnits']:
                    ous.append({
                        'Name': ou['Name'],
                        'Id': ou['Id'],
                        'Arn': ou['Arn']
                    })

            return accounts, ous

        except Exception:
            return [], []

    def _gen_prefix(self, prefix, is_last, ascii_mode):
        """Generate tree character prefix."""
        if ascii_mode:
            current = prefix + ('`-- ' if is_last else '|-- ')
            next_prefix = prefix + ('    ' if is_last else '|   ')
        else:
            current = prefix + ('└── ' if is_last else '├── ')
            next_prefix = prefix + ('    ' if is_last else '│   ')
        return current, next_prefix

    def _display_org_tree_single_level(self, parent_id, ou_tree_only=False, ascii_mode=False):
        """Display organizational tree for single level only."""
        accounts, ous = self._list_accounts_and_ous_in_parent(parent_id)

        # Update statistics
        self.stats['ou_count'] += len(ous)

        # Combine and sort all items
        all_items = []

        # Add OUs
        for ou in sorted(ous, key=lambda x: x['Name'].lower()):
            ou_accounts, _ = self._list_accounts_and_ous_in_parent(ou['Id'])
            account_count = len(ou_accounts)
            all_items.append(('ou', ou, account_count))

        # Add accounts if not ou_tree_only
        if not ou_tree_only:
            for account in sorted(accounts, key=lambda x: x['Name'].lower()):
                # Update account statistics
                self.stats['account_total'] += 1
                state = account.get('State', 'UNKNOWN')
                if state == 'PENDING_ACTIVATION':
                    self.stats['account_pending_activation'] += 1
                elif state == 'ACTIVE':
                    self.stats['account_active'] += 1
                elif state == 'SUSPENDED':
                    self.stats['account_suspended'] += 1
                elif state == 'PENDING_CLOSED':
                    self.stats['account_pending_closed'] += 1
                elif state == 'CLOSED':
                    self.stats['account_closed'] += 1
                else:
                    self.stats['account_other'] += 1

                all_items.append(('account', account, None))

        # Display items with tree characters
        for i, (item_type, item, count) in enumerate(all_items):
            is_last = (i == len(all_items) - 1)
            current_prefix, _ = self._gen_prefix('', is_last, ascii_mode)

            if item_type == 'ou':
                print('%sOU: %s (%s) (%d)' % (current_prefix, item['Name'], item['Id'], count))
            else:
                # Build account line with optional state field
                state = item.get('State', 'UNKNOWN')
                state_str = '' if state == 'ACTIVE' else ' - %s' % state
                print('%sAccount: %s (%s) - Email: %s%s - Created: %s' % (
                    current_prefix,
                    item['Name'],
                    item['Id'],
                    item['Email'],
                    state_str,
                    str(item['JoinedTimestamp']).split()[0]
                ))

        if not all_items:
            empty_prefix, _ = self._gen_prefix('', True, ascii_mode)
            print('%sNo accounts or child OUs found.' % empty_prefix)

    def _display_org_tree_recursive(self, parent_id, parent_name, indent_level=0, ou_tree_only=False, prefix='', ascii_mode=False):
        """Recursively display organizational tree with accounts and OUs."""
        accounts, ous = self._list_accounts_and_ous_in_parent(parent_id)

        # Update statistics
        self.stats['ou_count'] += len(ous)

        # In ou_tree_only mode, count accounts but don't track status
        if ou_tree_only:
            self.stats['account_total'] += len(accounts)

        # Combine and sort all items
        all_items = []

        # Add OUs
        for ou in sorted(ous, key=lambda x: x['Name'].lower()):
            ou_accounts, _ = self._list_accounts_and_ous_in_parent(ou['Id'])
            account_count = len(ou_accounts)
            all_items.append(('ou', ou, account_count))

        # Add accounts if not ou_tree_only
        if not ou_tree_only:
            for account in sorted(accounts, key=lambda x: x['Name'].lower()):
                # Update account statistics
                self.stats['account_total'] += 1
                state = account.get('State', 'UNKNOWN')
                if state == 'PENDING_ACTIVATION':
                    self.stats['account_pending_activation'] += 1
                elif state == 'ACTIVE':
                    self.stats['account_active'] += 1
                elif state == 'SUSPENDED':
                    self.stats['account_suspended'] += 1
                elif state == 'PENDING_CLOSED':
                    self.stats['account_pending_closed'] += 1
                elif state == 'CLOSED':
                    self.stats['account_closed'] += 1
                else:
                    self.stats['account_other'] += 1

                all_items.append(('account', account, None))

        # Display items with tree characters
        for i, (item_type, item, count) in enumerate(all_items):
            is_last = (i == len(all_items) - 1)
            current_prefix, next_prefix = self._gen_prefix(prefix, is_last, ascii_mode)

            if item_type == 'ou':
                print('%sOU: %s (%s) (%d)%s' % (current_prefix,
                      item['Name'], item['Id'], count, '' if ou_tree_only else ':'))
                self._display_org_tree_recursive(
                    item['Id'], item['Name'], indent_level + 1, ou_tree_only, next_prefix, ascii_mode)
            else:
                # Build account line with optional state field
                state = item.get('State', 'UNKNOWN')
                state_str = '' if state == 'ACTIVE' else ' - %s' % state
                print('%sAccount: %s (%s) - Email: %s%s - Created: %s' % (
                    current_prefix,
                    item['Name'],
                    item['Id'],
                    item['Email'],
                    state_str,
                    str(item['JoinedTimestamp']).split()[0]
                ))


class ListAllAccountsInOrgCommand(ListAllAccountsInOuCommand):
    """Alias for list-all-accounts-in-ou command.

    This command provides the same functionality as list-all-accounts-in-ou,
    but with a more intuitive name when viewing the entire organization.
    """
    pass


class VerifyAccessForUserCommand(BaseCommand):
    """Verify if a user has access to an account via a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--user-name', required=True, help='User name')
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--acct-id', required=True, help='Account ID')

    def execute(self) -> None:
        """Execute the command."""
        user_id = utils.get_user_id_by_name(self.client, self.args.user_name)
        if user_id is None:
            self.output.print_error(f'User "{self.args.user_name}" not found.')
            raise SystemExit(1)

        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_account_assignments')

        has_access = False
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            AccountId=self.args.acct_id,
            PermissionSetArn=ps_arn
        ):
            for item in page['AccountAssignments']:
                if item['PrincipalType'] == 'USER' and item['PrincipalId'] == user_id:
                    has_access = True
                    break
                elif item['PrincipalType'] == 'GROUP':
                    # Check if user is member of this group
                    groups = utils.get_group_memberships_for_user(self.client, user_id)
                    for group in groups:
                        if group['GroupId'] == item['PrincipalId']:
                            has_access = True
                            break
            if has_access:
                break

        if has_access:
            print(f'User "{self.args.user_name}" HAS access to account {self.args.acct_id} via permission set "{self.args.ps_name}"')
        else:
            print(f'User "{self.args.user_name}" DOES NOT have access to account {self.args.acct_id} via permission set "{self.args.ps_name}"')
