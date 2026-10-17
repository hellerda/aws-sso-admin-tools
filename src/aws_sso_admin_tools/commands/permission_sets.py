"""Permission set commands for AWS SSO Admin Tools."""

import json
from argparse import ArgumentParser

from .base import BaseCommand
from .. import utils


# --------------------------------------------------------------------------------------------------
# Permission Set CRUD Commands
# --------------------------------------------------------------------------------------------------

class CreatePsCommand(BaseCommand):
    """Create a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--ps-desc', help='Permission set description')
        parser.add_argument('--ps-durn', help='Session duration (e.g., PT2H)')
        parser.add_argument('--tags', help='Tags (Key=Value,Key2=Value2 or JSON)')

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')

        params = {
            'InstanceArn': self.client.instance_arn,
            'Name': self.args.ps_name,
        }

        if self.args.ps_desc:
            params['Description'] = self.args.ps_desc

        if self.args.ps_durn:
            params['SessionDuration'] = self.args.ps_durn

        if self.args.tags:
            params['Tags'] = utils.parse_tags_from_input(self.args.tags)

        response = sso_admin.create_permission_set(**params)
        response['PermissionSet'].pop('CreatedDate', None)

        if self.output.json_output:
            self.output.print_json(response['PermissionSet'])
        else:
            print(json.dumps(response['PermissionSet'], indent=4, sort_keys=False, default=str))


class UpdatePsCommand(BaseCommand):
    """Update a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', help='Permission set name')
        parser.add_argument('--ps-arn', help='Permission set ARN')
        parser.add_argument('--ps-desc', help='Permission set description')
        parser.add_argument('--ps-durn', help='Session duration (e.g., PT2H)')

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.ps_name and not self.args.ps_arn:
            self.output.print_error('No permission set specified; use one of: --ps-name, --ps-arn.')
            raise SystemExit(1)

        if self.args.ps_arn:
            ps_arn = self.args.ps_arn
        else:
            ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
            if ps_arn is None:
                self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')

        params = {
            'InstanceArn': self.client.instance_arn,
            'PermissionSetArn': ps_arn,
        }

        if self.args.ps_desc:
            params['Description'] = self.args.ps_desc

        if self.args.ps_durn:
            params['SessionDuration'] = self.args.ps_durn

        response = sso_admin.update_permission_set(**params)

        if not self.output.json_output:
            print(f'Updated permission set: {ps_arn}')


class DeletePsCommand(BaseCommand):
    """Delete a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', help='Permission set name')
        parser.add_argument('--ps-arn', help='Permission set ARN')

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.ps_name and not self.args.ps_arn:
            self.output.print_error('No permission set specified; use one of: --ps-name, --ps-arn.')
            raise SystemExit(1)

        if self.args.ps_arn:
            ps_arn = self.args.ps_arn
        else:
            ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
            if ps_arn is None:
                self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        sso_admin.delete_permission_set(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        )

        if not self.output.json_output:
            ps_name = self.args.ps_name or ps_arn
            print(f'Deleted permission set: {ps_name}')


class DescribePsCommand(BaseCommand):
    """Describe a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', help='Permission set name')
        parser.add_argument('--ps-arn', help='Permission set ARN')

    def execute(self) -> None:
        """Execute the command."""
        if not self.args.ps_name and not self.args.ps_arn:
            self.output.print_error('No permission set specified; use one of: --ps-name, --ps-arn.')
            raise SystemExit(1)

        if self.args.ps_arn:
            ps_arn = self.args.ps_arn
        else:
            ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
            if ps_arn is None:
                self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.describe_permission_set(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        )

        if self.output.json_output:
            self.output.print_json(response['PermissionSet'])
        else:
            print(json.dumps(response['PermissionSet'], indent=4, sort_keys=False, default=str))


# --------------------------------------------------------------------------------------------------
# Inline Policy Commands
# --------------------------------------------------------------------------------------------------

class PutPsInlinePolicyCommand(BaseCommand):
    """Put inline policy to a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--policy', required=True, help='Policy document (JSON or file://)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        policy_doc = utils.parse_policy_from_input(self.args.policy)

        sso_admin = self.client.get_client('sso-admin')
        sso_admin.put_inline_policy_to_permission_set(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn,
            InlinePolicy=policy_doc
        )

        if not self.output.json_output:
            print(f'Put inline policy to permission set: {self.args.ps_name}')


class DeletePsInlinePolicyCommand(BaseCommand):
    """Delete inline policy from a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        sso_admin.delete_inline_policy_from_permission_set(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        )

        if not self.output.json_output:
            print(f'Deleted inline policy from permission set: {self.args.ps_name}')


class GetPsInlinePolicyCommand(BaseCommand):
    """Get inline policy from a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        )

        if self.output.json_output:
            self.output.print_json(response)
        else:
            print(json.dumps(response, indent=4, sort_keys=False, default=str))


# --------------------------------------------------------------------------------------------------
# Managed Policy Commands
# --------------------------------------------------------------------------------------------------

class AttachPsManagedPoliciesCommand(BaseCommand):
    """Attach managed policies to a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--policy-arns', required=True,
                          help='Policy ARNs (comma-separated or JSON)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        policy_arns = utils.parse_policy_arns_from_input(self.args.policy_arns)

        sso_admin = self.client.get_client('sso-admin')
        for arn in policy_arns:
            sso_admin.attach_managed_policy_to_permission_set(
                InstanceArn=self.client.instance_arn,
                PermissionSetArn=ps_arn,
                ManagedPolicyArn=arn
            )
            if not self.output.json_output:
                print(f'Attached policy: {arn}')

        if not self.output.json_output:
            print(f'Attached {len(policy_arns)} managed policies to {self.args.ps_name}')


class DetachPsManagedPoliciesCommand(BaseCommand):
    """Detach managed policies from a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--policy-arns', required=True,
                          help='Policy ARNs (comma-separated or JSON)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        policy_arns = utils.parse_policy_arns_from_input(self.args.policy_arns)

        sso_admin = self.client.get_client('sso-admin')
        for arn in policy_arns:
            sso_admin.detach_managed_policy_from_permission_set(
                InstanceArn=self.client.instance_arn,
                PermissionSetArn=ps_arn,
                ManagedPolicyArn=arn
            )
            if not self.output.json_output:
                print(f'Detached policy: {arn}')

        if not self.output.json_output:
            print(f'Detached {len(policy_arns)} managed policies from {self.args.ps_name}')


class ListPsManagedPoliciesCommand(BaseCommand):
    """List managed policies attached to a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_managed_policies_in_permission_set')

        policies = []
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        ):
            policies.extend(page['AttachedManagedPolicies'])

        # Always output JSON (no separate HR mode)
        self.output.print_json(policies)


# --------------------------------------------------------------------------------------------------
# Customer Managed Policy Commands
# --------------------------------------------------------------------------------------------------

class AttachPsCustomerManagedPoliciesCommand(BaseCommand):
    """Attach customer managed policies to a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--cm-policies', required=True,
                          help='Customer managed policies (Name=Path,Name2=Path2 or JSON)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        cm_policies = utils.parse_cm_policies_from_input(self.args.cm_policies)

        sso_admin = self.client.get_client('sso-admin')
        for policy in cm_policies:
            sso_admin.attach_customer_managed_policy_reference_to_permission_set(
                InstanceArn=self.client.instance_arn,
                PermissionSetArn=ps_arn,
                CustomerManagedPolicyReference=policy
            )
            if not self.output.json_output:
                print(f'Attached customer managed policy: {policy["Name"]} (Path: {policy["Path"]})')

        if not self.output.json_output:
            print(f'Attached {len(cm_policies)} customer managed policies to {self.args.ps_name}')


class DetachPsCustomerManagedPoliciesCommand(BaseCommand):
    """Detach customer managed policies from a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--cm-policies', required=True,
                          help='Customer managed policies (Name=Path,Name2=Path2 or JSON)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        cm_policies = utils.parse_cm_policies_from_input(self.args.cm_policies)

        sso_admin = self.client.get_client('sso-admin')
        for policy in cm_policies:
            sso_admin.detach_customer_managed_policy_reference_from_permission_set(
                InstanceArn=self.client.instance_arn,
                PermissionSetArn=ps_arn,
                CustomerManagedPolicyReference=policy
            )
            if not self.output.json_output:
                print(f'Detached customer managed policy: {policy["Name"]} (Path: {policy["Path"]})')

        if not self.output.json_output:
            print(f'Detached {len(cm_policies)} customer managed policies from {self.args.ps_name}')


class ListPsCustomerManagedPoliciesCommand(BaseCommand):
    """List customer managed policies attached to a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_customer_managed_policy_references_in_permission_set')

        policies = []
        for page in paginator.paginate(
            InstanceArn=self.client.instance_arn,
            PermissionSetArn=ps_arn
        ):
            policies.extend(page['CustomerManagedPolicyReferences'])

        # Always output JSON (no separate HR mode)
        self.output.print_json(policies)


# --------------------------------------------------------------------------------------------------
# Tagging and Provisioning Commands
# --------------------------------------------------------------------------------------------------

class TagPsCommand(BaseCommand):
    """Tag a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--tags', required=True, help='Tags (Key=Value,Key2=Value2 or JSON)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        tags = utils.parse_tags_from_input(self.args.tags)

        sso_admin = self.client.get_client('sso-admin')
        sso_admin.tag_resource(
            InstanceArn=self.client.instance_arn,
            ResourceArn=ps_arn,
            Tags=tags
        )

        if not self.output.json_output:
            print(f'Tagged permission set: {self.args.ps_name}')


class UntagPsCommand(BaseCommand):
    """Untag a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--tag-keys', required=True, help='Tag keys (comma-separated)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        tag_keys = [key.strip() for key in self.args.tag_keys.split(',')]

        sso_admin = self.client.get_client('sso-admin')
        sso_admin.untag_resource(
            InstanceArn=self.client.instance_arn,
            ResourceArn=ps_arn,
            TagKeys=tag_keys
        )

        if not self.output.json_output:
            print(f'Untagged permission set: {self.args.ps_name}')


class ListPsTagsCommand(BaseCommand):
    """List tags for a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.list_tags_for_resource(
            InstanceArn=self.client.instance_arn,
            ResourceArn=ps_arn
        )

        # Always output JSON (no separate HR mode)
        self.output.print_json(response.get('Tags', []))


class ProvisionPsCommand(BaseCommand):
    """Provision a permission set."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--ps-name', required=True, help='Permission set name')
        parser.add_argument('--acct-id', help='Account ID (optional, provisions to all if omitted)')

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set "{self.args.ps_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')

        params = {
            'InstanceArn': self.client.instance_arn,
            'PermissionSetArn': ps_arn,
            'TargetType': 'AWS_ACCOUNT'
        }

        if self.args.acct_id:
            params['TargetId'] = self.args.acct_id
        else:
            params['TargetType'] = 'ALL_PROVISIONED_ACCOUNTS'

        response = sso_admin.provision_permission_set(**params)

        # Output full API response structure with top-level key
        self.output.print_json({
            'PermissionSetProvisioningStatus': response['PermissionSetProvisioningStatus']
        })
