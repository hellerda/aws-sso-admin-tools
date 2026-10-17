"""Application and TTI commands for AWS SSO Admin Tools."""

import json
from argparse import ArgumentParser

from .base import BaseCommand
from .. import utils


# --------------------------------------------------------------------------------------------------
# TTI Commands
# --------------------------------------------------------------------------------------------------

class ListTtisCommand(BaseCommand):
    """List all trusted token issuers."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        pass

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_trusted_token_issuers')

        # Get list of TTI ARNs
        tti_arns = []
        for page in paginator.paginate(InstanceArn=self.client.instance_arn):
            for tti in page['TrustedTokenIssuers']:
                tti_arns.append(tti['TrustedTokenIssuerArn'])

        # Get detailed information for each TTI
        detailed_ttis = []
        for tti_arn in tti_arns:
            response = sso_admin.describe_trusted_token_issuer(
                TrustedTokenIssuerArn=tti_arn
            )
            # Remove ResponseMetadata
            response.pop('ResponseMetadata', None)
            detailed_ttis.append(response)

        # Always output JSON (no separate HR mode)
        self.output.print_json(detailed_ttis)


class DescribeTtiCommand(BaseCommand):
    """Describe a trusted token issuer."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--tti-name', required=True, help='TTI name')

    def execute(self) -> None:
        """Execute the command."""
        tti_arn = utils.get_tti_arn_by_name(self.client, self.args.tti_name)
        if tti_arn is None:
            self.output.print_error(f'TTI "{self.args.tti_name}" not found.')
            raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.describe_trusted_token_issuer(
            TrustedTokenIssuerArn=tti_arn
        )

        # Remove ResponseMetadata from output
        response.pop('ResponseMetadata', None)

        # Always output JSON (no HR mode)
        self.output.print_json(response)


# --------------------------------------------------------------------------------------------------
# Application Commands
# --------------------------------------------------------------------------------------------------

class ListApplicationsCommand(BaseCommand):
    """List all applications."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        pass

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_applications')

        applications = []
        for page in paginator.paginate(InstanceArn=self.client.instance_arn):
            applications.extend(page['Applications'])

        # Always output JSON (no HR mode)
        self.output.print_json(applications)


class DescribeApplicationCommand(BaseCommand):
    """Describe an application."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        response = sso_admin.describe_application(
            ApplicationArn=app_arn
        )

        # Remove ResponseMetadata from output
        response.pop('ResponseMetadata', None)

        # Always output JSON (no HR mode)
        self.output.print_json(response)


class ListApplicationAssignmentsCommand(BaseCommand):
    """List application assignments."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
            # For header, use ARN if that's what was provided
            app_identifier = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)
            # For header, use name if that's what was provided
            app_identifier = self.args.app_name

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_application_assignments')

        assignments = []
        for page in paginator.paginate(ApplicationArn=app_arn):
            assignments.extend(page['ApplicationAssignments'])

        # Enrich assignments with principal names for both JSON and HR output
        enriched_assignments = []
        for assignment in assignments:
            principal_type = assignment['PrincipalType']
            principal_id = assignment['PrincipalId']

            # Look up the principal name
            if principal_type == 'USER':
                principal_name = utils.get_user_name_by_id(self.client, principal_id)
            elif principal_type == 'GROUP':
                principal_name = utils.get_group_name_by_id(self.client, principal_id)
            else:
                principal_name = None

            # Create new ordered dict with desired field order
            enriched = {
                'ApplicationArn': assignment['ApplicationArn'],
                'PrincipalId': assignment['PrincipalId'],
                'PrincipalName': principal_name,
                'PrincipalType': assignment['PrincipalType']
            }
            enriched_assignments.append(enriched)

        if self.output.json_output:
            self.output.print_json(enriched_assignments)
        else:
            # Human-readable output with header and name lookups
            print(f'Assigned principals for application "{app_identifier}":')

            if not enriched_assignments:
                print('No assignments found.')
            else:
                for assignment in enriched_assignments:
                    principal_type = assignment['PrincipalType']
                    principal_name = assignment.get('PrincipalName')
                    principal_id = assignment['PrincipalId']

                    # Display with bullet and name (fallback to ID if name not found)
                    if principal_name:
                        print(f'- {principal_type}: {principal_name}')
                    else:
                        print(f'- {principal_type}: {principal_id}')


class ListApplicationProvidersCommand(BaseCommand):
    """List application providers."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        pass

    def execute(self) -> None:
        """Execute the command."""
        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_application_providers')

        providers = []
        for page in paginator.paginate():
            providers.extend(page['ApplicationProviders'])

        # Always output JSON (no HR mode)
        self.output.print_json(providers)


class ListApplicationAccessScopesCommand(BaseCommand):
    """List application access scopes."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
            app_identifier = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)
            app_identifier = self.args.app_name

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_application_access_scopes')

        scopes = []
        for page in paginator.paginate(ApplicationArn=app_arn):
            scopes.extend(page['Scopes'])

        if self.output.json_output:
            self.output.print_json(scopes)
        else:
            # Human-readable output with header and bullets
            print(f'Access scopes for application "{app_identifier}":')

            if not scopes:
                print('No access scopes found.')
            else:
                for scope in scopes:
                    print(f'- {scope["Scope"]}')


class ListApplicationAuthMethodsCommand(BaseCommand):
    """List application authentication methods."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_application_authentication_methods')

        methods = []
        for page in paginator.paginate(ApplicationArn=app_arn):
            methods.extend(page['AuthenticationMethods'])

        # Always output JSON (no HR mode)
        self.output.print_json(methods)


class ListApplicationGrantsCommand(BaseCommand):
    """List application grants."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)

        sso_admin = self.client.get_client('sso-admin')
        paginator = sso_admin.get_paginator('list_application_grants')

        grants = []
        for page in paginator.paginate(ApplicationArn=app_arn):
            grants.extend(page['Grants'])

        # Always output JSON (no HR mode)
        self.output.print_json(grants)



# --------------------------------------------------------------------------------------------------
# Application Assignment Commands
# --------------------------------------------------------------------------------------------------

class CreateAppAssignmentCommand(BaseCommand):
    """Create an application assignment."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')
        parser.add_argument('--user-id', help='User ID')
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--group-id', help='Group ID')
        parser.add_argument('--group-name', help='Group name')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Validate principal specification
        principal_args = [self.args.user_id, self.args.user_name, self.args.group_id, self.args.group_name]
        if sum(arg is not None for arg in principal_args) != 1:
            self.output.print_error('Specify exactly one of: --user-id, --user-name, --group-id, --group-name.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)

        # Resolve principal ID and type
        if self.args.user_id:
            principal_type = 'USER'
            principal_id = self.args.user_id
        elif self.args.user_name:
            principal_type = 'USER'
            principal_id = utils.get_user_id_by_name(self.client, self.args.user_name)
            if principal_id is None:
                self.output.print_error(f'User "{self.args.user_name}" not found.')
                raise SystemExit(1)
        elif self.args.group_id:
            principal_type = 'GROUP'
            principal_id = self.args.group_id
        else:  # group_name
            principal_type = 'GROUP'
            principal_id = utils.get_group_id_by_name(self.client, self.args.group_name)
            if principal_id is None:
                self.output.print_error(f'Group "{self.args.group_name}" not found.')
                raise SystemExit(1)

        # Create the assignment
        try:
            sso_admin = self.client.get_client('sso-admin')

            # Enable assignment configuration for the application
            response = sso_admin.put_application_assignment_configuration(
                ApplicationArn=app_arn,
                AssignmentRequired=True
            )

            # Now create the actual assignment
            response = sso_admin.create_application_assignment(
                ApplicationArn=app_arn,
                PrincipalType=principal_type,
                PrincipalId=principal_id
            )

            if self.output.json_output:
                self.output.print_json(response)
            else:
                print(f'Created application assignment')
                print(f'Application: {app_arn}')
                print(f'Principal: {principal_type} {principal_id}')

        except Exception as e:
            from botocore.exceptions import ClientError
            if isinstance(e, ClientError):
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                self.output.print_error(f'AWS API Error ({error_code}): {error_message}')
            else:
                self.output.print_error(f'Error creating application assignment: {e}')
            raise SystemExit(1)


class DeleteAppAssignmentCommand(BaseCommand):
    """Delete an application assignment."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument('--app-name', help='Application name')
        parser.add_argument('--app-arn', help='Application ARN')
        parser.add_argument('--user-id', help='User ID')
        parser.add_argument('--user-name', help='User name')
        parser.add_argument('--group-id', help='Group ID')
        parser.add_argument('--group-name', help='Group name')

    def execute(self) -> None:
        """Execute the command."""
        # Validate application specification
        if not self.args.app_name and not self.args.app_arn:
            self.output.print_error('Specify either --app-name or --app-arn.')
            raise SystemExit(1)

        # Validate principal specification
        principal_args = [self.args.user_id, self.args.user_name, self.args.group_id, self.args.group_name]
        if sum(arg is not None for arg in principal_args) != 1:
            self.output.print_error('Specify exactly one of: --user-id, --user-name, --group-id, --group-name.')
            raise SystemExit(1)

        # Resolve application ARN
        if self.args.app_arn:
            app_arn = self.args.app_arn
        else:
            app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
            if app_arn is None:
                self.output.print_error(f'Application "{self.args.app_name}" not found.')
                raise SystemExit(1)

        # Resolve principal ID and type
        if self.args.user_id:
            principal_type = 'USER'
            principal_id = self.args.user_id
        elif self.args.user_name:
            principal_type = 'USER'
            principal_id = utils.get_user_id_by_name(self.client, self.args.user_name)
            if principal_id is None:
                self.output.print_error(f'User "{self.args.user_name}" not found.')
                raise SystemExit(1)
        elif self.args.group_id:
            principal_type = 'GROUP'
            principal_id = self.args.group_id
        else:  # group_name
            principal_type = 'GROUP'
            principal_id = utils.get_group_id_by_name(self.client, self.args.group_name)
            if principal_id is None:
                self.output.print_error(f'Group "{self.args.group_name}" not found.')
                raise SystemExit(1)

        # Delete the assignment
        try:
            sso_admin = self.client.get_client('sso-admin')
            response = sso_admin.delete_application_assignment(
                ApplicationArn=app_arn,
                PrincipalType=principal_type,
                PrincipalId=principal_id
            )

            if self.output.json_output:
                self.output.print_json(response)
            else:
                print(f'Deleted application assignment')
                print(f'Application: {app_arn}')
                print(f'Principal: {principal_type} {principal_id}')

        except Exception as e:
            from botocore.exceptions import ClientError
            if isinstance(e, ClientError):
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                self.output.print_error(f'AWS API Error ({error_code}): {error_message}')
            else:
                self.output.print_error(f'Error deleting application assignment: {e}')
            raise SystemExit(1)
