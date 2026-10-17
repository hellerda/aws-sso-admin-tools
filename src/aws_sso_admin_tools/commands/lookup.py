"""Lookup commands for AWS SSO Admin Tools."""

from argparse import ArgumentParser, Namespace

from .base import BaseCommand
from ..aws_client import AWSClient
from ..output import OutputHandler
from .. import utils


# --------------------------------------------------------------------------------------------------
# Account Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupAccountNameCommand(BaseCommand):
    """Look up account name by account ID."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--acct-id',
            required=True,
            help='Account ID'
        )

    def execute(self) -> None:
        """Execute the command."""
        acct_name = utils.get_acct_name_by_id(self.client, self.args.acct_id)
        if acct_name is None:
            self.output.print_error(f'Account id "{self.args.acct_id}" not found.')
            raise SystemExit(1)
        self.output.print_text(acct_name)


class LookupAccountIdCommand(BaseCommand):
    """Look up account ID by account name."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--acct-name',
            required=True,
            help='Account name'
        )

    def execute(self) -> None:
        """Execute the command."""
        acct_id = utils.get_acct_id_by_name(self.client, self.args.acct_name)
        if acct_id is None:
            self.output.print_error(f'Account name "{self.args.acct_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(acct_id)


# --------------------------------------------------------------------------------------------------
# OU Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupOuNameCommand(BaseCommand):
    """Look up OU name by OU ID or Org ID."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--ou-id',
            required=True,
            help='OU ID or Org ID'
        )

    def execute(self) -> None:
        """Execute the command."""
        if self.args.ou_id.startswith('o-'):
            # User passed an Org ID
            current_org = utils.get_organizational_root(self.client)
            if current_org['OrgId'] != self.args.ou_id:
                self.output.print_error('Org ID is not from the current organization')
                raise SystemExit(1)
            ou_name = 'Root'
            self.output.print_text(ou_name)

        elif self.args.ou_id.startswith('ou-'):
            # User passed an OU ID
            ou_name = utils.get_ou_name_by_id(self.client, self.args.ou_id)
            if ou_name is None:
                self.output.print_error(f'OU id "{self.args.ou_id}" not found.')
                raise SystemExit(1)
            self.output.print_text(ou_name)
        else:
            self.output.print_error('Invalid OU or Org ID.')
            raise SystemExit(1)


class LookupOuIdCommand(BaseCommand):
    """Look up OU ID by OU name."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--ou-name',
            required=True,
            help='OU name'
        )

    def execute(self) -> None:
        """Execute the command."""
        if self.args.ou_name == 'Root':
            # This is really an Org name, so return current Org ID
            ou_id = utils.get_organizational_root(self.client)['OrgId']
        else:
            ou_id = utils.get_ou_id_by_name(self.client, self.args.ou_name)

        if ou_id is None:
            self.output.print_error(f'OU name "{self.args.ou_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(ou_id)


class LookupOuArnCommand(BaseCommand):
    """Look up OU ARN by OU name."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--ou-name',
            required=True,
            help='OU name'
        )

    def execute(self) -> None:
        """Execute the command."""
        if self.args.ou_name == 'Root':
            # This is really an Org name, so return current Org ARN
            ou_arn = utils.get_organizational_root(self.client)['Arn']
        else:
            ou_arn = utils.get_ou_arn_by_name(self.client, self.args.ou_name)

        if ou_arn is None:
            self.output.print_error(f'OU name "{self.args.ou_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(ou_arn)


# --------------------------------------------------------------------------------------------------
# User Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupUserNameCommand(BaseCommand):
    """Look up user name by user ID."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--user-id',
            required=True,
            help='User ID'
        )

    def execute(self) -> None:
        """Execute the command."""
        user_name = utils.get_user_name_by_id(self.client, self.args.user_id)
        if user_name is None:
            self.output.print_error(f'User id "{self.args.user_id}" not found.')
            raise SystemExit(1)
        self.output.print_text(user_name)


class LookupUserIdCommand(BaseCommand):
    """Look up user ID by user name."""

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
            self.output.print_error(f'User name "{self.args.user_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(user_id)


# --------------------------------------------------------------------------------------------------
# Group Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupGroupNameCommand(BaseCommand):
    """Look up group name by group ID."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--group-id',
            required=True,
            help='Group ID'
        )

    def execute(self) -> None:
        """Execute the command."""
        group_name = utils.get_group_name_by_id(self.client, self.args.group_id)
        if group_name is None:
            self.output.print_error(f'Group id "{self.args.group_id}" not found.')
            raise SystemExit(1)
        self.output.print_text(group_name)


class LookupGroupIdCommand(BaseCommand):
    """Look up group ID by group name."""

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
            self.output.print_error(f'Group name "{self.args.group_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(group_id)


# --------------------------------------------------------------------------------------------------
# Permission Set Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupPsNameCommand(BaseCommand):
    """Look up permission set name by ARN."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--ps-arn',
            required=True,
            help='Permission Set ARN'
        )

    def execute(self) -> None:
        """Execute the command."""
        ps_name = utils.get_permission_set_name_by_arn(self.client, self.args.ps_arn)
        if ps_name is None:
            self.output.print_error(f'Permission set ARN "{self.args.ps_arn}" not found.')
            raise SystemExit(1)
        self.output.print_text(ps_name)


class LookupPsArnCommand(BaseCommand):
    """Look up permission set ARN by name."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--ps-name',
            required=True,
            help='Permission Set name'
        )

    def execute(self) -> None:
        """Execute the command."""
        ps_arn = utils.get_permission_set_arn_by_name(self.client, self.args.ps_name)
        if ps_arn is None:
            self.output.print_error(f'Permission set name "{self.args.ps_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(ps_arn)


# --------------------------------------------------------------------------------------------------
# Application Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupAppNameCommand(BaseCommand):
    """Look up application name by ARN."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--app-arn',
            required=True,
            help='Application ARN'
        )

    def execute(self) -> None:
        """Execute the command."""
        app_name = utils.get_application_name_by_arn(self.client, self.args.app_arn)
        if app_name is None:
            self.output.print_error(f'Application "{self.args.app_arn}" not found.')
            raise SystemExit(1)
        self.output.print_text(app_name)


class LookupAppArnCommand(BaseCommand):
    """Look up application ARN by name."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--app-name',
            required=True,
            help='Application name'
        )

    def execute(self) -> None:
        """Execute the command."""
        app_arn = utils.get_application_arn_by_name(self.client, self.args.app_name)
        if app_arn is None:
            self.output.print_error(f'Application name "{self.args.app_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(app_arn)


# --------------------------------------------------------------------------------------------------
# TTI Lookup Commands
# --------------------------------------------------------------------------------------------------

class LookupTtiNameCommand(BaseCommand):
    """Look up trusted token issuer name by ARN."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--tti-arn',
            required=True,
            help='Trusted Token Issuer ARN'
        )

    def execute(self) -> None:
        """Execute the command."""
        tti_name = utils.get_tti_name_by_arn(self.client, self.args.tti_arn)
        if tti_name is None:
            self.output.print_error(f'TTI "{self.args.tti_arn}" not found.')
            raise SystemExit(1)
        self.output.print_text(tti_name)


class LookupTtiArnCommand(BaseCommand):
    """Look up trusted token issuer ARN by name."""

    @staticmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """Register command arguments."""
        parser.add_argument(
            '--tti-name',
            required=True,
            help='Trusted Token Issuer name'
        )

    def execute(self) -> None:
        """Execute the command."""
        tti_arn = utils.get_tti_arn_by_name(self.client, self.args.tti_name)
        if tti_arn is None:
            self.output.print_error(f'TTI name "{self.args.tti_name}" not found.')
            raise SystemExit(1)
        self.output.print_text(tti_arn)
