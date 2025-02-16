#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
Common functions

(c) Copyright Dave Heller 2024
'''

import boto3
import logging
import os
import sys

from botocore.exceptions import ClientError
from optparse import OptionParser


# --------------------------------------------------------------------------------------------------
# Functions...
# --------------------------------------------------------------------------------------------------
def get_sso_instance(ctx):

    try:
        sso_admin_client = ctx.session.client('sso-admin')

        response = sso_admin_client.list_instances (
            MaxResults = 1  # assumes only one instance
        )

    except Exception as e:
        print("Error: %s" % str(e))
        exit(1)

    instance_arn = response['Instances'][0]['InstanceArn']
    identitystore_id = response['Instances'][0]['IdentityStoreId']

    return(instance_arn, identitystore_id)


def get_acct_desc_by_name(ctx, acct_name):

    organizations_client = ctx.session.client('organizations')

    try:
        for page in organizations_client.get_paginator('list_accounts').paginate():

            for acct in page['Accounts']:
                if acct['Name'] == acct_name:
                    return acct

        return None

    except:
        return None


def get_acct_desc_by_id(ctx, acct_id):

    organizations_client = ctx.session.client('organizations')

    try:
        acct = organizations_client.describe_account (
            AccountId = acct_id
        )
        return acct['Account']

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccountNotFoundException':  # type: ignore
            return None
        else:
            raise


def get_acct_id_by_name(ctx, acct_name):

    acct = get_acct_desc_by_name(ctx, acct_name)
    if acct != None:
        return acct['Id']

    return None


def get_acct_name_by_id(ctx, acct_id):

    acct = get_acct_desc_by_id(ctx, acct_id)
    if acct != None:
        return acct['Name']

    return None


def get_permission_set_desc_by_name(ctx, ps_name):

    sso_admin_client = ctx.session.client('sso-admin')

    paginator = sso_admin_client.get_paginator('list_permission_sets')

    for page in paginator.paginate(InstanceArn = ctx.instance_arn):
        for item in page['PermissionSets']:
            ps = sso_admin_client.describe_permission_set (
                InstanceArn = ctx.instance_arn,
                PermissionSetArn = item
            )
            if (ps['PermissionSet']['Name'] == ps_name):
                return (ps['PermissionSet'])

    return None


def get_permission_set_desc_by_arn(ctx, ps_arn):

    try:
        sso_admin_client = ctx.session.client('sso-admin')

        ps = sso_admin_client.describe_permission_set (
            InstanceArn = ctx.instance_arn,
            PermissionSetArn = ps_arn
        )
        return(ps['PermissionSet'])

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':  # type: ignore
            return None
        else:
            raise


def get_permission_set_arn_by_name(ctx, ps_name):

    ps = get_permission_set_desc_by_name(ctx, ps_name)
    if ps != None:
        return ps['PermissionSetArn']

    return None


def get_permission_set_name_by_arn(ctx, ps_arn):

    ps = get_permission_set_desc_by_arn(ctx, ps_arn)
    if ps != None:
        return ps['Name']

    return None


def get_application_arn_by_name(ctx, app_name):

    sso_admin_client = ctx.session.client('sso-admin')

    paginator = sso_admin_client.get_paginator('list_applications')

    for page in paginator.paginate(
            InstanceArn = ctx.instance_arn
        ):
        for item in page['Applications']:

            if (item['Name'] == app_name):
                return (item['ApplicationArn'])

    return None


def get_application_name_by_arn(ctx, app_arn):

    try:
        sso_admin_client = ctx.session.client('sso-admin')

        app = sso_admin_client.describe_application (
            ApplicationArn = app_arn
        )
        return(app['Name'])

    except:
        return None


def get_tti_arn_by_name(ctx, tti_name):

    sso_admin_client = ctx.session.client('sso-admin')

    paginator = sso_admin_client.get_paginator('list_trusted_token_issuers')

    for page in paginator.paginate(
            InstanceArn = ctx.instance_arn
        ):
        for item in page['TrustedTokenIssuers']:

            if (item['Name'] == tti_name):
                return (item['TrustedTokenIssuerArn'])

    return None


def get_tti_name_by_arn(ctx, tti_arn):

    try:
        sso_admin_client = ctx.session.client('sso-admin')

        tti = sso_admin_client.describe_trusted_token_issuer (
            TrustedTokenIssuerArn = tti_arn
        )
        return(tti['Name'])

    except:
        return None


def get_group_id_by_name(ctx, group_name):

    try:
        identitystore_client = ctx.session.client('identitystore')

        response = identitystore_client.get_group_id (
            IdentityStoreId = ctx.identitystore_id,
            AlternateIdentifier = {
                'UniqueAttribute': {
                    'AttributePath': 'displayName',
                    'AttributeValue': group_name
                }
            }
        )
        return(response['GroupId'])

    except:
        return None


def get_group_name_by_id(ctx, group_id):

    try:
        identitystore_client = ctx.session.client('identitystore')

        response = identitystore_client.describe_group (
            IdentityStoreId = ctx.identitystore_id,
            GroupId = group_id
        )
        return(response['DisplayName'])

    except:
        return None


def get_user_id_by_name(ctx, user_name):

    try:
        identitystore_client = ctx.session.client('identitystore')

        response = identitystore_client.get_user_id (
            IdentityStoreId = ctx.identitystore_id,
            AlternateIdentifier = {
                'UniqueAttribute': {
                    'AttributePath': 'userName',
                    'AttributeValue': user_name
                }
            }
        )
        return(response['UserId'])

    except:
        return None


def get_user_name_by_id(ctx, user_id):

    try:
        identitystore_client = ctx.session.client('identitystore')

        response = identitystore_client.describe_user (
            IdentityStoreId = ctx.identitystore_id,
            UserId = user_id
        )
        return(response['UserName'])

    except:
        return None


def get_group_memberships_for_user(ctx, user_id):

    identitystore_client = ctx.session.client('identitystore')

    found_groups = []

    try:
        paginator = identitystore_client.get_paginator('list_group_memberships_for_member')

        for page in paginator.paginate(
            IdentityStoreId = ctx.identitystore_id,
            MemberId={
                'UserId': user_id
            }
        ):
            for member in page["GroupMemberships"]:

                response = identitystore_client.describe_group (
                    IdentityStoreId = ctx.identitystore_id,
                    GroupId = member['GroupId']
                )
                found_groups.append(response)

        return found_groups

    except Exception as e:
        print("Error: %s" % str(e))
        exit(1)


# --------------------------------------------------------------------------------------------------
# Build AWS context including boto3 session...
# --------------------------------------------------------------------------------------------------
class AWSContextManager:
    def __init__(self, aws_profile, region_name):
        self.aws_profile = aws_profile
        self.region_name = region_name

    def __enter__(self):
        self.session = boto3.Session(profile_name=self.aws_profile,
                                     region_name=self.region_name)
        (self.instance_arn, self.identitystore_id) = get_sso_instance(self)
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        pass


# --------------------------------------------------------------------------------------------------
# Unit tests...
# --------------------------------------------------------------------------------------------------
def run():

    cmds_usage = '''\nAvailable commands:
    test-funcs
    lookup-account-name
    lookup-user-name
    lookup-group-name
    lookup-ps-name
    lookup-app-name
    lookup-tti-name
    lookup-account-id
    lookup-user-id
    lookup-group-id
    lookup-ps-arn
    lookup-app-arn
    lookup-tti-arn
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog lookup-ps-arn --ps_name MyPermissionSet\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--region', dest='region', default=None,
                      help='AWS region to use')
    parser.add_option('--acct-id', dest='acct_id', default=None,
                      help='Account ID')
    parser.add_option('--user-id', dest='user_id', default=None,
                      help='User ID')
    parser.add_option('--group-id', dest='group_id', default=None,
                      help='Group ID')
    parser.add_option('--ps-arn', dest='ps_arn', default=None,
                      help='Permission Set Arn')
    parser.add_option('--app-arn', dest='app_arn', default=None,
                      help='Trusted token issuer Arn')
    parser.add_option('--tti-arn', dest='tti_arn', default=None,
                      help='Application Arn')
    parser.add_option('--acct-name', dest='acct_name', default=None,
                      help='Account name')
    parser.add_option('--user-name', dest='user_name', default=None,
                      help='User name')
    parser.add_option('--group-name', dest='group_name', default=None,
                      help='Group name')
    parser.add_option('--ps-name', dest='ps_name', default=None,
                      help='Permission Set name')
    parser.add_option('--app-name', dest='app_name', default=None,
                      help='Application name')
    parser.add_option('--tti-name', dest='tti_name', default=None,
                      help='Trusted token issuer name')

    (options, args) = parser.parse_args()

    def need_account_id():
        if options.acct_id == None:
            print('No account specified; use --acct-id.')
            exit(1)

    def need_user_id():
        if options.user_id == None:
            print('No id specified; use --user-id.')
            exit(1)

    def need_group_id():
        if options.group_id == None:
            print('No group specified; use --group-id.')
            exit(1)

    def need_ps_arn():
        if options.ps_arn == None:
            print('No permission set Arn specified; use --ps-arn.')
            exit(1)

    def need_app_arn():
        if options.app_arn == None:
            print('No appliction Arn specified; use --app-arn.')
            exit(1)

    def need_tti_arn():
        if options.tti_arn == None:
            print('No TTI Arn specified; use --tti-arn.')
            exit(1)

    def need_account_name():
        if options.acct_name == None:
            print('No account specified; use --acct-name.')
            exit(1)

    def need_user_name():
        if options.user_name == None:
            print('No user specified; use --user-name.')
            exit(1)

    def need_group_name():
        if options.group_name == None:
            print('No group specified; use --group-name.')
            exit(1)

    def need_ps_name():
        if options.ps_name == None:
            print('No permission set specified; use --ps-name.')
            exit(1)

    def need_app_name():
        if options.app_name == None:
            print('No appliction specified; use --app-name.')
            exit(1)

    def need_tti_name():
        if options.tti_name == None:
            print('No TTI specified; use --tti-name.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'test-funcs':
            need_ps_name()
            need_app_name()
            need_tti_name()
            need_user_name()
            need_group_name()
            operation = op

        elif op == 'lookup-account-name':
            need_account_id()
            operation = op
        elif op == 'lookup-user-name':
            need_user_id()
            operation = op
        elif op == 'lookup-group-name':
            need_group_id()
            operation = op
        elif op == 'lookup-ps-name':
            need_ps_arn()
            operation = op
        elif op == 'lookup-app-name':
            need_app_arn()
            operation = op
        elif op == 'lookup-tti-name':
            need_tti_arn()
            operation = op
        elif op == 'lookup-account-id':
            need_account_name()
            operation = op
        elif op == 'lookup-user-id':
            need_user_name()
            operation = op
        elif op == 'lookup-group-id':
            need_group_name()
            operation = op
        elif op == 'lookup-ps-arn':
            need_ps_name()
            operation = op
        elif op == 'lookup-app-arn':
            need_app_name()
            operation = op
        elif op == 'lookup-tti-arn':
            need_tti_name()
            operation = op

        else:
            print('Unknown command: %s\n' % op)

    if operation == None:
        parser.print_help()
        exit(1)

    if 'AWS_DEFAULT_REGION' not in os.environ and 'AWS_REGION' in os.environ:
        os.environ['AWS_DEFAULT_REGION'] = os.environ['AWS_REGION']


    # ----------------------------------------------------------------------------------------------
    # Ops start here...
    # ----------------------------------------------------------------------------------------------
    with AWSContextManager(options.aws_profile, options.region) as ctx:

        if operation == 'test-funcs':

            # Simple test-assertions
            print('\nLooking up Permission Set \"%s\": %s' % (options.ps_name, "Success." if (options.ps_name ==
                  get_permission_set_name_by_arn(ctx, get_permission_set_arn_by_name(ctx, options.ps_name))) else "Failed."))
            print('Looking up Application \"%s\": %s' % (options.app_name, "Success." if (options.app_name ==
                  get_application_name_by_arn(ctx, get_application_arn_by_name(ctx, options.app_name))) else "Failed."))
            print('Looking up TTI \"%s\": %s' % (options.tti_name, "Success." if (options.tti_name ==
                  get_tti_name_by_arn(ctx, get_tti_arn_by_name(ctx, options.tti_name))) else "Failed."))
            print('Looking up Group \"%s\": %s' % (options.group_name, "Success." if (options.group_name ==
                  get_group_name_by_id(ctx, get_group_id_by_name(ctx, options.group_name))) else "Failed."))
            print('Looking up User \"%s\": %s' % (options.user_name, "Success." if (options.user_name ==
                  get_user_name_by_id(ctx, get_user_id_by_name(ctx, options.user_name))) else "Failed."))

            print("DONE.\n")


        # Utility operations using the funcs...
        elif operation == 'lookup-account-name':

            acct_name = get_acct_name_by_id(ctx, options.acct_id)
            if acct_name == None:
                print('Account id \"%s\" not found.' % options.acct_id)
            else:
                print(acct_name)


        elif operation == 'lookup-user-name':

            user_name = get_user_name_by_id(ctx, options.user_id)
            if user_name == None:
                print('User id \"%s\" not found.' % options.user_id)
            else:
                print(user_name)


        elif operation == 'lookup-group-name':

            group_name = get_group_name_by_id(ctx, options.group_id)
            if group_name == None:
                print('Group id \"%s\" not found.' % options.group_id)
            else:
                print(group_name)


        elif operation == 'lookup-ps-name':

            ps_name = get_permission_set_name_by_arn(ctx, options.ps_arn)
            if ps_name == None:
                print('Permission set Arn \"%s\" not found.' % options.ps_arn)
            else:
                print(ps_name)


        elif operation == 'lookup-app-name':

            app_name = get_application_name_by_arn(ctx, options.app_arn)
            if app_name == None:
                print('Application \"%s\" not found.' % options.app_arn)
            else:
                print(app_name)


        elif operation == 'lookup-tti-name':

            tti_name = get_tti_name_by_arn(ctx, options.tti_arn)
            if tti_name == None:
                print('TTI \"%s\" not found.' % options.tti_arn)
            else:
                print(tti_name)


        elif operation == 'lookup-account-id':

            acct_id = get_acct_id_by_name(ctx, options.acct_name)
            if acct_id == None:
                print('Account name \"%s\" not found.' % options.acct_name)
            else:
                print(acct_id)


        elif operation == 'lookup-user-id':

            user_id = get_user_id_by_name(ctx, options.user_name)
            if user_id == None:
                print('User name \"%s\" not found.' % options.user_name)
            else:
                print(user_id)


        elif operation == 'lookup-group-id':

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group name \"%s\" not found.' % options.group_name)
            else:
                print(group_id)


        elif operation == 'lookup-ps-arn':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('Permission set name \"%s\" not found.' % options.ps_name)
            else:
                print(ps_arn)


        elif operation == 'lookup-app-arn':

            app_arn = get_application_arn_by_name(ctx, options.app_name)
            if app_arn == None:
                print('Application name \"%s\" not found.' % options.app_name)
            else:
                print(app_arn)


        elif operation == 'lookup-tti-arn':

            tti_arn = get_tti_arn_by_name(ctx, options.tti_name)
            if tti_arn == None:
                print('TTI name \"%s\" not found.' % options.tti_name)
            else:
                print(tti_arn)


# --------------------------------------------------------------------------------------------------
# Main...
# --------------------------------------------------------------------------------------------------
def main():
    rc = 0

    try:
        # Get loglevel from environment
        try:
            LOGLEVEL = os.environ.get('LOGLEVEL').upper()
        except AttributeError as e:
            LOGLEVEL = 'CRITICAL'

        logging.basicConfig(level=LOGLEVEL)

        rc = run()

    except KeyboardInterrupt:
        print('Killed by keyboard interrupt.')
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)

    except Exception as e:
        print('Error (%s) %s' % (e.__class__.__name__, e))
        rc = 1
        exit(rc)

    return(rc)



if __name__ == '__main__':
    sys.exit(main())
