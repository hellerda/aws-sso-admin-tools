#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool for managing account assignments in AWS Identity Center.

(c) Copyright Dave Heller 2023
'''

import json
import os
import sys

from funcs import *

from optparse import OptionParser


# --------------------------------------------------------------------------------------------------
# Functions...
# --------------------------------------------------------------------------------------------------
def list_assigned_principals_for_ps_in_account(ctx, acct_id, ps_arn):

    sso_admin_client = ctx.session.client('sso-admin')

    paginator = sso_admin_client.get_paginator('list_account_assignments')

    for page in paginator.paginate(
        InstanceArn = ctx.instance_arn,
        AccountId = acct_id,
        PermissionSetArn = ps_arn
    ):
        for item in page['AccountAssignments']:

            if (item['PrincipalType'] == 'USER'):
                print('- USER: %s' % get_user_name_by_id(ctx, item['PrincipalId']))
            elif (item['PrincipalType'] == 'GROUP'):
                print('- GROUP: %s' % get_group_name_by_id(ctx, item['PrincipalId']))


def get_ps_provisioned_to_account(ctx, acct_id):

    sso_admin_client = ctx.session.client('sso-admin')

    try:
        results = (
            sso_admin_client.get_paginator(
                'list_permission_sets_provisioned_to_account')
            .paginate(
                InstanceArn = ctx.instance_arn,
                AccountId = acct_id)
            .build_full_result()
        )
        return (results.pop('PermissionSets', None))

    except Exception as e:
        print("Error: %s" % str(e))
        exit(1)


def get_accounts_for_provisioned_permission_set(ctx, ps_arn):

    sso_admin_client = ctx.session.client('sso-admin')

    try:
        results = (
            sso_admin_client.get_paginator(
                'list_accounts_for_provisioned_permission_set')
            .paginate(
                InstanceArn = ctx.instance_arn,
                PermissionSetArn = ps_arn)
            .build_full_result()
        )
        return (results.pop('AccountIds', None))

    except Exception as e:
        print("Error: %s" % str(e))
        exit(1)


def get_organizational_root(ctx):
    '''
    Get organizational root (requires ListRoots permission)
    '''

    organizations_client = ctx.session.client('organizations')

    try:
        for page in organizations_client.get_paginator('list_roots').paginate():
            for item in page['Roots']:
                if (item['Name'] == 'Root'):
                    return item['Id']

        raise ValueError('Organizational root not found.')

    except Exception as e:
        print("Error: %s" % str(e))
        exit(1)


def get_ou_id_by_name(ctx, ou_name):
    '''
    Lookup an OU (requires ListOrganizationalUnitsForParent)
    '''

    organizations_client = ctx.session.client('organizations')

    parent_id = get_organizational_root(ctx)

    try:
        for page in organizations_client.get_paginator('list_organizational_units_for_parent').paginate(
             ParentId = parent_id
        ):
            # TODO: Search paths, currently it will only find root-level OUs
            for item in page['OrganizationalUnits']:
                if (item['Name'] == ou_name):
                    return item['Id']

        raise ValueError('Organizational unit \"%s\" not found.' % ou_name)

    except Exception as e:
        print('Error: %s' % e)
        exit(1)


# --------------------------------------------------------------------------------------------------
# Main...
# --------------------------------------------------------------------------------------------------
def main():

    cmds_usage = '''\nAvailable commands:
    create-account-assignment
    delete-account-assignment
    provision-permission-set
    list-assigned-principals-for-ps-in-account
    list-accounts-for-provisioned-permission-set
    list-all-acct-assignments-for-provisioned-permission-set
    list-all-acct-assignments-for-principal
    list-all-acct-assignments-for-ps-in-org
    list-all-permission-sets-in-org
    list-all-permission-set-assignments-in-account
    list-all-permission-set-assignments-in-ou
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog list-accounts-for-provisioned-permission-set --ps-name MyPermissionSet\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--acct-id', dest='acct_id', default=None,
                      help='Account ID')
    parser.add_option('--ps-name', dest='ps_name', default=None,
                      help='Permission Set name')
    parser.add_option('--user-name', dest='user_name', default=None,
                      help='User name')
    parser.add_option('--group-name', dest='group_name', default=None,
                      help='Group name')
    parser.add_option('--ou-name', dest='ou_name', default=None,
                      help='OU name')

    (options, args) = parser.parse_args()

    def need_acct_id():
        if options.acct_id == None:
            print('No account specified; use --acct-id.')
            exit(1)

    def need_ps_name():
        if options.ps_name == None:
            print('No permission set specified; use --ps-name.')
            exit(1)

    def need_user_or_group_name():
        if (options.user_name == None and options.group_name) == None:
            print('No user or group specified; use one of: --user-name, --group-name.')
            exit(1)

    def need_ou_name():
        if options.ou_name == None:
            print('No organizational unit specified; use --ou-name.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'create-account-assignment':
            need_ps_name()
            need_user_or_group_name()
            operation = op
        elif op == 'delete-account-assignment':
            need_ps_name()
            need_user_or_group_name()
            operation = op
        elif op == 'provision-permission-set':
            need_ps_name()
            operation = op
        elif op == 'list-assigned-principals-for-ps-in-account':
            need_acct_id()
            need_ps_name()
            operation = op
        elif op == 'list-accounts-for-provisioned-permission-set':
            need_ps_name()
            operation = op
        elif op == 'list-all-acct-assignments-for-provisioned-permission-set':
            need_ps_name()
            operation = op
        elif op == 'list-all-acct-assignments-for-principal':
            need_user_or_group_name()
            operation = op
        elif op == 'list-all-acct-assignments-for-ps-in-org':
            operation = op
        elif op == 'list-all-permission-sets-in-org':
            operation = op
        elif op == 'list-permission-sets-provisioned-to-account':
            need_acct_id()
            operation = op
        elif op == 'list-all-permission-set-assignments-in-account':
            need_acct_id()
            operation = op
        elif op == 'list-all-permission-set-assignments-in-ou':
            need_ou_name()
            operation = op
        else:
            print('Unknown command: %s\n' % op)

    if operation == None:
        parser.print_help()
        exit(1)


    # ----------------------------------------------------------------------------------------------
    # Ops start here...
    # ----------------------------------------------------------------------------------------------
    with AWSContextManager(options.aws_profile) as ctx:

        sso_admin_client = ctx.session.client('sso-admin')
        organizations_client = ctx.session.client('organizations')

        instance_arn = ctx.instance_arn

        if operation == 'create-account-assignment':

            response = {}
            PrincipalType = ''
            PrincipalId = ''

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('permission set \'%s\' not found.' % options.ps_name)
                exit(1)

            if options.user_name != None:
                user_id = get_user_id_by_name(ctx, options.user_name)
                if user_id == None:
                    print('User \'%s\' not found.' % options.user_name)
                    exit(1)
                print('Assigning User \"%s\"...' % options.user_name)
                PrincipalType = 'USER'
                PrincipalId = user_id
            else:
                group_id = get_group_id_by_name(ctx, options.group_name)
                if group_id == None:
                    print('Group \'%s\' not found.' % options.group_name)
                    exit(1)
                print('Assigning Group \"%s\"...' % options.group_name)
                PrincipalType = 'GROUP'
                PrincipalId = group_id

            response = sso_admin_client.create_account_assignment (
                InstanceArn = instance_arn,
                PermissionSetArn = ps_arn,
                TargetType = 'AWS_ACCOUNT',
                TargetId = options.acct_id,
                PrincipalType = PrincipalType,
                PrincipalId = PrincipalId
            )
            response.pop('ResponseMetadata')
            print(json.dumps(response, indent=4, sort_keys=False, default=str))


        elif operation == 'delete-account-assignment':

            response = {}
            PrincipalType = ''
            PrincipalId = ''

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('permission set \'%s\' not found.' % options.ps_name)
                exit(1)

            if options.user_name != None:
                user_id = get_user_id_by_name(ctx, options.user_name)
                if user_id == None:
                    print('User \'%s\' not found.' % options.user_name)
                    exit(1)
                print('Assigning User \"%s\"...' % options.user_name)
                PrincipalType = 'USER'
                PrincipalId = user_id
            else:
                group_id = get_group_id_by_name(ctx, options.group_name)
                if group_id == None:
                    print('Group \'%s\' not found.' % options.group_name)
                    exit(1)
                print('Assigning Group \"%s\"...' % options.group_name)
                PrincipalType = 'GROUP'
                PrincipalId = group_id

            response = sso_admin_client.delete_account_assignment (
                InstanceArn = instance_arn,
                PermissionSetArn = ps_arn,
                TargetType = 'AWS_ACCOUNT',
                TargetId = options.acct_id,
                PrincipalType = PrincipalType,
                PrincipalId = PrincipalId
            )
            response.pop('ResponseMetadata')
            print(json.dumps(response, indent=4, sort_keys=False, default=str))


        elif operation == 'provision-permission-set':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('permission set \'%s\' not found.' % options.ps_name)
                exit(1)

            if (options.acct_id == None):

                response = sso_admin_client.provision_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn,
                    TargetType = 'ALL_PROVISIONED_ACCOUNTS'
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            else:

                response = sso_admin_client.provision_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn,
                    TargetType = 'AWS_ACCOUNT',
                    TargetId = options.acct_id
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))


        # --------------------------------------------------------------------------
        # This is a view BY ACCOUNT and PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-assigned-principals-for-ps-in-account':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('permission set \'%s\' not found.' % options.ps_name)
                exit(1)

            print('Listing assigned principals for PS \'%s\' in account: %s...' %
                (options.ps_name, options.acct_id))

            list_assigned_principals_for_ps_in_account(ctx, options.acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is our BASIC view BY PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-accounts-for-provisioned-permission-set':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('permission set \'%s\' not found.' % options.ps_name)
                exit(1)

            print('Listing assigned accounts for PS \'%s\'...' % options.ps_name)

            for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):
                print('- %s' % acct_id)


        # --------------------------------------------------------------------------
        # This is our FULL view BY PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-acct-assignments-for-provisioned-permission-set':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print('permission set \'%s\' not found.' % options.ps_name)
                exit(1)

            print('Listing assigned accounts for PS \'%s\'...' % options.ps_name)

            for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):
                print('ACCT: %s' % acct_id)
                list_assigned_principals_for_ps_in_account(ctx, acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is our FULL view BY PRINCIPAL.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-acct-assignments-for-principal':

            user_id = None
            group_id = None
            assignments = {}

            if options.user_name != None:
                user_id = get_user_id_by_name(ctx, options.user_name)
                if user_id == None:
                    print('User \'%s\' not found.' % options.user_name)
                    exit(1)
                print('Listing all Account assignments for \"%s\"...' % options.user_name)
            else:
                group_id = get_group_id_by_name(ctx, options.group_name)
                if group_id == None:
                    print('Group \'%s\' not found.' % options.group_name)
                    exit(1)
                print('Listing all Account assignments for \"%s\"...' % options.group_name)

            paginator = sso_admin_client.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn = instance_arn):

                for ps_arn in page['PermissionSets']:
                    print('Checking permission set \"%s\"...' %
                          get_permission_set_name_by_arn(ctx, ps_arn), ' '*30, end='\r')

                    for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):

                        paginator = sso_admin_client.get_paginator('list_account_assignments')
                        for page in paginator.paginate(
                            InstanceArn = ctx.instance_arn,
                            AccountId = acct_id,
                            PermissionSetArn = ps_arn
                        ):
                            for item in page['AccountAssignments']:

                                if (item['PrincipalType'] == 'USER') and (options.user_name != None):
                                    if item['PrincipalId'] == user_id:
                                        assignments.setdefault(acct_id, []).append(
                                            get_permission_set_name_by_arn(ctx, ps_arn))

                                elif (item['PrincipalType'] == 'GROUP'):
                                    if item['PrincipalId'] == group_id:
                                        assignments.setdefault(acct_id, []).append(
                                            get_permission_set_name_by_arn(ctx, ps_arn))

            for k, v in sorted(assignments.items()):
                print('Assigned PS in account \"%s\"...' % k)
                for ps in sorted(v):
                    print('- %s' % ps)

            print(' '*60, end='\r')


        # --------------------------------------------------------------------------
        # This is a view BY ORG, but really a view BY PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-acct-assignments-for-ps-in-org':

            print('Listing all Permission Set assignments in the Organization...')

            paginator = sso_admin_client.get_paginator('list_permission_sets')

            for page in paginator.paginate(InstanceArn = instance_arn):

                for ps_arn in page['PermissionSets']:
                    print('Listing account assignments for PS \'%s\'...' %
                        get_permission_set_name_by_arn(ctx, ps_arn))

                    for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):
                        print('ACCT: %s' % acct_id)
                        list_assigned_principals_for_ps_in_account(ctx, acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is like above but just lists PS without the acct assignment lookup.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-permission-sets-in-org':

            print('Listing all Permission Sets in the Organization...')

            paginator = sso_admin_client.get_paginator('list_permission_sets')

            for page in paginator.paginate(InstanceArn = instance_arn):

                for ps_arn in page['PermissionSets']:

                    ps = sso_admin_client.describe_permission_set (
                        InstanceArn = ctx.instance_arn,
                        PermissionSetArn = ps_arn
                    )
                    ps_name = ps['PermissionSet']['Name']
                    ps_dura = ps['PermissionSet']['SessionDuration']
                    ps_desc = ps['PermissionSet'].pop('Description', '-')

                    print('PS: \"%s\"  Description: \"%s\" (%s)' %
                          (ps_name, ps_desc, ps_dura))


        # --------------------------------------------------------------------------
        # This is our BASIC view BY ACCOUNT.
        # --------------------------------------------------------------------------
        elif operation == 'list-permission-sets-provisioned-to-account':

            print('Listing Permission Sets provisioned to account: %s...' % options.acct_id)

            ps_arns = get_ps_provisioned_to_account(ctx, options.acct_id)

            if ps_arns != None:

                for ps_arn in ps_arns:
                    print('- %s' % get_permission_set_name_by_arn(ctx, ps_arn))


        # --------------------------------------------------------------------------
        # This is our FULL view BY ACCOUNT.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-permission-set-assignments-in-account':

            print('Listing all Permission Set assignments in account: %s...' % options.acct_id)

            ps_arns = get_ps_provisioned_to_account(ctx, options.acct_id)

            if ps_arns != None:

                for ps_arn in ps_arns:
                    print('PS: %s' % get_permission_set_name_by_arn(ctx, ps_arn))
                    list_assigned_principals_for_ps_in_account(ctx, options.acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is a view BY OU, but really a view BY ACCOUNT.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-permission-set-assignments-in-ou':

            ou_id = get_ou_id_by_name(ctx, options.ou_name)

            print('Listing all Permission Set assignments in OU: %s...' % options.ou_name)

            for page in organizations_client.get_paginator('list_accounts_for_parent').paginate(
                ParentId = ou_id
            ):
                for item in page['Accounts']:
                    acct_id = item['Id']
                    print('Listing all Permission Set assignments in account: %s...' % acct_id)
                    ps_arns = get_ps_provisioned_to_account(ctx, acct_id)

                    if ps_arns != None:

                        for ps_arn in ps_arns:
                            print('PS: %s' % get_permission_set_name_by_arn(ctx, ps_arn))
                            list_assigned_principals_for_ps_in_account(ctx, acct_id, ps_arn)



if __name__ == '__main__':
    rc = 0

    try:
        rc = main()

    except KeyboardInterrupt:
        print('Killed by keyboard interrupt.')
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)

    except Exception as e:
        print("Error (%s) %s" % (e.__class__.__name__, e))
        rc = 1
        exit(rc)

    sys.exit(rc)
