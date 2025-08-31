#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool for managing account assignments in AWS Identity Center.

(c) Copyright Dave Heller 2025
'''

import json
import logging
import os
import sys

# from funcs import *

if __package__ is None or __package__ == '' :
    from funcs import *
else:
    from .funcs import *

from botocore.exceptions import ClientError
from optparse import OptionParser


# --------------------------------------------------------------------------------------------------
# Functions...
# --------------------------------------------------------------------------------------------------
def list_assigned_principals_for_ps_in_account(ctx, indent, acct_id, ps_arn):

    bullet = ''
    if indent == 1:
        bullet = '* '
    elif indent == 2:
        bullet = '  * '

    sso_admin_client = ctx.session.client('sso-admin')

    paginator = sso_admin_client.get_paginator('list_account_assignments')

    for page in paginator.paginate(
        InstanceArn = ctx.instance_arn,
        AccountId = acct_id,
        PermissionSetArn = ps_arn
    ):
        for item in page['AccountAssignments']:

            if (item['PrincipalType'] == 'USER'):
                pn = get_user_name_by_id(ctx, item['PrincipalId'])
                print('%sUSER: %s' % (bullet, item['PrincipalId'] if pn == None else pn))
            elif (item['PrincipalType'] == 'GROUP'):
                pn = get_group_name_by_id(ctx, item['PrincipalId'])
                print('%sGROUP: %s' % (bullet, item['PrincipalId'] if pn == None else pn))


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


def list_accounts_and_ous_in_parent(ctx, parent_id):
    '''
    List all accounts and child OUs in a parent (OU or Root)
    Returns tuple of (accounts_list, ous_list)
    '''
    organizations_client = ctx.session.client('organizations')

    accounts = []
    ous = []

    try:
        # Get accounts
        paginator = organizations_client.get_paginator('list_accounts_for_parent')
        for page in paginator.paginate(ParentId=parent_id):
            for acct in page['Accounts']:
                accounts.append({
                    'Name': acct['Name'],
                    'Id': acct['Id'],
                    'JoinedTimestamp': acct['JoinedTimestamp'],
                    'Email': acct['Email']
                })

        # Get child OUs
        paginator = organizations_client.get_paginator('list_organizational_units_for_parent')
        for page in paginator.paginate(ParentId=parent_id):
            for ou in page['OrganizationalUnits']:
                ous.append({
                    'Name': ou['Name'],
                    'Id': ou['Id'],
                    'Arn': ou['Arn']
                })

        return accounts, ous

    except organizations_client.exceptions.ParentNotFoundException:
        return [], []

    except Exception as e:
        print("Error: %s" % str(e))
        return [], []


# Tree character generator
gen_prefix = lambda prefix, is_last, ascii_mode: (
    (
        prefix + ('`-- ' if is_last else '|-- '),
        prefix + ('    ' if is_last else '|   ')
    ) if ascii_mode else (
        prefix + ('└── ' if is_last else '├── '),
        prefix + ('    ' if is_last else prefix + '│   ')
    )
)


def display_org_tree_single_level(ctx, parent_id, ou_tree_only=False, ascii_mode=False):
    '''
    Display organizational tree for single level only
    '''
    accounts, ous = list_accounts_and_ous_in_parent(ctx, parent_id)

    # Combine and sort all items
    all_items = []

    # Add OUs
    for ou in sorted(ous, key=lambda x: x['Name'].lower()):
        ou_accounts, _ = list_accounts_and_ous_in_parent(ctx, ou['Id'])
        account_count = len(ou_accounts)
        all_items.append(('ou', ou, account_count))

    # Add accounts if not ou_tree_only
    if not ou_tree_only:
        for account in sorted(accounts, key=lambda x: x['Name'].lower()):
            all_items.append(('account', account, None))

    # Display items with tree characters
    for i, (item_type, item, count) in enumerate(all_items):
        is_last = (i == len(all_items) - 1)
        current_prefix, _ = gen_prefix('', is_last, ascii_mode)

        if item_type == 'ou':
            print('%sOU: %s (%s) (%d)' % (current_prefix, item['Name'], item['Id'], count))
        else:
            print('%sAccount: %s (%s) - Email: %s - Created: %s' % (
                current_prefix,
                item['Name'],
                item['Id'],
                item['Email'],
                str(item['JoinedTimestamp']).split()[0]
            ))

    if not all_items:
        empty_prefix, _ = gen_prefix('', True, ascii_mode)
        print('%sNo accounts or child OUs found.' % empty_prefix)


def display_org_tree_recursive(ctx, parent_id, parent_name, indent_level=0, ou_tree_only=False, prefix='', ascii_mode=False):
    '''
    Recursively display organizational tree with accounts and OUs
    '''
    accounts, ous = list_accounts_and_ous_in_parent(ctx, parent_id)

    # Combine and sort all items
    all_items = []

    # Add OUs
    for ou in sorted(ous, key=lambda x: x['Name'].lower()):
        ou_accounts, _ = list_accounts_and_ous_in_parent(ctx, ou['Id'])
        account_count = len(ou_accounts)
        all_items.append(('ou', ou, account_count))

    # Add accounts if not ou_tree_only
    if not ou_tree_only:
        for account in sorted(accounts, key=lambda x: x['Name'].lower()):
            all_items.append(('account', account, None))

    # Display items with tree characters
    for i, (item_type, item, count) in enumerate(all_items):
        is_last = (i == len(all_items) - 1)
        current_prefix, next_prefix = gen_prefix(prefix, is_last, ascii_mode)

        if item_type == 'ou':
            print('%sOU: %s (%s) (%d)%s' % (current_prefix,
                  item['Name'], item['Id'], count, '' if ou_tree_only else ':'))
            display_org_tree_recursive(
                ctx, item['Id'], item['Name'], indent_level + 1, ou_tree_only, next_prefix, ascii_mode)
        else:
            print('%sAccount: %s (%s) - Email: %s - Created: %s' % (
                current_prefix,
                item['Name'],
                item['Id'],
                item['Email'],
                str(item['JoinedTimestamp']).split()[0]
            ))


# ------------------------------------------------------------------------------
# This is still a work in progress...
# ------------------------------------------------------------------------------
def get_target_arns_for_ps(ctx, ps_arn):
    '''
    Determine if PS is assume-role type and return list of target arns
    '''

    sso_admin_client = ctx.session.client('sso-admin')

    try:
        response = sso_admin_client.get_inline_policy_for_permission_set (
            InstanceArn = ctx.instance_arn,
            PermissionSetArn = ps_arn
        )

        # PS has no inline policy.
        if response['InlinePolicy'] == '':
            return []

        policy = json.loads(response['InlinePolicy'])

        if not isinstance(policy['Statement'], dict):
            logging.info('This is not a SIMPLE permissions policy, in PS arn "%s"' % ps_arn)
            return []

        arns_list = []
        if (policy['Statement']['Action'] == 'sts:AssumeRole'):
            arns_list = policy['Statement']['Resource']
            if not isinstance(arns_list, list):
                return []
            else:
                return arns_list

        else:
            logging.info('This is NOT an AssumeRole permissions policy, in PS arn "%s"' % ps_arn)
            return []

    except Exception as e:
        print("Error in get_target_arns_for_ps(): %s" % str(e))
        exit(1)


# --------------------------------------------------------------------------------------------------
# Run...
# --------------------------------------------------------------------------------------------------
def run():

    cmds_usage = '''\nAvailable commands:
    describe-account
    create-account-assignment
    delete-account-assignment
    provision-ps
    list-assigned-principals-for-ps-in-account
    list-accounts-for-provisioned-ps
    list-all-acct-assignments-for-provisioned-ps
    list-all-acct-assignments-for-user
    list-all-acct-assignments-for-group
    list-all-acct-assignments-for-principal
    list-all-acct-assignments-for-ps-in-org
    list-all-ps-in-org
    list-all-ps-assignments-in-account
    list-all-ps-assignments-in-ou
    list-all-accounts-in-ou
    verify-access-for-user
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog list-accounts-for-provisioned-ps --ps-name MyPermissionSet\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--region', dest='region', default=None,
                      help='AWS region to use')
    parser.add_option('--acct-id', dest='acct_id', default=None,
                      help='Account ID')
    parser.add_option('--acct-name', dest='acct_name', default=None,
                      help='Account name')
    parser.add_option('--ps-name', dest='ps_name', default=None,
                      help='Permission Set name')
    parser.add_option('--ps-arn', dest='ps_arn', default=None,
                      help='Permission Set Arn')
    parser.add_option('--user-id', dest='user_id', default=None,
                      help='User ID')
    parser.add_option('--user-name', dest='user_name', default=None,
                      help='User name')
    parser.add_option('--group-id', dest='group_id', default=None,
                      help='Group ID')
    parser.add_option('--group-name', dest='group_name', default=None,
                      help='Group name')
    parser.add_option('--ou-name', dest='ou_name', default=None,
                      help='OU name or "Root" for organization root')
    parser.add_option('--ou-id', dest='ou_id', default=None,
                      help='OU or Organization ID')
    parser.add_option('--ascii', dest='ascii', default=False,
                      action='store_true',
                      help='Use ASCII characters only for output')
    parser.add_option('--full-tree', dest='full_tree', default=False,
                      action='store_true',
                      help='Show full organizational tree recursively')
    parser.add_option('--ou-tree', dest='ou_tree', default=False,
                      action='store_true',
                      help='Show only organizational units, suppress account listings')
    parser.add_option('--show-acct-names', dest='show_acct_names', default=True,
                      action='store_true',
                      help='Show account names where applicable')
    parser.add_option('--no-show-acct-names', dest='show_acct_names', default=True,
                      action='store_false',
                      help='Suppress showing account names where applicable')
    parser.add_option('--show-principal-names', dest='show_principal_names', default=True,
                      action='store_true',
                      help='Show associated user or group names where applicable')
    parser.add_option('--no-show-principal-names', dest='show_principal_names', default=True,
                      action='store_false',
                      help='Suppress showing user or group names where applicable')
    parser.add_option('--show-ps-desc', dest='show_ps_desc', default=True,
                      action='store_true',
                      help='Show permission set descriptions where applicable')
    parser.add_option('--no-show-ps-desc', dest='show_ps_desc', default=True,
                      action='store_false',
                      help='Suppress showing permission set descriptions where applicable')
    parser.add_option('--show-target-arns', dest='show_target_arns', default=False,
                      action='store_true',
                      help='Show assume-role target Arns for a PS')
    parser.add_option('--no-show-target-arns', dest='show_target_arns', default=False,
                      action='store_false',
                      help='Suppress showing assume-role target Arns for a PS')
    parser.add_option('--compact', dest='compact', default=True,
                      action='store_true',
                      help='Show compact output where applicable')
    parser.add_option('--no-compact', '--expand', dest='compact', default=True,
                      action='store_false',
                      help='Show expanded output where applicable')
    parser.add_option('-j', '--json-only', dest='json_only', default=False,
                      action='store_true',
                      help='Output JSON only, quash human-readable fluff.')
    parser.add_option('--qa', dest='quash_admin', default=False,
                      action='store_true',
                      help='Suppress showing entries for AdministratorAccess PS')

    (options, args) = parser.parse_args()

    def need_acct_id():
        if options.acct_id == None:
            print('No account specified; use --acct-id.')
            exit(1)

    def need_acct_id_or_name():
        if (options.acct_id == None and options.acct_name == None):
            print('No account specified; use one of: --acct-id, --acct-name.')
            exit(1)

    def need_ps_name():
        if options.ps_name == None:
            print('No permission set specified; use --ps-name.')
            exit(1)

    def need_ps_name_or_arn():
        if (options.ps_name == None and options.ps_arn == None):
            print('No permission set specified; use one of: --ps-name, --ps-arn.')
            exit(1)

    def need_user_name():
        if options.user_name == None:
            print('No user specified; use --user-name.')
            exit(1)

    def need_user_or_group_name():
        if (options.user_name == None and options.group_name == None):
            print('No user or group specified; use one of: --user-name, --group-name.')
            exit(1)

    def need_principal():
        if (options.user_name == None and options.user_id == None and
                options.group_name == None and options.group_id == None):
            print('No user or group specified; use one of: %s' %
                  '--user-name, --user-id, --group-name, --group-id.')
            exit(1)

    def need_ou_name():
        if options.ou_name == None:
            print('No organizational unit specified; use --ou-name.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'describe-account':
            need_acct_id_or_name()
            operation = op
        elif op == 'create-account-assignment':
            need_ps_name_or_arn()
            need_principal()
            operation = op
        elif op == 'delete-account-assignment':
            need_ps_name_or_arn()
            need_principal()
            operation = op
        elif op == 'provision-ps':
            need_ps_name_or_arn()
            operation = op
        elif op == 'list-assigned-principals-for-ps-in-account':
            need_acct_id()
            need_ps_name_or_arn()
            operation = op
        elif op == 'list-accounts-for-provisioned-ps':
            need_ps_name_or_arn()
            operation = op
        elif op == 'list-all-acct-assignments-for-provisioned-ps':
            need_ps_name_or_arn()
            operation = op
        elif op == 'list-all-acct-assignments-for-user':
            need_user_or_group_name()
            operation = op
        elif op == 'list-all-acct-assignments-for-group':
            need_user_or_group_name()
            operation = op
        elif op == 'list-all-acct-assignments-for-principal':
            need_user_or_group_name()
            operation = op
        elif op == 'list-all-acct-assignments-for-ps-in-org':
            operation = op
        elif op == 'list-all-ps-in-org':
            operation = op
        elif op == 'list-ps-provisioned-to-account':
            need_acct_id()
            operation = op
        elif op == 'list-all-ps-assignments-in-account':
            need_acct_id()
            operation = op
        elif op == 'list-all-ps-assignments-in-ou':
            need_ou_name()
            operation = op
        elif op == 'list-all-accounts-in-ou':
            operation = op
        elif op == 'verify-access-for-user':
            need_acct_id()
            need_ps_name_or_arn()
            need_user_name()
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

        sso_admin_client = ctx.session.client('sso-admin')
        organizations_client = ctx.session.client('organizations')

        instance_arn = ctx.instance_arn

        if operation == 'describe-account':

            acct = None
            tags = {}

            # Get account info
            if options.acct_name != None:
                acct = get_acct_desc_by_name(ctx, options.acct_name)
                if acct == None:
                    raise SystemExit('Account "%s" not found.' % options.acct_name)
            else:
                acct = get_acct_desc_by_id(ctx, options.acct_id)
                if acct == None:
                    raise SystemExit('Account "%s" not found.' % options.acct_id)

            # Get org/OU info
            try:
                parent_ou = get_account_parent_ou(ctx, acct['Id'])
                if parent_ou:
                    acct['Parent'] = parent_ou
                else:
                    acct['Parent'] = {
                        'Type': 'UNKNOWN', 'Name': 'Unknown', 'Id': 'Unknown', 'Arn': None}
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    acct['Parent'] = {
                        'Type': 'ACCESS_DENIED', 'Name': 'AccessDenied', 'Id': 'AccessDenied', 'Arn': None}
                else:
                    raise

            # Get account tags
            try:
                tags = organizations_client.list_tags_for_resource (
                    ResourceId = acct['Id']
                )
                acct['Tags'] = tags['Tags']
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    acct['Tags'] = [{'Key': 'NoTags', 'Value': 'AccessDenied'}]
                else:
                    raise

            if options.json_only == True:
                print(json.dumps(acct, indent=4, sort_keys=False, default=str))
            else:
                # Display account info
                print('Account: %s ("%s"): email: %s %s %s on: %s' % (
                    acct['Id'], acct['Name'], acct['Email'], acct['Status'],
                    acct['JoinedMethod'], str(acct['JoinedTimestamp']).split()[0]))

                # Display org/OU info
                parent = acct.get('Parent', {})
                if parent.get('Type') == 'ROOT':
                    print('- Parent: Organizational root %s (%s) - (%s)' %
                          (parent['Name'], parent['Id'], parent['Arn']))
                elif parent.get('Type') == 'ORGANIZATIONAL_UNIT':
                    print('- Parent: OU "%s" (%s) - (%s)' %
                          (parent['Name'], parent['Id'], parent['Arn']))
                elif parent.get('Type') == 'ACCESS_DENIED':
                    print('- Parent: Access denied')
                else:
                    print('- Parent: Unknown')

                # Display account tags
                for tag in acct.get('Tags', []):
                    print('- Tag: "%s" = "%s"' % (tag['Key'], tag['Value']))


        elif operation == 'create-account-assignment':

            response = {}
            PrincipalType = ''
            PrincipalId = ''

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

            if options.user_id != None:
                user_id = options.user_id
                print('Assigning User "%s"...' % options.user_id)
                PrincipalType = 'USER'
                PrincipalId = user_id
            elif options.user_name != None:
                user_id = get_user_id_by_name(ctx, options.user_name)
                if user_id == None:
                    raise SystemExit('User "%s" not found.' % options.user_name)
                print('Assigning User "%s"...' % options.user_name)
                PrincipalType = 'USER'
                PrincipalId = user_id
            elif options.group_id != None:
                group_id = options.group_id
                print('Assigning Group "%s"...' % options.group_id)
                PrincipalType = 'GROUP'
                PrincipalId = group_id
            elif options.group_name != None:
                group_id = get_group_id_by_name(ctx, options.group_name)
                if group_id == None:
                    raise SystemExit('Group "%s" not found.' % options.group_name)
                print('Assigning Group "%s"...' % options.group_name)
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

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

            if options.user_id != None:
                user_id = options.user_id
                print('Unassigning User "%s"...' % options.user_id)
                PrincipalType = 'USER'
                PrincipalId = user_id
            elif options.user_name != None:
                user_id = get_user_id_by_name(ctx, options.user_name)
                if user_id == None:
                    raise SystemExit('User "%s" not found.' % options.user_name)
                print('Unassigning User "%s"...' % options.user_name)
                PrincipalType = 'USER'
                PrincipalId = user_id
            elif options.group_id != None:
                group_id = options.group_id
                print('Unassigning Group "%s"...' % options.group_id)
                PrincipalType = 'GROUP'
                PrincipalId = group_id
            elif options.group_name != None:
                group_id = get_group_id_by_name(ctx, options.group_name)
                if group_id == None:
                    raise SystemExit('Group "%s" not found.' % options.group_name)
                print('Unassigning Group "%s"...' % options.group_name)
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


        elif operation == 'provision-ps':

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

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

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

            print('Listing assigned principals for PS "%s" in account: %s...' %
                (options.ps_name, options.acct_id))

            list_assigned_principals_for_ps_in_account(ctx, 1, options.acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is our BASIC view BY PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-accounts-for-provisioned-ps':

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

            print('Listing assigned accounts for PS "%s"...' % options.ps_name)

            for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):

                if options.show_acct_names == False:
                    print('- %s' % acct_id)
                else:
                    print('- %s -- ("%s")' % (acct_id, get_acct_name_by_id(ctx, acct_id)))


        # --------------------------------------------------------------------------
        # This is our FULL view BY PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-acct-assignments-for-provisioned-ps':

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

            print('Listing assigned accounts for PS "%s"...' % options.ps_name)

            for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):

                if options.show_acct_names == False:
                    print('ACCT: %s...' % acct_id)
                else:
                    print('ACCT: %s --- ("%s")...' % (acct_id, get_acct_name_by_id(ctx, acct_id)))

                list_assigned_principals_for_ps_in_account(ctx, 1, acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is our FULL view BY PRINCIPAL.
        # --------------------------------------------------------------------------
        elif operation in ['list-all-acct-assignments-for-user',
                           'list-all-acct-assignments-for-group',
                           'list-all-acct-assignments-for-principal']:

            user_id = None
            group_id = None
            principal_id = None
            principal_type = None
            assignments = {}

            if options.user_name != None:
                user_id = get_user_id_by_name(ctx, options.user_name)
                if user_id == None:
                    print('User "%s" not found.' % options.user_name)
                    exit(1)
                principal_id = user_id
                principal_type = 'USER'
                print('Listing all Account assignments for "%s"...' % options.user_name)
            else:
                group_id = get_group_id_by_name(ctx, options.group_name)
                if group_id == None:
                    print('Group "%s" not found.' % options.group_name)
                    exit(1)
                principal_id = group_id
                principal_type = 'GROUP'
                print('Listing all Account assignments for "%s"...' % options.group_name)

            paginator = sso_admin_client.get_paginator('list_account_assignments_for_principal')
            for page in paginator.paginate(
                InstanceArn = instance_arn,
                PrincipalId = principal_id,
                PrincipalType = principal_type
            ):
                for acct_asst in page['AccountAssignments']:

                    # These now refer to the principal returned, not the principal we queried on.
                    acct_id = acct_asst['AccountId']
                    ps_arn = acct_asst['PermissionSetArn']
                    principal_id = acct_asst['PrincipalId']
                    principal_type = acct_asst['PrincipalType']
                    principal_name = ''
                    target_arns = []

                    ps = sso_admin_client.describe_permission_set (
                        InstanceArn = ctx.instance_arn,
                        PermissionSetArn = ps_arn
                    )
                    ps_name = ps['PermissionSet']['Name']
                    ps_desc = ps['PermissionSet'].pop('Description', '-')

                    if options.quash_admin == True:
                        if (ps_name == 'AdministratorAccess'):
                            continue

                    if options.show_principal_names == True:
                        if (principal_type == 'USER'):
                            principal_name = get_user_name_by_id(ctx, principal_id)
                        elif (principal_type == 'GROUP'):
                            principal_name = get_group_name_by_id(ctx, principal_id)

                        if (principal_name == None):
                            # Should not happen.
                            raise SystemExit('Principal with id "%s" not found.' % principal_id)

                    # Note the list can be empty if the option is off or this PS has no target arns.
                    import re
                    if (options.show_target_arns == True) and (
                        re.match('^R\\d{12}_', ps_name) or re.match('^[a-f0-9]{32}$', ps_name)):
                        target_arns = sorted(get_target_arns_for_ps(ctx, ps_arn))

                    # A dict holding a dict holding a tuple of values...
                    assignments.setdefault(acct_id, {}).setdefault(ps_name, ('', [], []))
                    # Append the list of principals...
                    assignments[acct_id][ps_name][1].append((principal_type, principal_name))
                    # Update the PS description and list of target_arns...
                    assignments[acct_id][ps_name] = (
                        ps_desc, assignments[acct_id][ps_name][1], target_arns)

            # Print the dict we just built...
            for k, v in sorted(assignments.items()):

                # For each account...
                if options.show_acct_names == False:
                    print('- Assigned access in account "%s"...' % k)
                else:
                    print('- Assigned access in account "%s" --- ("%s")...' %
                        (k, get_acct_name_by_id(ctx, k)))

                # Show all accesses in the account.
                for ps_name, val in sorted(v.items(), key=lambda x: x[0].lower()):
                    (ps_desc, principal_list, target_arns) = val

                    ps_desc_str = ''
                    principal_list_str = ''

                    if options.show_ps_desc == True:
                        ps_desc_str = ' ("%s")' % ps_desc

                    if (options.show_principal_names == True) and (options.compact == True):
                        principal_list_str = ' %s' % [t[1] for t in principal_list]

                    print('  * %s%s%s' % (ps_name, ps_desc_str, principal_list_str))

                    if (options.show_principal_names == True) and (options.compact == False):
                        for p in principal_list:
                            print('    * %s: %s' % p)

                    if not target_arns == []:
                        for arn in target_arns:
                            print('    - %s' % (arn))


        # --------------------------------------------------------------------------
        # This is a view BY ORG, but really a view BY PERMISSION SET.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-acct-assignments-for-ps-in-org':

            print('Listing all Permission Set assignments in the Organization...')

            ps_list = []
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

                    if options.quash_admin == True:
                        if (ps_name == 'AdministratorAccess'):
                            continue

                    ps_list.append((ps_name, ps_arn, ps_desc, ps_dura))
                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

            for ps_name, ps_arn, ps_desc, ps_dura in sorted(ps_list, key=lambda x: x[0].lower()):

                if options.show_ps_desc == True:
                    print('Listing assignments for PS "%s": ("%s") (%s)...' % (ps_name, ps_desc, ps_dura))
                else:
                    print('Listing assignments for PS: "%s"...' % (ps_name))

                # Optionally show assume-role targets.
                if options.show_target_arns == True:
                    target_arns = get_target_arns_for_ps(ctx, ps_arn)
                    if target_arns != []:
                        print('- Assume-role targets for this PS:')
                        for arn in sorted(target_arns):
                                print('  * %s' % arn)

                for acct_id in get_accounts_for_provisioned_permission_set(ctx, ps_arn):

                    if options.show_acct_names == False:
                        print('- ACCT: %s...' % acct_id)
                    else:
                        print('- ACCT: %s --- ("%s")...' %
                              (acct_id, get_acct_name_by_id(ctx, acct_id)))

                    if options.show_principal_names == True:
                        list_assigned_principals_for_ps_in_account(ctx, 2, acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # This is like above but just lists PS without the acct assignment lookup.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-ps-in-org':

            print('Listing all Permission Sets in the Organization...')

            ps_list = []
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

                    ps_list.append((ps_name, ps_arn, ps_dura, ps_desc))

                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

            for ps_name, ps_arn, ps_dura, ps_desc in sorted(ps_list, key=lambda x: x[0].lower()):

                print('PS: \"%s\"  Description: \"%s\" (%s)' %
                        (ps_name, ps_desc, ps_dura))

                # Optionally show assume-role targets.
                if options.show_target_arns == True:
                    target_arns = get_target_arns_for_ps(ctx, ps_arn)
                    if target_arns != []:
                        print('- Assume-role targets for this PS:')
                        for arn in sorted(target_arns):
                                print('  * %s' % arn)


        # --------------------------------------------------------------------------
        # This is our BASIC view BY ACCOUNT.
        # --------------------------------------------------------------------------
        elif operation == 'list-ps-provisioned-to-account':

            ps_list = []

            if options.show_acct_names == False:
                print('Listing Permission Sets provisioned to account: %s...' % options.acct_id)
            else:
                print('Listing Permission Sets provisioned to account: %s -- ("%s")...' % (
                    options.acct_id, get_acct_name_by_id(ctx, options.acct_id)))

            ps_arns = get_ps_provisioned_to_account(ctx, options.acct_id)

            if ps_arns != None:

                for ps_arn in ps_arns:

                    ps = sso_admin_client.describe_permission_set (
                        InstanceArn = ctx.instance_arn,
                        PermissionSetArn = ps_arn
                    )
                    ps_name = ps['PermissionSet']['Name']
                    ps_dura = ps['PermissionSet']['SessionDuration']
                    ps_desc = ps['PermissionSet'].pop('Description', '-')

                    ps_list.append((ps_name, ps_arn, ps_dura, ps_desc))

                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

            for ps_name, ps_arn, ps_dura, ps_desc in sorted(ps_list, key=lambda x: x[0].lower()):

                if options.show_ps_desc == True:
                    print('PS: "%s"  Description: "%s" (%s)' % (ps_name, ps_desc, ps_dura))
                else:
                    print('PS: "%s"' % (ps_name))

                # Optionally show assume-role targets.
                if options.show_target_arns == True:
                    target_arns = get_target_arns_for_ps(ctx, ps_arn)
                    if target_arns != []:
                        print('- Assume-role targets for this PS:')
                        for arn in sorted(target_arns):
                                print('  * %s' % arn)


        # --------------------------------------------------------------------------
        # This is our FULL view BY ACCOUNT.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-ps-assignments-in-account':

            ps_list = []

            if options.show_acct_names == False:
                print('Listing all Permission Sets assignments in account: %s...' % options.acct_id)
            else:
                print('Listing all Permission Sets assignments in account: %s -- ("%s")...' % (
                    options.acct_id, get_acct_name_by_id(ctx, options.acct_id)))

            ps_arns = get_ps_provisioned_to_account(ctx, options.acct_id)

            if ps_arns != None:

                for ps_arn in ps_arns:

                    ps = sso_admin_client.describe_permission_set (
                        InstanceArn = ctx.instance_arn,
                        PermissionSetArn = ps_arn
                    )
                    ps_name = ps['PermissionSet']['Name']
                    ps_dura = ps['PermissionSet']['SessionDuration']
                    ps_desc = ps['PermissionSet'].pop('Description', '-')

                    ps_list.append((ps_name, ps_arn, ps_dura, ps_desc))

                    print('Checking permission set "%s"...' % ps_name, ' '*30, end='\r')

            for ps_name, ps_arn, ps_dura, ps_desc in sorted(ps_list, key=lambda x: x[0].lower()):

                if options.show_ps_desc == True:
                    print('PS: "%s"  Description: "%s" (%s)' % (ps_name, ps_desc, ps_dura))
                else:
                    print('PS: "%s"' % (ps_name))

                if options.show_principal_names == True:
                    list_assigned_principals_for_ps_in_account(ctx, 1, options.acct_id, ps_arn)

                # Optionally show assume-role targets.
                if options.show_target_arns == True:
                    target_arns = get_target_arns_for_ps(ctx, ps_arn)
                    if target_arns != []:
                        print('- Assume-role targets for this PS:')
                        for arn in sorted(target_arns):
                                print('  * %s' % arn)


        # --------------------------------------------------------------------------
        # This is a view BY OU, but really a view BY ACCOUNT.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-ps-assignments-in-ou':

            ou_id = get_ou_id_by_name(ctx, options.ou_name)
            if ou_id == None:
                raise SystemExit('Organizational Unit "%s" not found.' % options.ou_name)

            print('Listing all Permission Set assignments in OU: %s...' % options.ou_name)

            acct_list = []

            for page in organizations_client.get_paginator('list_accounts_for_parent').paginate(
                ParentId = ou_id
            ):
                for acct in page['Accounts']:
                    acct_list.append((acct['Id'], acct['Name']))

            sort_key = 0 if options.show_acct_names == False else 1
            for acct_id, acct_name in sorted(acct_list, key=lambda x: x[sort_key].lower()):

                if options.show_acct_names == False:
                    print('Listing all Permission Set assignments in account: %s...' % acct_id)
                else:
                    print('Listing all Permission Set assignments in account: %s -- ("%s")...' %
                        (acct_id, acct_name))

                ps_list = []
                ps_arns = get_ps_provisioned_to_account(ctx, acct_id)

                if ps_arns != None:

                    for ps_arn in ps_arns:

                        ps = sso_admin_client.describe_permission_set (
                            InstanceArn = ctx.instance_arn,
                            PermissionSetArn = ps_arn
                        )
                        ps_name = ps['PermissionSet']['Name']
                        ps_dura = ps['PermissionSet']['SessionDuration']
                        ps_desc = ps['PermissionSet'].pop('Description', '-')

                        ps_list.append((ps_name, ps_arn, ps_dura, ps_desc))

                for ps_name, ps_arn, ps_dura, ps_desc in sorted(ps_list, key=lambda x: x[0].lower()):

                    print('PS: \"%s\"  Description: \"%s\" (%s)' %
                            (ps_name, ps_desc, ps_dura))

                    # Optionally show assume-role targets.
                    if options.show_target_arns == True:
                        target_arns = get_target_arns_for_ps(ctx, ps_arn)
                        if target_arns != []:
                            print('- Assume-role targets for this PS:')
                            for arn in sorted(target_arns):
                                    print('  * %s' % arn)

                    list_assigned_principals_for_ps_in_account(ctx, 1, acct_id, ps_arn)


        # --------------------------------------------------------------------------
        # List all accounts and child OUs in an OU or Organization.
        # --------------------------------------------------------------------------
        elif operation == 'list-all-accounts-in-ou':

            # Determine parent ID based on input type
            parent_id = None
            parent_display_name = ''
            org_info = None

            if options.ou_id:
                if options.ou_id.startswith('o-'):
                    # User passed an Org ID
                    org_info = get_organizational_root(ctx)
                    if org_info['OrgId'] != options.ou_id:
                        raise ValueError('Org ID is not from the current organization')
                    parent_id = org_info['RootId']
                    parent_display_name = 'Root'
                elif options.ou_id.startswith('ou-'):
                    # User passed an OU ID
                    parent_id = options.ou_id
                    parent_display_name = get_ou_name_by_id(ctx, options.ou_id) or options.ou_id
                else:
                    raise ValueError('Invalid OU or Org ID.')
            else:
                if options.ou_name == 'Root':
                    org_info = get_organizational_root(ctx)
                    parent_id = org_info['RootId']
                    parent_display_name = 'Root'
                else:
                    parent_id = get_ou_id_by_name(ctx, options.ou_name)
                    parent_display_name = options.ou_name

            # Default to organizational root if no identifier provided
            if parent_id is None and not (options.ou_name or options.ou_id):
                org_info = get_organizational_root(ctx)
                parent_id = org_info['RootId']
                parent_display_name = 'Root'

            if parent_id is None:
                raise SystemExit('Organizational Unit "%s" not found.' % (options.ou_name or options.ou_id))

            if options.full_tree and options.ou_tree:
                raise SystemExit('Options --full-tree and --ou-tree are mutually exclusive.')

            # Additionally show Org Id in header where appropriate
            org_suffix = ''
            if org_info:
                org_suffix = ' (%s)' % org_info['OrgId']

            if options.full_tree:
                print('Organizational tree from: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
                display_org_tree_recursive(ctx, parent_id, parent_display_name, 0, False, '', options.ascii)
            elif options.ou_tree:
                print('Organizational tree from: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
                display_org_tree_recursive(ctx, parent_id, parent_display_name, 0, True, '', options.ascii)
            else:
                print('Contents of: %s (%s)%s:' % (parent_display_name, parent_id, org_suffix))
                display_org_tree_single_level(ctx, parent_id, False, options.ascii)


        # --------------------------------------------------------------------------
        # Verify a permission assignment for a user.
        # --------------------------------------------------------------------------
        elif operation == 'verify-access-for-user':

            ps_arn = options.ps_arn

            if options.ps_name != None:
                ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
                if ps_arn == None:
                    raise SystemExit('Permission set "%s" not found.' % options.ps_name)

            user_id = get_user_id_by_name(ctx, options.user_name)
            if user_id == None:
                print('User "%s" not found.' % options.user_name)
                exit(1)

            print('Verifying assigment of PS "%s" for user "%s" in account: %s...' %
                (options.ps_name, options.user_name, options.acct_id))

            paginator = sso_admin_client.get_paginator('list_account_assignments_for_principal')
            for page in paginator.paginate(
                Filter={'AccountId': options.acct_id},
                InstanceArn = instance_arn,
                PrincipalId = user_id,
                PrincipalType = 'USER'
            ):
                for acct in page['AccountAssignments']:

                    if acct['PermissionSetArn'] == ps_arn:
                        print('Access verified.')
                        exit(0)

            print('Access NOT verified.')
            exit(1)



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
