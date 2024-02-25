#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool for managing users ang groups in AWS Identity Center.

(c) Copyright Dave Heller 2023
'''

import json
import os
import sys

from funcs import *

from optparse import OptionParser


# --------------------------------------------------------------------------------------------------
# Main...
# --------------------------------------------------------------------------------------------------
def main():

    cmds_usage = '''\nAvailable commands:
    create-group
    delete-group
    describe-group
    list-groups
    describe-user
    create-users
    delete-users
    get-users
    list-users
    create-group-memberships
    get-group-memberships
    delete-group-memberships
    list-group-memberships
    list-all-group-memberships-for-user
    create-group-membership
    get-group-membership
    delete-group-membership
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog create-group --group_name MyGroup\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--user-name', dest='user_name', default=None,
                      help='User name')
    parser.add_option('--group-name', dest='group_name', default=None,
                      help='Group name')
    parser.add_option('--group-desc', dest='group_desc', default=None,
                      help='Group description')

    (options, args) = parser.parse_args()

    def need_user_name():
        if options.user_name == None:
            print('No user specified; use --user-name.')
            exit(1)

    def need_group_name():
        if options.group_name == None:
            print('No group specified; use --group-name.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'create-group':
            need_group_name()
            operation = op
        elif op == 'delete-group':
            need_group_name()
            operation = op
        elif op == 'describe-group':
            need_group_name()
            operation = op
        elif op == 'list-groups':
            operation = op
        elif op == 'describe-user':
            need_user_name()
            operation = op
        elif op == 'create-users':
            operation = op
        elif op == 'delete-users':
            operation = op
        elif op == 'get-users':
            operation = op
        elif op == 'list-users':
            operation = op
        elif op == 'list-all-group-memberships-for-user':
            need_user_name()
            operation = op
        elif op == 'create-group-memberships':
            need_group_name()
            operation = op
        elif op == 'get-group-memberships':
            need_group_name()
            operation = op
        elif op == 'delete-group-memberships':
            need_group_name()
            operation = op
        elif op == 'list-group-memberships':
            need_group_name()
            operation = op
        elif op == 'create-group-membership':
            need_group_name()
            need_user_name()
            operation = op
        elif op == 'get-group-membership':
            need_group_name()
            need_user_name()
            operation = op
        elif op == 'delete-group-membership':
            need_group_name()
            need_user_name()
            operation = op
        else:
            print('Unknown command: %s\n' % op)

    if operation == None:
        parser.print_help()
        exit(1)


    # ----------------------------------------------------------------------------------------------
    # Customize this...
    # ----------------------------------------------------------------------------------------------
    # User list for bulk operations
    user_list = [
        # Family name, given name, email
        ('Newton', 'Isaac', 'isaac@brainstorm.org'),
        ('DaVinci', 'Lenny', 'lenny@brainstorm.org'),
        ('Curie', 'Marie', 'marie@brainstorm.org'),
        ('West', 'Gladys', 'gladys@brainstorm.org')
    ]


    # ----------------------------------------------------------------------------------------------
    # Ops start here...
    # ----------------------------------------------------------------------------------------------
    with AWSContextManager(options.aws_profile) as ctx:

        identitystore_client = ctx.session.client('identitystore')

        identitystore_id = ctx.identitystore_id

        if operation == 'create-group':

            try:
                response = identitystore_client.create_group (
                    IdentityStoreId = identitystore_id,
                    DisplayName = options.group_name,
                    Description = options.group_desc
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except identitystore_client.exceptions.ConflictException:
                print('Group: \"%s\" already exists.' % options.group_name)

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'describe-group' or operation == 'delete-group':

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group \'%s\' not found.' % options.group_name)
                exit(1)

            try:
                if operation == 'delete-group':
                    print('Deleting Group: \"%s\" with ID: %s' % (options.group_name, group_id))
                    response = identitystore_client.delete_group (
                        IdentityStoreId = identitystore_id,
                        GroupId = group_id
                    )

                else:
                    response = identitystore_client.describe_group (
                        IdentityStoreId = identitystore_id,
                        GroupId = group_id
                    )
                    response.pop('ResponseMetadata')
                    print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'list-groups':

            try:
                paginator = identitystore_client.get_paginator('list_groups')

                for page in paginator.paginate(IdentityStoreId = identitystore_id):
                    for item in page["Groups"]:

                        try:
                            descr = item['Description']
                        except KeyError:
                            descr = '-'

                        try:
                            cb = item['ExternalIds']
                            cb = 'SCIM'
                        except KeyError:
                            cb = 'Manual'

                        print('Group: \"%s\"  Description: \"%s\" (%s)' %
                            (item['DisplayName'], descr, cb))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'create-users':

            for item in user_list:
                (family_name, given_name, email) = item

                user_name = email

                try:
                    response = identitystore_client.create_user (
                        IdentityStoreId = identitystore_id,
                        UserName = user_name,
                        Name = {
                            'FamilyName': family_name,
                            'GivenName': given_name
                        },
                        DisplayName = given_name + ' ' + family_name,
                        Emails=[
                            {
                                'Value': email,
                                'Type': 'work',
                                'Primary': True
                            },
                        ]
                    )
                    print('Created user: \"%s\" (\"%s %s\") with UserId: %s' %
                        (user_name, given_name, family_name, response['UserId']))

                except identitystore_client.exceptions.ConflictException:
                    print('User: \"%s\" already exists' % user_name)

                except Exception as e:
                    print("Error: %s" % str(e))
                    exit(1)


        elif operation == 'describe-user':

            user_id = get_user_id_by_name(ctx, options.user_name)
            if user_id == None:
                print('User \'%s\' not found.' % options.user_name)
                exit(1)

            try:
                response = identitystore_client.describe_user (
                    IdentityStoreId = identitystore_id,
                    UserId = user_id
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'get-users' or operation == 'delete-users' :

            for item in user_list:
                (_, _, email) = item

                user_name = email

                user_id = get_user_id_by_name(ctx, user_name)
                if user_id == None:
                    print('User \'%s\' not found.' % user_name)
                    continue

                try:
                    if operation == 'delete-users' :
                        response = identitystore_client.delete_user (
                            IdentityStoreId = identitystore_id,
                            UserId = user_id
                        )
                        print('User: \"%s\" deleted.' % user_name)

                    else:
                        response = identitystore_client.describe_user (
                            IdentityStoreId = identitystore_id,
                            UserId = user_id
                        )
                        print('Found user: \"%s\" (\"%s\") with UserId: %s' %
                            (user_name, response['DisplayName'], response['UserId']))

                except Exception as e:
                    print("Error: %s" % str(e))
                    exit(1)


        elif operation == 'list-users':

            try:
                paginator = identitystore_client.get_paginator('list_users')

                for page in paginator.paginate(IdentityStoreId = identitystore_id):
                    for item in page["Users"]:

                        title = item.pop('Title', '-')

                        print('User: %s (%s) Title: %s' %
                            (item['UserName'], item['DisplayName'], title))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'create-group-memberships':

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group \'%s\' not found.' % options.group_name)
                exit(1)

            for item in user_list:
                (_, _, email) = item

                user_name = email

                user_id = get_user_id_by_name(ctx, user_name)
                if user_id == None:
                    print('User \'%s\' not found.' % user_name)
                    continue

                try:
                    response = identitystore_client.create_group_membership (
                        IdentityStoreId = identitystore_id,
                        GroupId = group_id,
                        MemberId = {
                            'UserId': user_id
                        }
                    )
                    print('User: \"%s\" now has MEMBERSHIP_ID: %s in Group: \"%s\"' %
                        (user_name, response['MembershipId'], options.group_name))

                except identitystore_client.exceptions.ConflictException:
                    print('User: \"%s\" already has a membership in Group: \"%s\"' %
                        (user_name, options.group_name))

                except Exception as e:
                    print("Error: %s" % str(e))
                    exit(1)


        elif operation == 'get-group-memberships' or operation == 'delete-group-memberships':

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group \'%s\' not found.' % options.group_name)
                exit(1)

            for item in user_list:
                (_, _, email) = item

                user_name = email

                user_id = get_user_id_by_name(ctx, user_name)
                if user_id == None:
                    print('User \'%s\' not found.' % user_name)
                    continue

                try:
                    response = identitystore_client.get_group_membership_id (
                        IdentityStoreId = identitystore_id,
                        GroupId = group_id,
                        MemberId = {
                            'UserId': user_id
                        }
                    )
                    print('User: \"%s\" has MEMBERSHIP_ID: %s in Group: \"%s\"' %
                        (user_name, response['MembershipId'], options.group_name))

                    if operation != 'delete-group-memberships':
                        continue

                    print('Removing membership.')
                    _ = identitystore_client.delete_group_membership (
                        IdentityStoreId = identitystore_id,
                        MembershipId = response['MembershipId'],
                    )

                except identitystore_client.exceptions.ResourceNotFoundException:
                    print('User: \"%s\" has no membership in Group: \"%s\"' %
                        (user_name, options.group_name))

                except Exception as e:
                    print("Error: %s" % str(e))
                    exit(1)


        elif operation == 'list-group-memberships':

            # While output looks similar, above query checks membership
            # based on a list, while this lists ALL users in the group.

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group \'%s\' not found.' % options.group_name)
                exit(1)

            try:
                paginator = identitystore_client.get_paginator('list_group_memberships')

                for page in paginator.paginate(
                    IdentityStoreId = identitystore_id,
                    GroupId = group_id
                ):
                    for item in page["GroupMemberships"]:
                        print('User: \"%s\" has MEMBERSHIP_ID: %s in Group: \"%s\"' % (get_user_name_by_id(ctx,
                            item['MemberId']['UserId']), item['MembershipId'], options.group_name))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'list-all-group-memberships-for-user':

            user_id = get_user_id_by_name(ctx, options.user_name)
            if user_id == None:
                print('User \'%s\' not found.' % options.user_name)
                exit(1)
            print('Listing all group memberships for \"%s\"...' % options.user_name)

            group_names = []
            for group in get_group_memberships_for_user(ctx, user_id):
                group_names.append(group['DisplayName'])

            if group_names == []:
                print('- None found.')
                exit(1)

            for group in sorted(group_names):
                print(group)


        elif operation == 'create-group-membership':

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group \'%s\' not found.' % options.group_name)
                exit(1)

            user_id = get_user_id_by_name(ctx, options.user_name)
            if user_id == None:
                print('User \'%s\' not found.' % options.user_name)
                exit(1)

            try:
                response = identitystore_client.create_group_membership (
                    IdentityStoreId = identitystore_id,
                    GroupId = group_id,
                    MemberId = {
                        'UserId': user_id
                    }
                )
                print('User: \"%s\" now has MEMBERSHIP_ID: %s in Group: \"%s\"' %
                    (options.user_name, response['MembershipId'], options.group_name))

            except identitystore_client.exceptions.ConflictException:
                print('User: \"%s\" already has a membership in Group: \"%s\"' %
                    (options.user_name, options.group_name))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'get-group-membership' or operation == 'delete-group-membership':

            group_id = get_group_id_by_name(ctx, options.group_name)
            if group_id == None:
                print('Group \'%s\' not found.' % options.group_name)
                exit(1)

            user_id = get_user_id_by_name(ctx, options.user_name)
            if user_id == None:
                print('User \'%s\' not found.' % options.user_name)
                exit(1)

            try:
                response = identitystore_client.get_group_membership_id (
                    IdentityStoreId = identitystore_id,
                    GroupId = group_id,
                    MemberId = {
                        'UserId': user_id
                    }
                )
                print('User: \"%s\" has MEMBERSHIP_ID: %s in Group: \"%s\"' %
                    (options.user_name, response['MembershipId'], options.group_name))

                if operation == 'delete-group-membership':

                    print('Removing membership.')
                    _ = identitystore_client.delete_group_membership (
                        IdentityStoreId = identitystore_id,
                        MembershipId = response['MembershipId'],
                    )

            except identitystore_client.exceptions.ResourceNotFoundException:
                print('User: \"%s\" has no membership in Group: \"%s\"' %
                    (options.user_name, options.group_name))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)



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
