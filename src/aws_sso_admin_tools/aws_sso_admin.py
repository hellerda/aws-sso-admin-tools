#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
Universal command router for aws-sso-admin-tools

(c) Copyright Dave Heller 2024
'''

import logging
import os
import sys

if __name__ == '__main__':
    import funcs
    import manage_account_assignments
    import manage_apps
    import manage_permission_sets
    import manage_users_groups
else:
    from . import funcs
    from . import manage_account_assignments
    from . import manage_apps
    from . import manage_permission_sets
    from . import manage_users_groups


# --------------------------------------------------------------------------------------------------
# Run...
# --------------------------------------------------------------------------------------------------
def run():

    args = sys.argv

    if len(args) > 0:
        prog =  os.path.basename(args[0])

    cmds_usage = '''\nAvailable commands:
  Simple lookup operations:
    lookup-user-name
    lookup-group-name
    lookup-ps-name
    lookup-app-name
    lookup-user-id
    lookup-group-id
    lookup-ps-arn
    lookup-app-arn

  User and Group operations:
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

  Permission Set operations:
    create-ps
    update-ps
    delete-ps
    describe-ps
    tag-ps
    untag-ps
    attach-ps-managed-policies
    detach-ps-managed-policies
    list-ps-managed-policies
    attach-ps-customer-managed-policies
    detach-ps-customer-managed-policies
    list-ps-customer-managed-policies
    put-ps-inline-policy
    delete-ps-inline-policy
    get-ps-inline-policy
    list-ps-tags
    provision-ps

  Account Assignment operations:
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
    verify-access-for-user

  Application management operations:
    list-ttis
    describe-tti
    list-applications
    describe-application
    list-application-assignments
    list-application-providers
    list-application-access-scopes
    list-application-auth-methods
    list-application-grants
    '''

    usage = f'usage: {prog} command [options]\n' + \
            f'   ex: {prog} list-accounts-for-provisioned-permission-set --ps-name MyPermissionSet\n' + \
            f'   For command list use "{prog} help"\n'

    op = None

    if len(args) > 1:
        op = args[1].lower()

        if op == 'help':
            print(usage + cmds_usage)

        # Simple lookup operations...
        elif op == 'lookup-user-name':
            funcs.run()
        elif op == 'lookup-group-name':
            funcs.run()
        elif op == 'lookup-ps-name':
            funcs.run()
        elif op == 'lookup-app-name':
            funcs.run()
        elif op == 'lookup-tti-name':
            funcs.run()
        elif op == 'lookup-user-id':
            funcs.run()
        elif op == 'lookup-group-id':
            funcs.run()
        elif op == 'lookup-ps-arn':
            funcs.run()
        elif op == 'lookup-app-arn':
            funcs.run()
        elif op == 'lookup-tti-arn':
            funcs.run()

        # User and Group operations...
        elif op == 'create-group':
            manage_users_groups.run()
        elif op == 'delete-group':
            manage_users_groups.run()
        elif op == 'describe-group':
            manage_users_groups.run()
        elif op == 'list-groups':
            manage_users_groups.run()
        elif op == 'describe-user':
            manage_users_groups.run()
        elif op == 'create-users':
            manage_users_groups.run()
        elif op == 'delete-users':
            manage_users_groups.run()
        elif op == 'get-users':
            manage_users_groups.run()
        elif op == 'list-users':
            manage_users_groups.run()
        elif op == 'list-all-group-memberships-for-user':
            manage_users_groups.run()
        elif op == 'create-group-memberships':
            manage_users_groups.run()
        elif op == 'get-group-memberships':
            manage_users_groups.run()
        elif op == 'delete-group-memberships':
            manage_users_groups.run()
        elif op == 'list-group-memberships':
            manage_users_groups.run()
        elif op == 'create-group-membership':
            manage_users_groups.run()
        elif op == 'get-group-membership':
            manage_users_groups.run()
        elif op == 'delete-group-membership':
            manage_users_groups.run()

        # Permission Set operations...
        elif op == 'create-ps':
            manage_permission_sets.run()
        elif op == 'update-ps':
            manage_permission_sets.run()
        elif op == 'delete-ps':
            manage_permission_sets.run()
        elif op == 'describe-ps':
            manage_permission_sets.run()
        elif op == 'tag-ps':
            manage_permission_sets.run()
        elif op == 'untag-ps':
            manage_permission_sets.run()
        elif op == 'attach-ps-managed-policies':
            manage_permission_sets.run()
        elif op == 'detach-ps-managed-policies':
            manage_permission_sets.run()
        elif op == 'list-ps-managed-policies':
            manage_permission_sets.run()
        elif op == 'attach-ps-customer-managed-policies':
            manage_permission_sets.run()
        elif op == 'detach-ps-customer-managed-policies':
            manage_permission_sets.run()
        elif op == 'list-ps-customer-managed-policies':
            manage_permission_sets.run()
        elif op == 'put-ps-inline-policy':
            manage_permission_sets.run()
        elif op == 'delete-ps-inline-policy':
            manage_permission_sets.run()
        elif op == 'get-ps-inline-policy':
            manage_permission_sets.run()
        elif op == 'list-ps-tags':
            manage_permission_sets.run()
        elif op == 'provision-ps':
            manage_permission_sets.run()

        # Account Assignment operations...
        elif op == 'create-account-assignment':
            manage_account_assignments.run()
        elif op == 'delete-account-assignment':
            manage_account_assignments.run()
        elif op == 'provision-permission-set':
            manage_account_assignments.run()
        elif op == 'list-assigned-principals-for-ps-in-account':
            manage_account_assignments.run()
        elif op == 'list-accounts-for-provisioned-permission-set':
            manage_account_assignments.run()
        elif op == 'list-all-acct-assignments-for-provisioned-permission-set':
            manage_account_assignments.run()
        elif op == 'list-all-acct-assignments-for-principal':
            manage_account_assignments.run()
        elif op == 'list-all-acct-assignments-for-ps-in-org':
            manage_account_assignments.run()
        elif op == 'list-all-permission-sets-in-org':
            manage_account_assignments.run()
        elif op == 'list-permission-sets-provisioned-to-account':
            manage_account_assignments.run()
        elif op == 'list-all-permission-set-assignments-in-account':
            manage_account_assignments.run()
        elif op == 'list-all-permission-set-assignments-in-ou':
            manage_account_assignments.run()
        elif op == 'verify-access-for-user':
            manage_account_assignments.run()

        # Application management operations...
        elif op == 'list-applications':
            manage_apps.run()
        elif op == 'describe-application':
            manage_apps.run()
        elif op == 'list-application-providers':
            manage_apps.run()
        elif op == 'list-application-assignments':
            manage_apps.run()
        elif op == 'list-application-access-scopes':
            manage_apps.run()
        elif op == 'list-application-auth-methods':
            manage_apps.run()
        elif op == 'list-application-grants':
            manage_apps.run()
        elif op == 'describe-tti':
            manage_apps.run()
        elif op == 'list-ttis':
            manage_apps.run()

        else:
            print('Unknown command: %s\n' % op)
            print(usage)
            exit(1)

    else:
        print(usage)
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
