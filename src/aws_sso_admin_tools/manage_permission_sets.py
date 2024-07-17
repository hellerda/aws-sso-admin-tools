#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool for managing permission sets in AWS Identity Center.

(c) Copyright Dave Heller 2024
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

from optparse import OptionParser


# --------------------------------------------------------------------------------------------------
# Functions...
# --------------------------------------------------------------------------------------------------
def read_policy_from_cmdline():

    ps_policy_doc = {}
    input_val = ''

    if options.policy_doc != None:

        loc = options.policy_doc.split('file://')

        if (len(loc) == 1):
            input_val = loc[0]

        elif (len(loc) == 2):
            input_val = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            print('Error: unable to parse the value passed to --policy.')
            exit(1)

        try:
            ps_policy_doc = json.loads(input_val)

        except json.JSONDecodeError:
            print('Error: input to --policy must be valid JSON.')
            exit(1)

    return ps_policy_doc


def read_tags_from_cmdline():

    ps_tags = []
    input_val = ''

    if options.tags != None:

        loc = options.tags.split('file://')

        if (len(loc) == 1):
            input_val = loc[0]

        elif (len(loc) == 2):
            input_val = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            print('Error: unable to parse the value passed to --tags.')
            exit(1)

        try:
            ps_tags = json.loads(input_val)

        except json.JSONDecodeError:
            ps_tags = []
            item_list = input_val.split(',')

            for item in item_list:
                pair = item.split('=')
                if (len(pair) != 2):
                    print('Error: unable to parse the value passed to --tags.')
                    exit(1)
                pair_dict = {}
                pair_dict['Key'] = pair[0]
                pair_dict['Value'] = pair[1]
                ps_tags.append(pair_dict)

    return ps_tags


def read_policy_arns_from_cmdline():

    policy_arns = []
    input_val = ''

    if options.policy_arns != None:

        if (options.policy_arns == ''):
            print('Error: empty value passed to --policy-arns.')
            exit(1)

        loc = options.policy_arns.split('file://')

        if (len(loc) == 1):
            input_val = loc[0]

        elif (len(loc) == 2):
            input_val = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            print('Error: unable to parse the value passed to --policy-arns.')
            exit(1)

        try:
            policy_arns = json.loads(input_val)

        except json.JSONDecodeError:
            policy_arns = []
            item_list = ''.join(options.policy_arns.split()).split(',')

            for item in item_list:
                policy_arns.append(item)

    return policy_arns


def read_cm_policies_from_cmdline():

    cm_policies = []
    input_val = ''

    if options.cm_policies != None:

        loc = options.cm_policies.split('file://')

        if (len(loc) == 1):
            input_val = loc[0]

        elif (len(loc) == 2):
            input_val = open(loc[1], 'rt').read()

        elif (len(loc) > 2):
            print('Error: unable to parse the value passed to --cm-policies.')
            exit(1)

        try:
            cm_policies = json.loads(input_val)

        except json.JSONDecodeError:
            cm_policies = []
            item_list = input_val.split(',')

            for item in item_list:
                pair = item.split('=')
                if (len(pair) != 2):
                    print('Error: unable to parse the value passed to --cm-policies.')
                    exit(1)
                pair_dict = {}
                pair_dict['Name'] = pair[0]
                pair_dict['Path'] = pair[1]
                cm_policies.append(pair_dict)

    return cm_policies


# --------------------------------------------------------------------------------------------------
# Run...
# --------------------------------------------------------------------------------------------------
def run():

    cmds_usage = '''\nAvailable commands:
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
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog describe-ps --ps_name MyPermissionSet\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--acct-id', dest='acct_id', default=None,
                      help='Account ID')
    parser.add_option("--ps-name", dest="ps_name", default=None,
                      help='Permission Set name')
    parser.add_option("--ps-desc", dest="ps_desc", default=None,
                      help='Permission Set description')
    parser.add_option("--ps-durn", dest="ps_durn", default=None,
                      help='Permission Set session duration')
    parser.add_option("--policy", dest="policy_doc", default=None,
                      help='Path to file containing IAM policy')
    parser.add_option("--policy-arns", dest="policy_arns", default=None,
                      help='List of policy Arns to attach to PS')
    parser.add_option("--cm-policies", dest="cm_policies", default=None,
                      help='List of customer managed policy refs to attach to PS')
    parser.add_option("--tags", dest="tags", default=None,
                      help='List of PS tags or path to file containing tags in JSON')
    parser.add_option("--tag-keys", dest="tag_keys", default=None,
                      help='List of PS tag keys to delete')

    (options, args) = parser.parse_args()

    def need_ps_name():
        if options.ps_name == None:
            print('No permission set specified; use --ps-name.')
            exit(1)

    def need_tag_keys():
        if options.tag_keys == None:
            print('No tagkeys specified; use --tag-keys.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'create-ps':
            need_ps_name()
            operation = op
        elif op == 'update-ps':
            need_ps_name()
            operation = op
        elif op == 'delete-ps':
            need_ps_name()
            operation = op
        elif op == 'describe-ps':
            need_ps_name()
            operation = op
        elif op == 'tag-ps':
            need_ps_name()
            operation = op
        elif op == 'untag-ps':
            need_ps_name()
            need_tag_keys()
            operation = op
        elif op == 'attach-ps-managed-policies':
            need_ps_name()
            operation = op
        elif op == 'detach-ps-managed-policies':
            need_ps_name()
            operation = op
        elif op == 'list-ps-managed-policies':
            need_ps_name()
            operation = op
        elif op == 'attach-ps-customer-managed-policies':
            need_ps_name()
            operation = op
        elif op == 'detach-ps-customer-managed-policies':
            need_ps_name()
            operation = op
        elif op == 'list-ps-customer-managed-policies':
            need_ps_name()
            operation = op
        elif op == 'put-ps-inline-policy':
            need_ps_name()
            operation = op
        elif op == 'delete-ps-inline-policy':
            need_ps_name()
            operation = op
        elif op == 'get-ps-inline-policy':
            need_ps_name()
            operation = op
        elif op == 'list-ps-tags':
            need_ps_name()
            operation = op
        elif op == 'provision-ps':
            need_ps_name()
            operation = op
        else:
            print('Unknown command: %s\n' % op)

    if operation == None:
        parser.print_help()
        exit(1)


    # ----------------------------------------------------------------------------------------------
    # Defaults (do not edit)...
    # ----------------------------------------------------------------------------------------------
    ps_policy_doc = {}
    ps_tags = []
    policy_arns = []
    cm_policies = []

    # ----------------------------------------------------------------------------------------------
    # Customize this...
    # ----------------------------------------------------------------------------------------------
    # Your Inline policy here:
    #
    # ps_policy_doc = {
    #     "Version": "2012-10-17",
    #     "Statement": [
    #         {
    #         "Effect": "Allow",
    #         "Action": "ssm:DescribeParameters",
    #         "Resource": "*"
    #         }
    #     ]
    # }

    # Your Permission Set tags here:
    #
    # ps_tags=[
    #     {
    #         "Key": "Environment",
    #         "Value": "Development"
    #     },
    #     {
    #         "Key": "Application",
    #         "Value": "Sample"
    #     }
    # ]

    # Your Policy Arns here:
    #
    # policy_arns=[
    #     "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    #     "arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"
    # ]

    # Your Customer managed policies here:
    #
    # cm_policies=[
    #     {
    #         "Name": "CustomerPolicy1",
    #         "Path": "/"
    #     },
    #     {
    #         "Name": "CustomerPolicy1",
    #         "Path": "/"
    #     }
    # ]


    # ----------------------------------------------------------------------------------------------
    # Ops start here...
    # ----------------------------------------------------------------------------------------------
    with AWSContextManager(options.aws_profile) as ctx:

        sso_admin_client = ctx.session.client('sso-admin')

        instance_arn = ctx.instance_arn

        if operation == 'create-ps':

            if options.tags != None:
                ps_tags = read_tags_from_cmdline()

            print(json.dumps(ps_tags, indent=4, sort_keys=False, default=str))

            if not isinstance(ps_tags, list):
                print('Error: Input to --tags must be a list.')
                exit(1)

            try:
                response = {}

                if options.ps_desc == None and options.ps_durn == None:
                    response = sso_admin_client.create_permission_set (
                        InstanceArn = instance_arn,
                        Name = options.ps_name,
                        Tags = ps_tags
                    )
                elif options.ps_desc != None and options.ps_durn == None:
                    response = sso_admin_client.create_permission_set (
                        InstanceArn = instance_arn,
                        Name = options.ps_name,
                        Description = options.ps_desc,
                        Tags = ps_tags
                    )
                elif options.ps_desc == None and options.ps_durn != None:
                    response = sso_admin_client.create_permission_set (
                        InstanceArn = instance_arn,
                        Name = options.ps_name,
                        SessionDuration = options.ps_durn,
                        Tags = ps_tags
                    )
                if options.ps_desc != None and options.ps_durn != None:
                    response = sso_admin_client.create_permission_set (
                        InstanceArn = instance_arn,
                        Name = options.ps_name,
                        Description = options.ps_desc,
                        SessionDuration = options.ps_durn,
                        Tags = ps_tags
                    )

                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'update-ps':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                if options.ps_desc == None and options.ps_durn == None:
                    print('Need at least one of --ps-desc or --ps-durn.')
                    exit(1)
                elif options.ps_desc != None and options.ps_durn == None:
                    response = sso_admin_client.update_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        Description = options.ps_desc
                    )
                elif options.ps_desc == None and options.ps_durn != None:
                    response = sso_admin_client.update_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        SessionDuration = options.ps_durn
                    )
                if options.ps_desc != None and options.ps_durn != None:
                    response = sso_admin_client.update_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        Description = options.ps_desc,
                        SessionDuration = options.ps_durn
                    )

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'delete-ps':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.delete_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn
                )

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'describe-ps':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.describe_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'tag-ps':

            if options.tags != None:
                ps_tags = read_tags_from_cmdline()

            print(json.dumps(ps_tags, indent=4, sort_keys=False, default=str))

            if not isinstance(ps_tags, list):
                print('Error: Input to --tags must be a list.')
                exit(1)

            if ps_tags == []:
                print('No tags specified; use --tags.')
                exit(1)

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.tag_resource (
                    InstanceArn = instance_arn,
                    ResourceArn = ps_arn,
                    Tags = ps_tags
                )

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'untag-ps':

            if (options.tag_keys == ''):
                print('Error: empty value passed to --tag-keys.')
                exit(1)

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            tag_keys = options.tag_keys.split(',')

            try:
                response = sso_admin_client.untag_resource (
                    InstanceArn = instance_arn,
                    ResourceArn = ps_arn,
                    TagKeys = tag_keys
                )

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'attach-ps-managed-policies':

            if options.policy_arns != None:
                policy_arns = read_policy_arns_from_cmdline()

            if not isinstance(policy_arns, list):
                print('Error: Input to --policy-arns must be a list.')
                exit(1)

            if policy_arns == []:
                print('No policy_arns specified; use --policy-arns.')
                exit(1)

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            for policy_arn in policy_arns:

                try:
                    response = sso_admin_client.attach_managed_policy_to_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        ManagedPolicyArn = policy_arn
                    )

                except Exception as e:
                    print("Policy arn \"%s\" cannot be attached: %s" % (policy_arn, str(e)))


        elif operation == 'detach-ps-managed-policies':

            if options.policy_arns != None:
                policy_arns = read_policy_arns_from_cmdline()

            if not isinstance(policy_arns, list):
                print('Error: Input to --policy-arns must be a list.')
                exit(1)

            if policy_arns == []:
                print('No policy_arns specified; use --policy-arns.')
                exit(1)

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            for policy_arn in policy_arns:

                try:
                    response = sso_admin_client.detach_managed_policy_from_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        ManagedPolicyArn = policy_arn
                    )

                except Exception as e:
                    print("Policy arn \"%s\" cannot be detached: %s" % (policy_arn, str(e)))


        elif operation == 'list-ps-managed-policies':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.list_managed_policies_in_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn,
                    MaxResults = 30  # normally there are up to 20 per IAM role, max
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'attach-ps-customer-managed-policies':

            if options.cm_policies != None:
                cm_policies = read_cm_policies_from_cmdline()
            print(json.dumps(cm_policies, indent=4, sort_keys=False, default=str))

            if not isinstance(cm_policies, list):
                print('Error: Input to --cm-policies must be a list.')
                exit(1)

            if cm_policies == []:
                print('No customer managed policies specified; use --cm-policies.')
                exit(1)

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            for cm_policy in cm_policies:

                try:
                    response = sso_admin_client.attach_customer_managed_policy_reference_to_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        CustomerManagedPolicyReference = cm_policy
                    )

                except Exception as e:
                    print("Managed policy \"%s\" cannot be attached: %s" % (cm_policy['Name'], str(e)))


        elif operation == 'detach-ps-customer-managed-policies':

            if options.cm_policies != None:
                cm_policies = read_cm_policies_from_cmdline()
            print(json.dumps(cm_policies, indent=4, sort_keys=False, default=str))

            if not isinstance(cm_policies, list):
                print('Error: Input to --cm-policies must be a list.')
                exit(1)

            if cm_policies == []:
                print('No customer managed policies specified; use --cm-policies.')
                exit(1)

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            for cm_policy in cm_policies:

                try:
                    response = sso_admin_client.detach_customer_managed_policy_reference_from_permission_set (
                        InstanceArn = instance_arn,
                        PermissionSetArn = ps_arn,
                        CustomerManagedPolicyReference = cm_policy
                    )

                except Exception as e:
                    print("Managed policy \"%s\" cannot be detached: %s" % (cm_policy['Name'], str(e)))


        elif operation == 'list-ps-customer-managed-policies':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.list_customer_managed_policy_references_in_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn,
                    MaxResults = 30  # normally there are up to 20 per IAM role, max
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'put-ps-inline-policy':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            if options.policy_doc != None:
                ps_policy_doc = read_policy_from_cmdline()

            if ps_policy_doc == {}:
                print('No policy specified; use --policy.')
                exit(1)

            print(json.dumps(ps_policy_doc, indent=4, sort_keys=False, default=str))

            try:
                response = sso_admin_client.put_inline_policy_to_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn,
                    InlinePolicy = json.dumps(ps_policy_doc)
                )

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'delete-ps-inline-policy':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.delete_inline_policy_from_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn
                )

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'get-ps-inline-policy':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.get_inline_policy_for_permission_set (
                    InstanceArn = instance_arn,
                    PermissionSetArn = ps_arn
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'list-ps-tags':

            ps_arn = get_permission_set_arn_by_name(ctx, options.ps_name)
            if ps_arn == None:
                print("permission set \"%s\" not found." % options.ps_name)
                exit(1)

            try:
                response = sso_admin_client.list_tags_for_resource (
                    InstanceArn = instance_arn,
                    ResourceArn = ps_arn
                )
                response.pop('ResponseMetadata')
                print(json.dumps(response, indent=4, sort_keys=False, default=str))

            except Exception as e:
                print("Error: %s" % str(e))
                exit(1)


        elif operation == 'provision-ps':

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
