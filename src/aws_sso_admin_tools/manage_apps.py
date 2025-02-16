#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
A simple tool for managing registered applications in AWS Identity Center.

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
def list_application_assignments(ctx, app_name):

    app_arn = get_application_arn_by_name(ctx, app_name)
    if app_arn == None:
        print('application \"%s\" not found.' % app_name)
        exit(1)

    sso_admin_client = ctx.session.client('sso-admin')

    paginator = sso_admin_client.get_paginator('list_application_assignments')

    for page in paginator.paginate(
        ApplicationArn = app_arn
    ):
        for item in page['ApplicationAssignments']:

            if (item['PrincipalType'] == 'USER'):
                print('- USER: %s' % get_user_name_by_id(ctx, item['PrincipalId']))
            elif (item['PrincipalType'] == 'GROUP'):
                print('- GROUP: %s' % get_group_name_by_id(ctx, item['PrincipalId']))


# --------------------------------------------------------------------------------------------------
# Run...
# --------------------------------------------------------------------------------------------------
def run():

    cmds_usage = '''\nAvailable commands:
    list-ttis
    describe-tti
    list-applications
    describe-application
    list-application-assignments
    list-application-providers
    list-application-access-scopes
    list-application-auth-methods
    list-application-grants
    '''.rstrip()

    usage = 'usage: %prog command [options]\n   ex: %prog describe-application --app-name My-Custom-App\n'
    parser = OptionParser(usage + cmds_usage)
    global options

    parser.add_option('--profile', dest='aws_profile', default=None,
                      help='AWS profile to use')
    parser.add_option('--region', dest='region', default=None,
                      help='AWS region to use')
    parser.add_option('--app-name', dest='app_name', default=None,
                      help='Application name')
    parser.add_option('--app-protocol', dest='app_protocol', default=None,
                      help='Application protocol')
    parser.add_option('--tti-name', dest='tti_name', default=None,
                      help='Trusted token issuer name')

    (options, args) = parser.parse_args()

    def need_app_name():
        if options.app_name == None:
            print('No application specified; use --app-name.')
            exit(1)

    def need_tti_name():
        if options.tti_name == None:
            print('No TTI specified; use --tti-name.')
            exit(1)

    operation = None

    if len(args) > 0:
        op = args[0].lower()
        if op == 'list-applications':
            operation = op
        elif op == 'describe-application':
            need_app_name()
            operation = op
        elif op == 'list-application-providers':
            operation = op
        elif op == 'list-application-assignments':
            need_app_name()
            operation = op
        elif op == 'list-application-access-scopes':
            need_app_name()
            operation = op
        elif op == 'list-application-auth-methods':
            need_app_name()
            operation = op
        elif op == 'list-application-grants':
            need_app_name()
            operation = op
        elif op == 'describe-tti':
            need_tti_name()
            operation = op
        elif op == 'list-ttis':
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

        instance_arn = ctx.instance_arn

        if operation == 'list-applications':

            paginator = sso_admin_client.get_paginator('list_applications')

            for page in paginator.paginate(InstanceArn = instance_arn):

                for item in page['Applications']:
                    print(json.dumps(item, indent=4, sort_keys=False, default=str))


        elif operation == 'describe-application':

            app_arn = get_application_arn_by_name(ctx, options.app_name)
            if app_arn == None:
                print('application \"%s\" not found.' % options.app_name)
                exit(1)

            response = sso_admin_client.describe_application (
                ApplicationArn = app_arn
            )
            response.pop('ResponseMetadata')
            print(json.dumps(response, indent=4, sort_keys=False, default=str))


        elif operation == 'list-application-providers':

            if (options.app_protocol != None):
                options.app_protocol = options.app_protocol.upper()

                if (options.app_protocol != 'SAML' and options.app_protocol != 'OAUTH'):
                    raise ValueError('Unknown app protocol \"%s\"' % options.app_protocol)

            paginator = sso_admin_client.get_paginator('list_application_providers')

            for page in paginator.paginate():

                for item in page['ApplicationProviders']:
                    if (options.app_protocol != None and
                        options.app_protocol != item["FederationProtocol"]):
                        continue

                    print(json.dumps(item, indent=4, sort_keys=False, default=str))


        elif operation == 'list-application-assignments':

            list_application_assignments(ctx, options.app_name)


        elif operation == 'list-application-access-scopes':

            app_arn = get_application_arn_by_name(ctx, options.app_name)
            if app_arn == None:
                print('application \"%s\" not found.' % options.app_name)
                exit(1)

            paginator = sso_admin_client.get_paginator('list_application_access_scopes')

            for page in paginator.paginate(
                ApplicationArn = app_arn
            ):
                for item in page['Scopes']:
                    print(json.dumps(item, indent=4, sort_keys=False, default=str))


        elif operation == 'list-application-auth-methods':

            app_arn = get_application_arn_by_name(ctx, options.app_name)
            if app_arn == None:
                print('application \"%s\" not found.' % options.app_name)
                exit(1)

            paginator = sso_admin_client.get_paginator('list_application_authentication_methods')

            for page in paginator.paginate(
                ApplicationArn = app_arn
            ):
                for item in page['AuthenticationMethods']:
                    print(json.dumps(item, indent=4, sort_keys=False, default=str))


        elif operation == 'list-application-grants':

            app_arn = get_application_arn_by_name(ctx, options.app_name)
            if app_arn == None:
                print('application \"%s\" not found.' % options.app_name)
                exit(1)

            paginator = sso_admin_client.get_paginator('list_application_grants')

            for page in paginator.paginate(
                ApplicationArn = app_arn
            ):
                for item in page['Grants']:
                    print(json.dumps(item, indent=4, sort_keys=False, default=str))


        elif operation == 'describe-tti':

            tti_arn = get_tti_arn_by_name(ctx, options.tti_name)
            if tti_arn == None:
                print('TTI \"%s\" not found.' % options.tti_name)
                exit(1)

            response = sso_admin_client.describe_trusted_token_issuer (
                TrustedTokenIssuerArn = tti_arn
            )
            response.pop('ResponseMetadata')
            print(json.dumps(response, indent=4, sort_keys=False, default=str))


        if operation == 'list-ttis':

            paginator = sso_admin_client.get_paginator('list_trusted_token_issuers')

            for page in paginator.paginate(InstanceArn = instance_arn):

                for item in page['TrustedTokenIssuers']:

                    response = sso_admin_client.describe_trusted_token_issuer (
                        TrustedTokenIssuerArn = item['TrustedTokenIssuerArn']
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
