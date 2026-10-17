#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
AWS SSO Admin Tools - Main Entry Point

Provides a unified CLI for managing AWS Identity Center resources.
"""

import argparse
import boto3
import logging
import os
import sys
from typing import Optional

from .aws_client import AWSClient
from .commands import COMMAND_REGISTRY
from .models import AWSClientError
from .output import OutputHandler


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    # Create parent parser with common arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        '--profile',
        dest='aws_profile',
        default=None,
        help='AWS profile to use'
    )
    parent_parser.add_argument(
        '--region',
        dest='region',
        default=None,
        help='AWS region to use'
    )
    parent_parser.add_argument(
        '-j', '--json-only',
        dest='json_only',
        action='store_true',
        default=False,
        help='Output JSON only'
    )

    # Create main parser
    parser = argparse.ArgumentParser(
        prog='aws-sso-admin',
        description='Tools for managing AWS Identity Center (formerly AWS SSO)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Add global options to main parser as well
    parser.add_argument(
        '--profile',
        dest='aws_profile',
        default=None,
        help='AWS profile to use'
    )
    parser.add_argument(
        '--region',
        dest='region',
        default=None,
        help='AWS region to use'
    )
    parser.add_argument(
        '-j', '--json-only',
        dest='json_only',
        action='store_true',
        default=False,
        help='Output JSON only'
    )

    # Subcommands - pass parent parser so options can appear after command
    subparsers = parser.add_subparsers(
        dest='command',
        help='Command to execute',
        metavar='COMMAND'
    )

    # Register all commands with parent parser
    for cmd_name, cmd_class in COMMAND_REGISTRY.items():
        cmd_parser = subparsers.add_parser(
            cmd_name,
            help=f'Execute {cmd_name} command',
            parents=[parent_parser]
        )
        cmd_class.register_arguments(cmd_parser)

    return parser


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, 1 for error, 130 for keyboard interrupt)
    """
    # Configure logging from environment
    try:
        log_level = os.environ.get('LOGLEVEL', 'CRITICAL').upper()
    except AttributeError:
        log_level = 'CRITICAL'

    logging.basicConfig(
        level=log_level,
        format='%(levelname)s: %(message)s',
        stream=sys.stderr
    )

    # Handle AWS region environment variables
    if 'AWS_DEFAULT_REGION' not in os.environ and 'AWS_REGION' in os.environ:
        os.environ['AWS_DEFAULT_REGION'] = os.environ['AWS_REGION']

    # Parse arguments
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Get command class
    command_class = COMMAND_REGISTRY.get(args.command)
    if not command_class:
        print(f'Unknown command: {args.command}', file=sys.stderr)
        return 1

    try:
        # Create boto3 session
        session = boto3.Session(
            profile_name=args.aws_profile,
            region_name=args.region
        )

        # Initialize AWS client and output handler
        client = AWSClient(session=session)
        output = OutputHandler(json_output=args.json_only)

        # Execute command
        command = command_class(args, client, output)
        command.execute()

        return 0

    except KeyboardInterrupt:
        print('\nKilled by keyboard interrupt.', file=sys.stderr)
        return 130

    except AWSClientError as e:
        print(f'AWS Error: {e}', file=sys.stderr)
        logging.exception('AWS client error')
        return 1

    except Exception as e:
        print(f'Error ({e.__class__.__name__}): {e}', file=sys.stderr)
        logging.exception('Unexpected error')
        return 1


if __name__ == '__main__':
    sys.exit(main())
