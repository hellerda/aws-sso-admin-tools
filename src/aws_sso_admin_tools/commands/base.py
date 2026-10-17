"""Base command class for AWS SSO Admin Tools."""

from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from typing import Any

from ..aws_client import AWSClient
from ..output import OutputHandler


class BaseCommand(ABC):
    """Abstract base class for all commands."""

    def __init__(self, args: Namespace, client: AWSClient, output: OutputHandler):
        """
        Initialize command.

        Args:
            args: Parsed command-line arguments
            client: AWS client manager
            output: Output handler
        """
        self.args = args
        self.client = client
        self.output = output


    @staticmethod
    @abstractmethod
    def register_arguments(parser: ArgumentParser) -> None:
        """
        Register command-specific arguments.

        Args:
            parser: Argument parser to register arguments with
        """
        pass


    @abstractmethod
    def execute(self) -> None:
        """Execute the command."""
        pass
