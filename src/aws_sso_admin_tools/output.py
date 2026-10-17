"""Output formatting for AWS SSO Admin Tools."""

import json
import sys
from typing import Any, List, Dict, Optional


class OutputHandler:
    """Handles output formatting for JSON and human-readable modes."""

    def __init__(self, json_output: bool = False):
        """
        Initialize output handler.

        Args:
            json_output: If True, output in JSON format. Otherwise, human-readable.
        """
        self.json_output = json_output


    def print_json(self, data: Any) -> None:
        """
        Print data in JSON format.

        Args:
            data: Data to print (must be JSON serializable)
        """
        print(json.dumps(data, indent=2, default=str))

    def print_text(self, text: str) -> None:
        """
        Print text to stdout.

        Args:
            text: Text to print
        """
        print(text)

    def print_error(self, message: str) -> None:
        """
        Print error message to stderr.

        Args:
            message: Error message to print
        """
        print(f"Error: {message}", file=sys.stderr)


    def print_list(self, items: List[Any], fields: Optional[List[str]] = None) -> None:
        """
        Print a list of items.

        Args:
            items: List of items to print
            fields: Optional list of field names to display (for dict items)
        """
        if self.json_output:
            self.print_json(items)
        else:
            for item in items:
                if isinstance(item, dict) and fields:
                    values = [str(item.get(f, '')) for f in fields]
                    print('\t'.join(values))
                else:
                    print(item)

    def print_detail(self, data: Dict[str, Any]) -> None:
        """
        Print detailed information about an item.

        Args:
            data: Dictionary of data to print
        """
        if self.json_output:
            self.print_json(data)
        else:
            for key, value in data.items():
                print(f"{key}: {value}")
