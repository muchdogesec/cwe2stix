import os
import argparse
from cwe2stix.cwe2stix import Cwe2Stix

parser = argparse.ArgumentParser()


def main(version=None):
    Cwe2Stix(version=version).run()


if __name__ == "__main__":
    parser.add_argument(
        "-v", "--version", help="Run script for Specific Versions (4.0 Till 4.12)"
    )
    parser.add_argument(
        "-g", "--get_version", help="Run script for Specific Versions (4.0 Till 4.12)"
    )
    args = parser.parse_args()
    main(version=args.version)
