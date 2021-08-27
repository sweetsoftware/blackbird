#!/usr/bin/env python3

import argparse
import asyncio

from blackbird.core.engine import BlackBird
from blackbird.core.exceptions import BlackBirdError
from blackbird.core import log


async def main():
    parser = argparse.ArgumentParser(description="Network reconnaissance and enumeration tool.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--input-files', help='Import nmap XML files (comma separated)')
    parser.add_argument('-o', '--output-dir', help='Store results there')
    parser.add_argument('-M', '--modules', default="default", help='Run only selected modules (comma separated), or module tags')
    parser.add_argument('-t', '--targets', help="Comma separated list of targets. Will only scan these.")
    parser.add_argument('-H', '--host-file', help='Hostnames file')
    parser.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    parser.add_argument('-P', '--passlist', help='Custom password list to try on all services')
    parser.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    parser.add_argument('--brute-type', choices=['default', 'custom'], default="default",
        help='Bruteforce type: default (default wordlists + any custom wordlist) or custom (only custom wordlists)')
    parser.add_argument('--search', help='Seach hosts by keyword, e.g "ldap", "Apache", ...')
    parser.add_argument('--list-modules', action='store_true',
                        help='List available modules')
    parser.add_argument('--dry-run', action='store_true', help='Print commands but do not execute')
    args = parser.parse_args()

    blackbird = BlackBird(
        input_files=args.input_files,
        host_file=args.host_file,
        search=args.search,
        output_dir=args.output_dir,
        modules=args.modules,
        user_list=args.userlist,
        pass_list=args.passlist,
        userpass_list=args.userpasslist,
        brute_type=args.brute_type,
        targets=args.targets)
    await blackbird.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BlackBirdError as err:
        log.error(str(err))
    except Exception as exc:
        print('Unhandled exception : %s' % exc)
        import traceback
        traceback.print_exc()
