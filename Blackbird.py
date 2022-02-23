#!/usr/bin/env python3

import argparse
import asyncio

from blackbird.core.engine import BlackBird
from blackbird.core.exceptions import BlackBirdError
from blackbird.core import log


async def main():
    parser = argparse.ArgumentParser(description="Network reconnaissance and enumeration tool.",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--input-files', help='Input nmap XML files (comma separated)')
    parser.add_argument('-s', '--single-target', help='Single target mode (target.com:2222 or target.com)')
    parser.add_argument('-o', '--output-dir', help='Store results there (default: create tempdir)')
    parser.add_argument('-m', '--modules', default="default", help='Comma-separated list of modules ( or module tags) to run')
    parser.add_argument('--search', help='Seach hosts by keyword, e.g "ldap", "Apache", ...')
    parser.add_argument('-lm', '--list-modules', action='store_true',
                        help='List available modules')


    group2 = parser.add_argument_group('Advanced options')
    group2.add_argument('-t', '--targets', help="Comma separated list of targets to run modules on (default : all hosts in nmap XML file)")
    group2.add_argument('-H', '--host-file', help='Hostnames / IP association file in /etc/hosts file format')
    group2.add_argument('-U', '--userlist', help='Custom userlist to try on all services')
    group2.add_argument('-P', '--passlist', help='Custom password list to try on all services')
    group2.add_argument('-C', '--userpasslist', help='User/password combinations (user:pass one by line)')
    group2.add_argument('--brute-type', choices=['default', 'custom'], default="default",
        help='Bruteforce type: default (default wordlists + any custom wordlist) or custom (only custom wordlists)')
    
    group3 = parser.add_argument_group('Misc options')
    group3.add_argument('--dry-run', action='store_true', help='Print commands but do not execute')
    group3.add_argument('-c', '--max-concurrency', type=int, help='Max concurrent tasks')
    group3.add_argument('--logo', action='store_true', help='Show logo')
    group3.add_argument('--cmd-timeout', type=int, help='Timeout for external commands (seconds)')
    group3.add_argument('-q', '--quiet', action='store_true', help='Show only command output')
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
        targets=args.targets,
        cmd_timeout=args.cmd_timeout,
        show_logo=args.logo,
        max_tasks=args.max_concurrency,
        dry_run=args.dry_run,
        single_host=args.single_target,
        quiet=args.quiet)
    if args.list_modules:
        for module_name in blackbird.get_module_list():
            print(module_name)
        return
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
