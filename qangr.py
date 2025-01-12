#!/usr/bin/env python3
import logging
import argparse
import sys
import angr, claripy 

"""Argparse Stuff"""

about = "A streamlined CLI tool (a wrapper for the Angr framework) designed to simplify and accelerate CTF challenge solving.\n\nMade with ❤️ by qvipin"
parser = argparse.ArgumentParser(description=about, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("binary", metavar="<binary>", help='Target Binary (e.g. chall or crackme)')
# will add input through args soon...
# parser.add_argument("-IA", "--input-through-args", metavar="<Bits>", help="Use if binary takes input through args (e.g., ./chall <password>) and specify max bit size", required=False)
parser.add_argument("-g", "--good-address", metavar="<0x00000>", help='Good Address (Win Func)', required=True)
parser.add_argument("-b", "--bad-address", metavar="<0x00000>", help='Bad Address (e.g. puts(str: "Incorrect!"))', required=False)
parser.add_argument("-B", "--base-address", metavar="<0x00000 or auto>", help='Base Address; Use 0x400000 or Specify AUTO for PIE Binaries (Default is `0x000000`)', required=False)
parser.add_argument("--DFS", action='store_true', help='Uses DFS exploration instead of the default BFS Exploration', required=False)
parser.add_argument("--binary-info", action='store_true', help='Specify argument for additional binary information.', required=False)
parser.add_argument("--angr-logging-level", help='Logging level for angr (Default: WARNING and higher). Use --angr-logging-level=<value>.', choices=["DEBUG", "INFO"],  required=False)

args = parser.parse_args()
path_to_binary = args.binary # Binary Path Here

from pwn import context, ELF # Import moved here due to ArgParse issues

"""Binary Info"""
try:
    if args.binary_info:
        context.log_level = 'warning'
        print(ELF(path_to_binary))
except FileNotFoundError:
    print("usage: qangr [-h] -g <0x00000> [-b <0x00000>] [-B <0x00000 or auto>] [--DFS] [--binary-info] [--angr-logging-level {DEBUG,INFO}] <binary>\nqangr: error: the following arguments are required: <binary>")


""" WIP
if not sys.maxsize > 2**32 and binary.arch != ["i386", "amd64"]:
    print("[*] Your system isn't x86_64, the binary may be incompatible for u")
"""


"""Angr Stuff"""
try:
    if args.angr_logging_level: # Managing log levels for angr and pwn
        logging.getLogger('angr').setLevel(f'{args.angr_logging_level}')
    logging.getLogger("pwnlib.elf.elf").setLevel(logging.ERROR)

    project = angr.Project(path_to_binary, auto_load_libs=False) 

# base address checks
    if args.base_address is None:
        base = 0x000000
    elif args.base_address.lower() == "auto":
        base = project.loader.main_object.min_addr # auto base address search
    else:
        base = int(args.base_address, 16)

    good_address = base + int(args.good_address, 16)

# entry state/sim
    initial_state = project.factory.entry_state()
    sim = project.factory.simgr(initial_state) # Sim starts here.
    print('[*] Exploring ts (this) 💔...')

# checks for options and the specified way on simulation
    if args.bad_address and args.DFS is None: # If bad address is specified but no DFS
        bad_address = base + int(args.bad_address, 16)
        sim.explore(find=good_address, avoid=bad_address)
    elif args.bad_address and args.DFS: # bad addr and dfs 
        bad_address = base + int(args.bad_address, 16)
        sim.use_technique(angr.exploration_techniques.DFS())
        sim.explore(find=good_address, avoid=bad_address)
    else: # nothing
        sim.explore(find=good_address)

# Checking if Simgr found anything
    if sim.found: 
        solution_state = sim.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print(f"[*] Solution found: {solution}")
    elif not args.base_address and ELF(path_to_binary).pie: # Checking if base address is not specified and if PIE is enabled
         print("[*] Solution not found. PIE detected. Please specify a base address (e.g., 0x400000).")
    elif not args.bad_address or not args.base_address:
        print("[*] Solution not found. Providing all optional arguments may improve your chances of success. Please specify them and try again.")
    else:
        print("[*] Solution not found.")
except ValueError:
    print("[*] Error: Please provide valid arguments. Use -h for help.")
except KeyboardInterrupt:
    print("[*] CTRL + C Detected, quitting program.")
