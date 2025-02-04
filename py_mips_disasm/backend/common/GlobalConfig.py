#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2022 Decompollaborate
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import enum


@enum.unique
class InputEndian(enum.Enum):
    BIG = enum.auto()
    LITTLE = enum.auto()
    MIDDLE = enum.auto()


class GlobalConfig:
    REMOVE_POINTERS: bool = False
    IGNORE_BRANCHES: bool = False # Ignores the address of every branch, jump and jal
    IGNORE_WORD_LIST: set = set() # Ignores words that starts in 0xXX

    ADD_NEW_SYMBOLS: bool = True
    AUTOGENERATED_NAMES_BASED_ON_SECTION_TYPE: bool = True
    AUTOGENERATED_NAMES_BASED_ON_DATA_TYPE: bool = True
    PRODUCE_SYMBOLS_PLUS_OFFSET: bool = False
    SYMBOL_FINDER_FILTER_LOW_ADDRESSES: bool = True
    SYMBOL_FINDER_FILTER_HIGH_ADDRESSES: bool = True

    ENDIAN: InputEndian = InputEndian.BIG

    GP_VALUE: int|None = None
    "Value used for $gp relocation loads and stores"

    PRINT_NEW_FILE_BOUNDARIES: bool = False

    ASM_COMMENT: bool = True
    WRITE_BINARY: bool = False # write to files splitted binaries
    GLABEL_ASM_COUNT: bool = True

    ASM_TEXT_LABEL: str = "glabel"
    ASM_DATA_LABEL: str = "glabel"
    ASM_TEXT_END_LABEL: str = ""

    TRUST_USER_FUNCTIONS: bool = True
    DISASSEMBLE_UNKNOWN_INSTRUCTIONS: bool = False
    DISASSEMBLE_RSP: bool = False

    STRING_GUESSER: bool = True

    QUIET: bool = False
    VERBOSE: bool = False
    PRINT_FUNCTION_ANALYSIS_DEBUG_INFO: bool = False
    PRINT_SYMBOL_FINDER_DEBUG_INFO: bool = False
    PRINT_UNPAIRED_LUIS_DEBUG_INFO: bool = False


    @staticmethod
    def addParametersToArgParse(parser: argparse.ArgumentParser):
        backendConfig = parser.add_argument_group("Disassembler backend configuration")

        backendConfig.add_argument("--disasm-unknown", help="Force disassembly of functions with unknown instructions",  action="store_true")
        backendConfig.add_argument("--disasm-rsp", help="Experimental. Enables the disassembly of rsp abi instructions. Warning: In its current state the generated asm may not be assemblable to a matching binary",  action="store_true")

        backendConfig.add_argument("--ignore-words", help="A space separated list of hex numbers. Word differences will be ignored that starts in any of the provided arguments. Max value: FF. Only works when --nuke-pointers is passed", action="extend", nargs="+")

        backendConfig.add_argument("--disable-string-guesser", help="Disables the string guesser feature (does nto affect the strings referenced by .data)", action="store_true")

        backendConfig.add_argument("--no-filter-low-addresses", help="Treat low addresses (lower than 0x40000000) as real pointers", action="store_true")
        backendConfig.add_argument("--no-filter-high-addresses", help="Treat high addresses (higher than 0xC0000000) as real pointers", action="store_true")

        backendConfig.add_argument("--no-name-vars-by-section", help="Disables the naming-after-section feature for autogenerated names. By default, autogenerated symbols get a R_ or B_ prefix if the symbol is from a rodata or bss section", action="store_true")
        backendConfig.add_argument("--no-name-vars-by-type", help="Disables the naming-after-type feature for autogenerated names. By default, autogenerated symbols can get a STR_, FLT_ or DBL_ prefix if the symbol is a string, float or double", action="store_true")

        backendConfig.add_argument("--endian", help="Set the endianness of input files. Defaults to 'big'", choices=["big", "little", "middle"])

        backendConfig.add_argument("--gp", help="Set the value used for loads and stores concering the $gp register. A hex value is expected")

        backendConfig.add_argument("--print-new-file-boundaries", help="Print to stdout any new file boundary found", action="store_true")


        miscConfig = parser.add_argument_group("Disassembler misc options")

        miscConfig.add_argument("--disable-asm-comments", help="Disables the comments in assembly code", action="store_true")
        miscConfig.add_argument("--write-binary", help="Produce a binary of the processed file", action="store_true")
        miscConfig.add_argument("--no-glabel-count", help="Disable glabel count comment", action="store_true")

        miscConfig.add_argument("--asm-text-label", help="")
        miscConfig.add_argument("--asm-data-label", help="")
        miscConfig.add_argument("--asm-end-label", help="")


        verbosityConfig = parser.add_argument_group("Verbosity options")

        verbosityConfig.add_argument("-v", "--verbose", help="Enable verbose mode",  action="store_true")
        verbosityConfig.add_argument("-q", "--quiet", help="Silence most output",  action="store_true")


        debugging = parser.add_argument_group("Disassembler debugging options")

        debugging.add_argument("--debug-func-analysis", help="Enables some debug info printing related to the function analysis)", action="store_true")
        debugging.add_argument("--debug-symbol-finder", help="Enables some debug info printing related to the symbol finder system)", action="store_true")
        debugging.add_argument("--debug-unpaired-luis", help="Enables some debug info printing related to the unpaired LUI instructions)", action="store_true")


    @classmethod
    def parseArgs(cls, args: argparse.Namespace):
        GlobalConfig.DISASSEMBLE_UNKNOWN_INSTRUCTIONS = args.disasm_unknown
        GlobalConfig.DISASSEMBLE_RSP = args.disasm_rsp

        if args.ignore_words:
            for upperByte in args.ignore_words:
                GlobalConfig.IGNORE_WORD_LIST.add(int(upperByte, 16))

        GlobalConfig.STRING_GUESSER = not args.disable_string_guesser
        GlobalConfig.SYMBOL_FINDER_FILTER_LOW_ADDRESSES = not args.no_filter_low_addresses
        GlobalConfig.SYMBOL_FINDER_FILTER_HIGH_ADDRESSES = not args.no_filter_high_addresses

        GlobalConfig.AUTOGENERATED_NAMES_BASED_ON_SECTION_TYPE = not args.no_name_vars_by_section
        GlobalConfig.AUTOGENERATED_NAMES_BASED_ON_DATA_TYPE = not args.no_name_vars_by_type

        if args.endian == "little":
            GlobalConfig.ENDIAN = InputEndian.LITTLE
        elif args.endian == "middle":
            GlobalConfig.ENDIAN = InputEndian.MIDDLE
        else:
            GlobalConfig.ENDIAN = InputEndian.BIG

        if args.gp is not None:
            GlobalConfig.GP_VALUE = int(args.gp, 16)

        GlobalConfig.PRINT_NEW_FILE_BOUNDARIES = args.print_new_file_boundaries

        GlobalConfig.WRITE_BINARY = args.write_binary
        GlobalConfig.ASM_COMMENT = not args.disable_asm_comments
        GlobalConfig.GLABEL_ASM_COUNT = not args.no_glabel_count

        if args.asm_text_label:
            GlobalConfig.ASM_TEXT_LABEL = args.asm_text_label
        if args.asm_data_label:
            GlobalConfig.ASM_DATA_LABEL = args.asm_data_label
        if args.asm_end_label:
            GlobalConfig.ASM_TEXT_END_LABEL = args.asm_end_label

        GlobalConfig.VERBOSE = args.verbose
        GlobalConfig.QUIET = args.quiet

        GlobalConfig.PRINT_FUNCTION_ANALYSIS_DEBUG_INFO = args.debug_func_analysis
        GlobalConfig.PRINT_SYMBOL_FINDER_DEBUG_INFO = args.debug_symbol_finder
        GlobalConfig.PRINT_SYMBOL_FINDER_DEBUG_INFO = args.debug_unpaired_luis
