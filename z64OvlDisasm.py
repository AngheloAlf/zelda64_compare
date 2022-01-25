#!/usr/bin/python3

from __future__ import annotations

import argparse
import os

from py_mips_disasm.mips.Utils import *
from py_mips_disasm.mips.GlobalConfig import GlobalConfig, printQuietless, printVerbose
from py_mips_disasm.mips.MipsContext import Context
from py_mips_disasm.mips.FileSplitFormat import FileSplitFormat

from mips.MipsFileOverlay import FileOverlay
from mips.ZeldaTables import getFileAddresses


def ovlDisassemblerMain():
    description = ""
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("binary", help="Path to input binary")
    parser.add_argument("output", help="Path to output. Use '-' to print to stdout instead")

    parser.add_argument("--file-splits", help="Path to a file splits csv")

    parser.add_argument("--file-addresses", help="Path to a csv with the addresses of every file")

    args = parser.parse_args()

    GlobalConfig.VERBOSE = True

    array_of_bytes = readFileAsBytearray(args.binary)
    input_name = os.path.splitext(os.path.split(args.binary)[1])[0]

    # head, tail = os.path.split(args.output)


    context = Context()

    splitsData = None
    if args.file_splits is not None and os.path.exists(args.file_splits):
        splitsData = FileSplitFormat(args.file_splits)

    fileAddresses = getFileAddresses(args.file_addresses)

    f = FileOverlay(array_of_bytes, input_name, "ver", context, splitsData=splitsData)

    if input_name in fileAddresses:
        if f.vRamStart < 0:
            f.setVRamStart(fileAddresses[input_name].vramStart)

    printVerbose("Analyzing")
    f.analyze()
    f.setCommentOffset(0)

    os.makedirs(args.output, exist_ok=True)

    f.saveToFile(args.output)


if __name__ == "__main__":
    ovlDisassemblerMain()
