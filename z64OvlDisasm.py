#! /usr/bin/env python3

from __future__ import annotations

import argparse
import os
from typing import List

import py_mips_disasm.backend as disasmBack

from mips.ZeldaTables import getFileAddresses


def writeFiles(ovlSection: disasmBack.mips.FileSplits, textOutput: str, dataOutput: str|None):
    disasmBack.Utils.printVerbose("Writing files...")

    if dataOutput is None:
        dataOutput = textOutput

    textOutput += "/"
    dataOutput += "/"

    head, tail = os.path.split(textOutput)

    # Create directories
    if head != "":
        os.makedirs(head, exist_ok=True)

    head, tail = os.path.split(dataOutput)

    # Create directories
    if head != "":
        os.makedirs(head, exist_ok=True)

    for subFileName, section in ovlSection.sectionsDict[disasmBack.FileSectionType.Text].items():
        section.saveToFile(os.path.join(textOutput, subFileName))

    for sectionType, filesinSection in ovlSection.sectionsDict.items():
        if sectionType == disasmBack.FileSectionType.Text:
            continue
        for subFileName, section in filesinSection.items():
            section.saveToFile(os.path.join(dataOutput, subFileName))


# Return the name of the file after the overlay file, which is its reloc file in Animal Forest
def findRelocFile(input_name: str, file_addresses: str) -> str:
    if file_addresses is not None and os.path.exists(file_addresses):
        with open(file_addresses) as f:
            header = True
            retNext = False
            for line in f:
                if header:
                    # Skip csv header
                    header = False
                    continue
                if retNext:
                    return line.strip().split(",")[0]
                filename = line.strip().split(",")[0]
                if input_name == filename:
                    retNext = True
    raise RuntimeError("Relocation file not found.")


def ovlDisassemblerMain():
    description = ""
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("binary", help="Path to input binary")
    parser.add_argument("output", help="Path to output. Use '-' to print to stdout instead")

    parser.add_argument("-r", "--reloc-separate", help="Should look for separate relocation file", action="store_true")

    parser.add_argument("--data-output", help="Path to output the data and rodata disassembly")

    parser.add_argument("--file-splits", help="Path to a file splits csv")

    parser.add_argument("--file-addresses", help="Path to a csv with the addresses of every file")

    parser.add_argument("--split-functions", help="Enables the function and rodata splitter. Expects a path to place the splited functions", metavar="PATH")

    parser.add_argument("--nuke-pointers", help="Use every technique available to remove pointers", action="store_true")

    disasmBack.Context.addParametersToArgParse(parser)

    disasmBack.GlobalConfig.addParametersToArgParse(parser)

    parser.add_argument("--add-filename", help="Adds the filename of the file to the generated function/variable name")

    args = parser.parse_args()

    disasmBack.GlobalConfig.parseArgs(args)

    disasmBack.GlobalConfig.REMOVE_POINTERS = args.nuke_pointers
    disasmBack.GlobalConfig.IGNORE_BRANCHES = args.nuke_pointers
    if args.nuke_pointers:
        disasmBack.GlobalConfig.IGNORE_WORD_LIST.add(0x80)

    disasmBack.GlobalConfig.PRODUCE_SYMBOLS_PLUS_OFFSET = True
    disasmBack.GlobalConfig.TRUST_USER_FUNCTIONS = True


    context = disasmBack.Context()
    context.parseArgs(args)

    array_of_bytes = disasmBack.Utils.readFileAsBytearray(args.binary)
    input_name = os.path.splitext(os.path.split(args.binary)[1])[0]


    splitsData = None
    if args.file_splits is not None and os.path.exists(args.file_splits):
        splitsData = disasmBack.FileSplitFormat()
        splitsData.readCsvFile(args.file_splits)

    fileAddresses = getFileAddresses(args.file_addresses)

    if args.reloc_separate:
        reloc_filename = findRelocFile(input_name, args.file_addresses)
        reloc_path = os.path.join(os.path.split(args.binary)[0], reloc_filename)

        vram = None
        if reloc_filename in fileAddresses:
            vram = fileAddresses[reloc_filename].vramStart
        relocSection = disasmBack.mips.sections.SectionRelocZ64(context, vram, input_name, disasmBack.Utils.readFileAsBytearray(reloc_path))
        relocSection.differentSegment = True
    else:
        relocSection = disasmBack.mips.sections.SectionRelocZ64(context, None, input_name, array_of_bytes)
        relocSection.differentSegment = False


    vramStart = None
    if input_name in fileAddresses:
        vramStart = fileAddresses[input_name].vramStart

    f = disasmBack.mips.FileSplits(context, vramStart, input_name, array_of_bytes, splitsData=splitsData, relocSection=relocSection)

    f.analyze()

    if disasmBack.GlobalConfig.VERBOSE:
        for sectDict in f.sectionsDict.values():
            for section in sectDict.values():
                section.printAnalyzisResults()

    if args.nuke_pointers:
        disasmBack.Utils.printVerbose("Nuking pointers...")
        f.removePointers()

    writeFiles(f, args.output, args.data_output)

    if args.split_functions is not None:
        disasmBack.Utils.printVerbose("Spliting functions")
        rodataList: List[disasmBack.mips.sections.SectionRodata] = list()
        for rodataName, rodataSection in f.sectionsDict[disasmBack.FileSectionType.Rodata].items():
            assert(isinstance(rodataSection, disasmBack.mips.sections.SectionRodata))
            rodataList.append(rodataSection)
        for path, subFile in f.sectionsDict[disasmBack.FileSectionType.Text].items():
            assert(isinstance(subFile, disasmBack.mips.sections.SectionText))
            for func in subFile.symbolList:
                assert isinstance(func, disasmBack.mips.symbols.SymbolFunction)
                disasmBack.mips.FilesHandlers.writeSplitedFunction(os.path.join(args.split_functions, subFile.name), func, rodataList, context)
        disasmBack.mips.FilesHandlers.writeOtherRodata(args.split_functions, rodataList, context)

    if args.save_context is not None:
        head, tail = os.path.split(args.save_context)
        if head != "":
            os.makedirs(head, exist_ok=True)
        context.saveContextToFile(args.save_context)


if __name__ == "__main__":
    ovlDisassemblerMain()
