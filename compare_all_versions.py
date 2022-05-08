#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
from multiprocessing import Pool, cpu_count
from functools import partial

import py_mips_disasm.backend as disasmBack

from mips.ZeldaTables import contextReadVariablesCsv, contextReadFunctionsCsv, getFileAddresses, FileAddressesEntry


def countUnique(row: list) -> int:
    unique = set(row)
    count = len(unique)
    if "" in unique:
        count -= 1
    return count

def removePointers(args, filedata: bytearray) -> bytearray:
    if args.dont_remove_ptrs:
        return filedata
    if not args.ignore04: # This will probably grow...
        return filedata

    words = disasmBack.Utils.bytesToBEWords(filedata)
    for i in range(len(words)):
        w = words[i]
        if args.ignore04:
            if ((w >> 24) & 0xFF) == 0x04:
                words[i] = 0x04000000
    return disasmBack.Utils.beWordsToBytes(words, filedata)


def getHashesOfFiles(args, filesPath: list[str]) -> list[str]:
    hashList = []
    for path in filesPath:
        f = disasmBack.Utils.readFileAsBytearray(path)
        if len(f) != 0:
            fHash = disasmBack.Utils.getStrHash(removePointers(args, f))
            line = fHash + " " + path # To be consistent with runCommandGetOutput("md5sum", md5arglist)
            hashList.append(line)
    return hashList

def compareFileAcrossVersions(filename: str, game: str, versionsList: list[str], contextPerVersion: dict[str, disasmBack.Context], fileAddressesPerVersion: dict, args) -> list[list[str]]:
    md5arglist = list(map(lambda orig_string: game + "/" + orig_string + "/" + "baserom" + "/" + filename, versionsList))
    # os.system( "md5sum " + " ".join(filesPath) )

    # Get hashes.
    # output = runCommandGetOutput("md5sum", filesPath)
    output = getHashesOfFiles(args, md5arglist)

    # Print md5hash
    #print("\n".join(output))
    #print()

    filesHashes = dict() # "NN0": "339614255f179a1e308d954d8f7ffc0a"
    firstFilePerHash = dict() # "339614255f179a1e308d954d8f7ffc0a": "NN0"

    for line in output:
        trimmed = disasmBack.Utils.removeExtraWhitespace(line)
        filehash, filepath = trimmed.split(" ")
        version = filepath.split("/")[1]

        # Map each abbreviation and its hash.
        filesHashes[version] = filehash

        # Find out where in which version this hash appeared for first time.
        if filehash not in firstFilePerHash:
            firstFilePerHash[filehash] = version

    row = [filename]
    for ver in versionsList:
        if ver in filesHashes:
            fHash = filesHashes[ver]
            row.append(firstFilePerHash[fHash])
        else:
            row.append("")
    return [row]

def compareOverlayAcrossVersions(filename: str, game: str, versionsList: list[str], contextPerVersion: dict[str, disasmBack.Context], fileAddressesPerVersion: dict[str, dict[str, FileAddressesEntry]], args) -> list[list[str]]:
    column = []
    filesHashes = dict() # "filename": {"NN0": hash}
    firstFilePerHash = dict() # "filename": {hash: "NN0"}

    if filename.startswith("#"):
        return column

    is_overlay = filename.startswith("ovl_")

    for version in versionsList:
        splitsData = None
        tablePath = os.path.join(game, version, "tables", f"files_{filename}.csv")
        if os.path.exists(tablePath):
            # print(tablePath)
            splitsData = disasmBack.FileSplitFormat()
            splitsData.readCsvFile(tablePath)

        path = os.path.join(game, version, "baserom", filename)

        array_of_bytes = disasmBack.Utils.readFileAsBytearray(path)
        if len(array_of_bytes) == 0:
            # print(f"Skipping {path}")
            continue

        if is_overlay:
            vramStart = None
            if version in fileAddressesPerVersion:
                if filename in fileAddressesPerVersion[version]:
                    vramStart = fileAddressesPerVersion[version][filename].vramStart

            relocSection = disasmBack.mips.sections.SectionRelocZ64(contextPerVersion[version], None, filename, array_of_bytes)
            f = disasmBack.mips.FileSplits(contextPerVersion[version], vramStart, filename, array_of_bytes, relocSection=relocSection)
        elif filename in ("code", "boot", "n64dd"):
            f = disasmBack.mips.FileSplits(contextPerVersion[version], None, filename, array_of_bytes, splitsData=splitsData)
        else:
            f = disasmBack.mips.sections.SectionBase(contextPerVersion[version], None, filename, array_of_bytes, disasmBack.FileSectionType.Unknown)

        f.analyze()

        if disasmBack.GlobalConfig.REMOVE_POINTERS:
            f.removePointers()

        if isinstance(f, disasmBack.mips.FileSplits):
            subfiles = {
                ".text" : f.sectionsDict[disasmBack.FileSectionType.Text],
                ".data" : f.sectionsDict[disasmBack.FileSectionType.Data],
                ".rodata" : f.sectionsDict[disasmBack.FileSectionType.Rodata],
                #".bss" : f.bss,
            }
        else:
            subfiles = {
                "" : {"": f},
            }

        for sectionName, sectionCat in subfiles.items():
            for name, sub in sectionCat.items():
                if is_overlay:
                    name = ""
                if name != "":
                    name = "." + name
                file_section = filename + name + sectionName
                if file_section not in filesHashes:
                    filesHashes[file_section] = dict()
                    firstFilePerHash[file_section] = dict()

                f_hash = sub.getHash()
                # Map each abbreviation to its hash.
                filesHashes[file_section][version] = f_hash

                # Find out where in which version this hash appeared for first time.
                if f_hash not in firstFilePerHash[file_section]:
                    firstFilePerHash[file_section][f_hash] = version

    for file_section in filesHashes:
        row = [file_section]
        for version in versionsList:
            if version in filesHashes[file_section]:
                fHash = filesHashes[file_section][version]
                row.append(firstFilePerHash[file_section][fHash])
            else:
                row.append("")
        column.append(row)

    return column


def main():
    parser = argparse.ArgumentParser()
    choices = ["oot", "mm"]
    parser.add_argument("game", help="Game to comapre.", choices=choices)
    parser.add_argument("versionlist", help="Path to version list.")
    parser.add_argument("filelist", help="list of filenames of the ROM that will be compared.")
    parser.add_argument("--noheader", help="Disables the csv header.", action="store_true")
    # parser.add_argument("--overlays", help="Treats the files in filelist as overlays.", action="store_true")
    parser.add_argument("--ignore-words", help="A space separated list of hex numbers. Word differences will be ignored that starts in any of the provided arguments. Max value: FF", action="extend", nargs="+")
    parser.add_argument("--ignore-branches", help="Ignores the address of every branch, jump and jal.", action="store_true")
    parser.add_argument("--dont-remove-ptrs", help="Disable the pointer removal feature.", action="store_true")
    parser.add_argument("--disable-multiprocessing", help="", action="store_true")
    args = parser.parse_args()

    disasmBack.GlobalConfig.REMOVE_POINTERS = not args.dont_remove_ptrs
    disasmBack.GlobalConfig.IGNORE_BRANCHES = args.ignore_branches
    if args.ignore_words:
        for upperByte in args.ignore_words:
            disasmBack.GlobalConfig.IGNORE_WORD_LIST.add(int(upperByte, 16))
    disasmBack.GlobalConfig.PRODUCE_SYMBOLS_PLUS_OFFSET = True

    # Read filelist
    versionsList = []
    with open(args.versionlist) as f:
        for version in f:
            if version.startswith("#"):
                continue
            versionsList.append(version.strip())
    filesList = disasmBack.Utils.readFile(args.filelist)

    contextPerVersion: dict[str, disasmBack.Context] = dict()
    for version in versionsList:
        context = disasmBack.Context()
        context.fillDefaultBannedSymbols()
        context.fillLibultraSymbols()
        context.fillHardwareRegs()
        contextReadVariablesCsv(context, args.game, version)
        contextReadFunctionsCsv(context, args.game, version)
        contextPerVersion[version] = context

    fileAddressesPerVersion: dict[str, dict[str, FileAddressesEntry]] = dict()
    for version in versionsList:
        fileAddressesPerVersion[version] = getFileAddresses(os.path.join(args.game, version, "tables", "file_addresses.csv"))

    if not args.noheader:
        # Print csv header
        print("File name", end="")
        for ver in versionsList:
            print("," + ver, end="")
        print(",Different versions", end="")
        print()

    # compareFunction = compareFileAcrossVersions
    # if args.overlays:
    #     compareFunction = compareOverlayAcrossVersions
    compareFunction = compareOverlayAcrossVersions

    if args.disable_multiprocessing:
        for filename in filesList:
            for row in compareFunction(filename, args.game, versionsList=versionsList, contextPerVersion=contextPerVersion, fileAddressesPerVersion=fileAddressesPerVersion, args=args):
                # Print csv row
                for cell in row:
                    print(cell + ",", end="")
                print(countUnique(row)-1)
    else:
        numCores = cpu_count()
        p = Pool(numCores)
        for column in p.imap(partial(compareFunction, game=args.game, versionsList=versionsList, contextPerVersion=contextPerVersion, fileAddressesPerVersion=fileAddressesPerVersion, args=args), filesList):
            for row in column:
                # Print csv row
                for cell in row:
                    print(cell + ",", end="")
                print(countUnique(row)-1)


if __name__ == "__main__":
    main()
