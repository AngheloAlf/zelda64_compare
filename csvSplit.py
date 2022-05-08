#! /usr/bin/env python3

from __future__ import annotations

import argparse
import os

import py_mips_disasm.backend as disasmBack

from mips.MipsSplitEntry import readSplitsFromCsv



def _split_fileSplits_withPrefix(game: str, seg: str, categoryPrefix: str):
    sections = ["text", "data", "rodata", "bss"]

    tablePerVersion = dict()

    for section in sections:
        csvPath = os.path.join(game, "tables", f"{categoryPrefix}{seg}.{section}.csv")

        if not os.path.exists(csvPath):
            continue

        splits = readSplitsFromCsv(csvPath)
        # print(splits)

        for version, filesDict in splits.items():
            # print(version)

            if version == "":
                continue

            if version not in tablePerVersion:
                tablePerVersion[version] = dict()

            auxList = []

            for filename, splitDataList in filesDict.items():
                for splitData in splitDataList:
                    # print("\t", filename, splitData)
                    if splitData.offset < 0 or splitData.vram < 0 or splitData.filename == "":
                        continue
                    auxList.append((splitData.offset, splitData.vram, splitData.size, splitData.filename))

            if len(auxList) == 0:
                continue

            # fake extra to avoid problems
            auxList.append((0xFFFFFF, 0x80FFFFFF, 0, "end"))

            # Reading from the file may not be sorted by offset
            auxList.sort()

            tablePerVersion[version][section] = list()

            i = 0
            while i < len(auxList) - 1:
                offset, vram, size, filename = auxList[i]
                nextOffset, _, _, _ = auxList[i+1]

                end = offset + size
                if size <= 0:
                    end = nextOffset

                if end < nextOffset:
                    # Adds missing files
                    auxList.insert(i+1, (end, vram + (end - offset), -1, f"file_{end:06X}"))

                tablePerVersion[version][section].append((offset, vram, filename))

                i += 1


    for version, sectionedDict in tablePerVersion.items():
        sections = list(sectionedDict.keys())
        for i in range(len(sections)-1):
            currentSection = sections[i]
            nextSection = sections[i+1]
            lastOffsetCurrent = sectionedDict[currentSection][-1][0]
            firstOffsetNext = sectionedDict[nextSection][0][0]
            if lastOffsetCurrent == firstOffsetNext:
                del sectionedDict[currentSection][-1]

    for version, sectionedDict in tablePerVersion.items():
        isFirst = True
        dstFolder = os.path.join(game, version, "tables")
        os.makedirs(dstFolder, exist_ok=True)
        with open(os.path.join(dstFolder, f"files_{seg}.csv"), "w") as f:
            for section, data in sectionedDict.items():
                if isFirst:
                    isFirst = False
                else:
                    f.write("\n")

                f.write(f"offset,vram,.{section}\n")
                for row in data:
                    offset, vram, filename = row
                    f.writelines(f"{offset:X},{vram:X},{filename}\n")

def split_fileSplits(game: str, seg: str):
    categoriesPrefixes = ["", "iQue."]

    for catPrefix in categoriesPrefixes:
        _split_fileSplits_withPrefix(game, seg, catPrefix)


def split_functions(game: str):
    csvPath = os.path.join(game, "tables", "functions.csv")

    tablePerVersion: dict[str, dict[int, str]] = dict()

    functions = disasmBack.Utils.readCsv(csvPath)

    columnsToDiscard = 1
    if functions[0][1] != "":
        columnsToDiscard = int(functions[0][1])

    header = functions[0][columnsToDiscard+1:]
    for i in range(columnsToDiscard+1, len(functions)):
        funcName = functions[i][0]
        data = functions[i][columnsToDiscard+1:]

        if funcName == "":
            continue

        for headerIndex, version in enumerate(header):
            if version not in tablePerVersion:
                tablePerVersion[version] = dict()

            vramStr = data[headerIndex]
            if vramStr == "":
                continue
            if vramStr == "-":
                continue

            vram = int(vramStr, 16)
            if vram in tablePerVersion[version]:
                disasmBack.Utils.eprint(f"Warning: Duplicated function's VRAM found in version '{version}'")
                oldFuncName = tablePerVersion[version][vram]
                disasmBack.Utils.eprint(f"\t old: {vram:08X},{oldFuncName}")
                disasmBack.Utils.eprint(f"\t new: {vram:08X},{funcName}")
                disasmBack.Utils.eprint(f"\t Discarding old")
            if funcName in tablePerVersion[version].values():
                disasmBack.Utils.eprint(f"Warning: Duplicated function name found in version '{version}'")
                oldVram = vram
                for oldVram, oldFuncName in tablePerVersion[version].items():
                    if funcName == oldFuncName:
                        break
                disasmBack.Utils.eprint(f"\t old: {oldVram:08X},{funcName}")
                disasmBack.Utils.eprint(f"\t new: {vram:08X},{funcName}")

            tablePerVersion[version][vram] = funcName

    for version, funcVramDict in tablePerVersion.items():
        dstFolder = os.path.join(game, version, "tables")
        os.makedirs(dstFolder, exist_ok=True)
        with open(os.path.join(dstFolder, "functions.csv"), "w") as f:
            for vram, funcName in sorted(funcVramDict.items()):
                f.writelines(f"{vram:08X},{funcName}\n")


def split_variables(game: str):
    csvPath = os.path.join(game, "tables", "variables.csv")

    tablePerVersion: dict[str, dict[int, tuple[str, str, int]]] = dict()

    variables = disasmBack.Utils.readCsv(csvPath)
    header = variables[0][3:]
    for i in range(2, len(variables)):
        varName, type, _, *data = variables[i]

        if varName == "":
            continue

        for headerIndex, version in enumerate(header[::2]):
            if version not in tablePerVersion:
                tablePerVersion[version] = dict()

            # print(varName, version, data)
            vramStr, sizeStr = data[2*headerIndex : 2*headerIndex + 2]
            if vramStr == "":
                continue
            if vramStr == "-":
                continue
            if sizeStr == "":
                sizeStr = "4"

            vram = int(vramStr, 16)
            size = int(sizeStr, 16)
            if vram in tablePerVersion[version]:
                disasmBack.Utils.eprint(f"Warning: Duplicated variable's VRAM found in version '{version}'")
                oldVarName, oldType, oldSize = tablePerVersion[version][vram]
                disasmBack.Utils.eprint(f"\t old: {vram:08X},{oldVarName},{oldType},0x{oldSize:X}")
                disasmBack.Utils.eprint(f"\t new: {vram:08X},{varName},{type},0x{size:X}")
                disasmBack.Utils.eprint(f"\t Discarding old")
            for oldVram, (oldVarName, oldType, oldSize) in tablePerVersion[version].items():
                if varName == oldVarName:
                    disasmBack.Utils.eprint(f"Warning: Duplicated variable name found in version '{version}'")
                    disasmBack.Utils.eprint(f"\t old: {oldVram:08X},{oldVarName},{oldType},0x{oldSize:X}")
                    disasmBack.Utils.eprint(f"\t new: {vram:08X},{varName},{type},0x{size:X}")
                    break

            tablePerVersion[version][vram] = (varName, type, size)

    for version, variablesVramDict in tablePerVersion.items():
        dstFolder = os.path.join(game, version, "tables")
        os.makedirs(dstFolder, exist_ok=True)
        with open(os.path.join(dstFolder, "variables.csv"), "w") as f:
            for vram, (varName, type, size) in sorted(variablesVramDict.items()):
                f.writelines(f"{vram:08X},{varName},{type},0x{size:X}\n")


def main():
    description = ""

    epilog = f"""\
    """
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    choices = ["oot", "mm", "dnm"]
    parser.add_argument("game", help="", choices=choices)
    parser.add_argument("csv", help="") # TODO
    args = parser.parse_args()

    seg = os.path.split(args.csv)[-1].split('.')[0]

    if seg == "functions":
        split_functions(args.game)
    elif seg == "variables":
        split_variables(args.game)
    else:
        split_fileSplits(args.game, seg)


if __name__ == "__main__":
    main()
