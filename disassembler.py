#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os

import py_mips_disasm.backend as disasmBack

from mips.ZeldaTables import contextReadVariablesCsv, contextReadFunctionsCsv, getFileAddresses


def disassembleFile(version: str, filename: str, game: str, outputfolder: str, context: disasmBack.Context, vram: int = -1, textend: int = -1):
    is_overlay = filename.startswith("ovl_")

    path = os.path.join(game, version, "baserom", filename)

    array_of_bytes = disasmBack.Utils.readFileAsBytearray(path)
    if len(array_of_bytes) == 0:
        disasmBack.Utils.eprint(f"File '{path}' not found!")
        exit(-1)

    splitsData = None
    tablePath = os.path.join(game, version, "tables", f"files_{filename}.csv")
    if os.path.exists(tablePath):
        # print(tablePath)
        splitsData = disasmBack.FileSplitFormat()
        splitsData.readCsvFile(tablePath)

    if is_overlay:
        print("Overlay detected. Parsing...")

        vramStart = None
        fileAddresses = getFileAddresses(os.path.join(game, version, "tables", "file_addresses.csv"))
        if filename in fileAddresses:
            vramStart = fileAddresses[filename].vramStart

        relocSection = disasmBack.mips.sections.SectionRelocZ64(context, None, filename, array_of_bytes)
        f = disasmBack.mips.FileSplits(context, vramStart, filename, array_of_bytes, relocSection=relocSection)
    elif filename in ("code", "boot", "n64dd"):
        print(f"{filename} detected. Parsing...")
        f = disasmBack.mips.FileSplits(context, None, filename, array_of_bytes, splitsData=splitsData)
    else:
        print("Unknown file type. Assuming .text. Parsing...")

        text_data = array_of_bytes
        if textend >= 0:
            print(f"Parsing until offset {disasmBack.Utils.toHex(textend, 2)}")
            text_data = array_of_bytes[:textend]

        f = disasmBack.mips.sections.SectionText(context, None, filename, text_data)

    if vram >= 0:
        print(f"Using VRAM {disasmBack.Utils.toHex(vram, 8)[2:]}")
        f.setVram(vram)

    f.analyze()

    print()
    print(f"Found {f.nFuncs} functions.")

    new_file_folder = os.path.join(outputfolder, filename)
    os.makedirs(new_file_folder, exist_ok=True)
    new_file_path = os.path.join(new_file_folder, filename)

    nBoundaries: int = 0
    if isinstance(f, disasmBack.mips.FileSplits):
        for name, text in f.sectionsDict[disasmBack.FileSectionType.Text].items():
            assert(isinstance(text, disasmBack.mips.sections.SectionText))
            nBoundaries += len(text.fileBoundaries)
    else:
        nBoundaries += len(f.fileBoundaries)
    if nBoundaries > 0:
        print(f"Found {nBoundaries} file boundaries.")

    print(f"Writing files to {new_file_folder}")
    f.saveToFile(new_file_path)

    print()
    print("Disassembling complete!")
    print("Goodbye.")


def disassemblerMain():
    description = ""
    parser = argparse.ArgumentParser(description=description)
    choices = ["oot", "mm"]
    parser.add_argument("game", help="Game to disassemble.", choices=choices)
    parser.add_argument("version", help="Select which baserom folder will be used. Example: ique_cn would look up in folder baserom_ique_cn")
    parser.add_argument("file", help="File to be disassembled from the baserom folder.")
    parser.add_argument("outputfolder", help="Path to output folder.")
    parser.add_argument("--vram", help="Set the VRAM address for unknown files.", default="-1")
    parser.add_argument("--text-end-offset", help="Set the offset of the end of .text section for unknown files.", default="-1")
    parser.add_argument("--disable-asm-comments", help="Disables the comments in assembly code.", action="store_true")
    parser.add_argument("--save-context", help="Saves the context to a file. The provided filename will be suffixed with the corresponding version.", metavar="FILENAME")
    args = parser.parse_args()

    disasmBack.GlobalConfig.REMOVE_POINTERS = False
    disasmBack.GlobalConfig.IGNORE_BRANCHES = False
    disasmBack.GlobalConfig.WRITE_BINARY = False
    disasmBack.GlobalConfig.ASM_COMMENT = not args.disable_asm_comments
    disasmBack.GlobalConfig.PRODUCE_SYMBOLS_PLUS_OFFSET = True

    context = disasmBack.Context()
    context.fillDefaultBannedSymbols()
    context.fillLibultraSymbols()
    context.fillHardwareRegs()
    contextReadVariablesCsv(context, args.game, args.version)
    contextReadFunctionsCsv(context, args.game, args.version)

    disassembleFile(args.version, args.file, args.game, args.outputfolder, context, int(args.vram, 16), int(args.text_end_offset, 16))

    if args.save_context is not None:
        head, tail = os.path.split(args.save_context)
        if head != "":
            os.makedirs(head, exist_ok=True)
        context.saveContextToFile(args.save_context)


if __name__ == "__main__":
    disassemblerMain()
