var dosHeader = struct({
    Magic: struct({
        Byte0: char(),
        Byte1: char()
    }),
    CBLP: uint16(),
    CP: uint16(),
    crlc: uint16(),
    cparhdr: uint16(),
    minalloc: uint16(),
    maxalloc: uint16(),
    ss: uint16(),
    sp: uint16(),
    csum: uint16(),
    ip: uint16(),
    cs: uint16(),
    lfarlc: uint16(),
    ovno: uint16(),
    res_1: array(uint16(), 4),
    oemid: uint16(),
    oeminfo: uint16(),
    res_2: array(uint16(), 10),
    lfanew: uint32()
}).setValidation(validateDosHeader);

var machine_type = {
    UNKNOWN: 0,
    AM33: 467,
    AMD64: 34404,
    ARM: 448,
    ARMV7: 452,
    EBC: 3772,
    I386: 332,
    IA64: 512,
    M32R: 36929,
    MIPS16: 614,
    MIPSFPU: 870,
    MIPSFPU16: 1126,
    POWERPC: 496,
    POWERPCCFP: 497,
    R4000: 358,
    SH3: 418,
    SH3DSP: 419,
    SH4: 422,
    SH5: 424,
    THUMB: 450,
    WCEMIPSV2: 361
};

var peHeader = struct({
    Magic: struct({
        Byte0: char(),
        Byte1: char(),
        Byte2: char(),
        Byte3: char()
    }),
    Machine: enumeration("MachineType", uint16(), machine_type),
    NumSections: uint16(),
    TimeDate: uint32(),
    SymbolTableAddress: uint32(),
    NumSymbols: uint32(),
    OptionalHeaderSize: uint16(),
    Characteristics: struct({
        BaseRelocationsStripped: bitfield("bool", 1).set({name: "Base relocations stripped"}),
        ExecutableImage: bitfield("bool", 1).set({name: "Executable image"}),
        LineNumbersStripped: bitfield("bool", 1).set({name: "Line numbers stripped"}),
        SymbolsStripped: bitfield("bool", 1).set({name: "Symbols stripped"}),
        AggressivelyTrim: bitfield("bool", 1).set({name: "Aggressively trim"}),
        LargeAddressSpace: bitfield("bool", 1).set({name: ">2GB address space"}),
        Reserved: bitfield("bool", 1).set({name: "Reserved"}),
        LittleEndian: bitfield("bool", 1).set({name: "Little endian"}),
        ThirtyTwoBit: bitfield("bool", 1).set({name: "32-bit"}),
        DebuggingInfoStripped: bitfield("bool", 1).set({name: "Debugging information stripped"}),
        SwapRemovableMedia: bitfield("bool", 1).set({name: "Copy to swap from removable media"}),
        SwapNetworkMedia: bitfield("bool", 1).set({name: "Copy to swap from network media"}),
        SystemFile: bitfield("bool", 1).set({name: "System file"}),
        DLLImage: bitfield("bool", 1).set({name: "DLL image"}),
        UniprocessorMachine: bitfield("bool", 1).set({name: "Uniprocessor machine"}),
        BigEndian: bitfield("bool", 1).set({name: "Big endian"}),
    })
}).setValidation(validatePeHeader);

var optionalHeader = struct({
    Magic: struct({Byte0: char(), Byte1: char()}),
    MajorLinkerVersion: uint8(),
    MinorLinkerVersion: uint8(),
    SizeOfCode: uint32().set({name: "Size of all sections"}),
    SizeOfInitializedData: uint32(),
    SizeOfUninitializedData: uint32(),
    AddressOfEntryPointRVA: uint32(),
    BaseOfCodeRVA: uint32(),
    BaseOfDataRVA: uint32(),
}).setValidation(validateOptionalHeader);

var optionalHeaderWin32 = struct({
    ImageBase: uint32(),
    SectionAlignment: uint32(),
    FileAlignment: uint32(),
    MajorOSVersion: uint16(),
    MinorOSVersion: uint16(),
    MajorImageVersion: uint16(),
    MinorImageVersion: uint16(),
    MajorSubsystemVersion: uint16(),
    MinorSubsystemVersion: uint16(),
    Win32VersionValue: uint32(),
    SizeOfImage: uint32(),
    SizeOfHeaders: uint32(),
    Checksum: uint32(),
    Subsystem: uint16(),
    DLLCharacteristics: uint16(),
    SizeOfStackReserve: uint32(),
    SizeOfStackCommit: uint32(),
    SizeOfHeapReserve: uint32(),
    SizeOfHeapCommit: uint32(),
    LoaderFlags: uint32(),
    NumberOfDataDirectories: uint32()
});

var directoryEntry = struct({
    RVA: uint32(),
    Size: uint32()
});

var sectionEntry = struct({
    Name: array(char(), 8).set({
        toStringFunc: function () {
            return this[0].value.toString(16) +
                this[1].value.toString(16) +
                this[2].value.toString(16) +
                this[3].value.toString(16) +
                this[4].value.toString(16) +
                this[5].value.toString(16) +
                this[6].value.toString(16) +
                this[7].value.toString(16);
        }
    }),
    VirtualSize: uint32(),
    VirtualAddressRVA: uint32(),
    SizeOfRawData: uint32(),
    PointerToRawData: uint32(),
    PointerToRelocations: uint32(),
    PointerToLineNumbers: uint32(),
    NumberOfRelocations: uint16(),
    NumberOfLineNumbers: uint16(),
    Characteristics: uint32()
}).set({
    toStringFunc: function() {
        return this.Name.toStringFunc();
    }
});

function getMethods(obj) {
    var result = [];
    for (var id in obj) {
        try {
            if (typeof (obj[id]) == "function") {
                result.push(id + "()");
            } else {
                result.push(id);
            }
        } catch (err) {
            result.push(id + ": inaccessible");
        }
    }
    return result;
}

function validateDosHeader(root) {
    var ret = true;
    var magic = this.Magic;
    if (magic.Byte0.uint8 != 0x4D) {
        magic.Byte0.validationError = "Must == 0x4D";
        ret = false;
    }
    if (magic.Byte1.uint8 != 0x5A) {
        magic.Byte1.validationError = "Must == 0x5A";
        ret = false;
    }

    return ret;
}

function validatePeHeader() {
    var ret = true;
    var magic = this["Magic"];

    if (magic.Byte0.uint8 != 0x50) {
        magic.Byte0.validationError = "Must == 0x50";
        ret = false;
    }
    if (magic.Byte1.uint8 != 0x45) {
        magic.Byte1.validationError = "Must == 0x45";
        ret = false;
    }
    if (magic.Byte2.uint8 != 0x00) {
        magic.Byte2.validationError = "Must == 0x00";
        ret = false;
    }
    if (magic.Byte3.uint8 != 0x00) {
        magic.Byte3.validationError = "Must == 0x00";
        ret = false;
    }

    return ret;
}

function validateOptionalHeader(root) {
    var ret = true;
    var magic = this.Magic;

    // TODO: Support PE32+ as well as PE32
    if (magic.Byte0.uint8 != 0x0B) {
        magic.Byte0.validationError = "Must == 0x0B";
        ret = false;
    }
    if (magic.Byte1.uint8 != 0x01) {
        magic.Byte1.validationError = "Must == 0x01";
        ret = false;
    }

    return ret;
}

function init() {
    const SIZEOF_DOS_HEADER = 0x40;
    var dosStub = array(char(),
        function (root) {
            var peFileOffset = root.DOSHeader.lfanew.value;
            if (peFileOffset >= SIZEOF_DOS_HEADER) {
                return peFileOffset - SIZEOF_DOS_HEADER;
            }
            return 0;
        });


    var header = struct({
        DOSHeader: dosHeader,
        DOSStub: dosStub,
        PEHeader: peHeader,
        OptionalHeaders: taggedUnion(
            {
                Header: optionalHeader
            },
            [
                alternative(
                    isOptionalPE32,
                    {
                        Data: optionalHeaderWin32,
                        Directories: array(directoryEntry, getNumberOfDataDirectories)
                    })
            ],
            {
                invalid: array(char(), 0)
            }
        ),
        SectionHeaders: array(sectionEntry, getNumberOfSectionHeaders)
    });

    return header;
}


function isOptionalPE32(root) {
    var optionalHeaderMagic = root.OptionalHeaders.Header.Magic;
    return optionalHeaderMagic.Byte0.uint8 == 0x0B && optionalHeaderMagic.Byte1.uint8 == 0x01;
}


function getNumberOfDataDirectories(root) {
    var pe32Header = root.OptionalHeaders.Data;
    return pe32Header.NumberOfDataDirectories.uint32;
}

function getNumberOfSectionHeaders(root) {
    var peHeader = root.PEHeader;
    return peHeader.NumSections.uint16;
}