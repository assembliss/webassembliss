const ARCH_ID = "arm64_linux";
const ARCH_NUM_BITS = 64;

// Add registers we want to display to the register table.
const qilingARM64Registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
    "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
    "x26", "x27", "x28", "x29", "x30", "sp", "pc", "lr", "cpacr_el1", "tpidr_el0", "pstate", "cpsr"];
populateRegisterTable(qilingARM64Registers);

function createEditor(default_code) {
    BASE_createEditor(default_code, getARM64SyntaxHighlighting, getARM64HoverInfo)
}

function startTracing(combineAllSteps) {
    // Initialize all flags as false.
    document.getElementById("nFlag").innerHTML = ERROR_SYMBOL;
    document.getElementById("zFlag").innerHTML = ERROR_SYMBOL;
    document.getElementById("cFlag").innerHTML = ERROR_SYMBOL;
    document.getElementById("vFlag").innerHTML = ERROR_SYMBOL;
    BASE_startTracing(combineAllSteps);
}

function getARM64SyntaxHighlighting() {
    return {
        // First draft of an ARM64 assembly syntax.
        // Instructions taken from: https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions
        instructions: [
            "ABS", "abs", "ADC", "adc", "ADCS", "adcs", "add", "ADD", "ADDG", "addg", "ADDPT", "addpt", "adds", "ADDS", "ADR", "adr", "ADRP", "adrp", "AND", "and", "ands", "ANDS", "apas", "APAS", "ASR", "asr", "asrv", "ASRV", "at", "AT",
            "AUTDA", "autda", "AUTDB", "autdb", "AUTIA", "autia", "autia171615", "AUTIA171615", "AUTIASPPC", "autiasppc", "autiasppcr", "AUTIASPPCR", "autib", "AUTIB", "AUTIB171615", "autib171615", "AUTIBSPPC", "autibsppc", "autibsppcr", "AUTIBSPPCR", "axflag", "AXFLAG",
            "b", "B", "b.eq", "B.EQ", "b.ne", "B.NE", "b.mi", "B.MI", "b.pl", "B.PL", "b.gt", "B.GT", "b.ge", "B.GE", "b.lt", "B.LT", "b.le", "B.LE",
            "bc", "BC", "BFC", "bfc", "BFI", "bfi", "bfm", "BFM", "bfxil", "BFXIL", "bic", "BIC", "BICS", "bics", "bl", "BL", "BLR", "blr", "blraa", "BLRAA", "BR", "br", "BRAA", "braa", "BRB", "brb", "brk", "BRK", "bti", "BTI", "cas", "CAS", "CASB", "casb", "CASH", "cash",
            "CASP", "casp", "caspt", "CASPT", "cast", "CAST", "CB", "cb", "cbb", "CBB", "cbble", "CBBLE", "cbblo", "CBBLO", "CBBLS", "cbbls", "cbblt", "CBBLT", "CBGE", "cbge", "cbh", "CBH", "CBHLE", "cbhle", "CBHLO", "cbhlo", "cbhls", "CBHLS", "cbhlt", "CBHLT",
            "cbhs", "CBHS", "CBLE", "cble", "cblo", "CBLO", "cbls", "CBLS", "cblt", "CBLT", "cbnz", "CBNZ", "cbz", "CBZ", "ccmn", "CCMN", "ccmp", "CCMP", "cfinv", "CFINV", "cfp", "CFP", "chkfeat", "CHKFEAT", "CINC", "cinc", "CINV", "cinv", "clrbhb", "CLRBHB",
            "CLREX", "clrex", "cls", "CLS", "CLZ", "clz", "CMN", "cmn", "CMP", "cmp", "CMPP", "cmpp", "cneg", "CNEG", "CNT", "cnt", "COSP", "cosp", "cpp", "CPP", "cpyfp", "CPYFP", "cpyfpn", "CPYFPN", "cpyfprn", "CPYFPRN", "CPYFPRT", "cpyfprt", "cpyfprtn", "CPYFPRTN",
            "CPYFPRTRN", "cpyfprtrn", "CPYFPRTWN", "cpyfprtwn", "CPYFPT", "cpyfpt", "CPYFPTN", "cpyfptn", "cpyfptrn", "CPYFPTRN", "cpyfptwn", "CPYFPTWN", "cpyfpwn", "CPYFPWN", "cpyfpwt", "CPYFPWT", "cpyfpwtn", "CPYFPWTN", "CPYFPWTRN", "cpyfpwtrn", "CPYFPWTWN", "cpyfpwtwn", "CPYP", "cpyp", "cpypn", "CPYPN", "CPYPRN", "cpyprn", "CPYPRT", "cpyprt",
            "CPYPRTN", "cpyprtn", "CPYPRTRN", "cpyprtrn", "CPYPRTWN", "cpyprtwn", "cpypt", "CPYPT", "cpyptn", "CPYPTN", "cpyptrn", "CPYPTRN", "cpyptwn", "CPYPTWN", "cpypwn", "CPYPWN", "cpypwt", "CPYPWT", "CPYPWTN", "cpypwtn", "CPYPWTRN", "cpypwtrn", "CPYPWTWN", "cpypwtwn", "CRC32B", "crc32b", "CRC32CB", "crc32cb", "csdb", "CSDB",
            "csel", "CSEL", "cset", "CSET", "CSETM", "csetm", "csinc", "CSINC", "csinv", "CSINV", "CSNEG", "csneg", "ctz", "CTZ", "DC", "dc", "DCPS1", "dcps1", "dcps2", "DCPS2", "DCPS3", "dcps3", "DGH", "dgh", "dmb", "DMB", "DRPS", "drps", "DSB", "dsb",
            "dvp", "DVP", "eon", "EON", "EOR", "eor", "eret", "ERET", "eretaa", "ERETAA", "esb", "ESB", "EXTR", "extr", "GCSB", "gcsb", "gcspopcx", "GCSPOPCX", "GCSPOPM", "gcspopm", "GCSPOPX", "gcspopx", "GCSPUSHM", "gcspushm", "GCSPUSHX", "gcspushx", "GCSSS1", "gcsss1", "gcsss2", "GCSSS2",
            "GCSSTR", "gcsstr", "gcssttr", "GCSSTTR", "gmi", "GMI", "hint", "HINT", "hlt", "HLT", "HVC", "hvc", "ic", "IC", "irg", "IRG", "ISB", "isb", "LD64B", "ld64b", "LDADD", "ldadd", "ldaddb", "LDADDB", "ldaddh", "LDADDH", "LDAPR", "ldapr", "LDAPRB", "ldaprb",
            "ldaprh", "LDAPRH", "ldapur", "LDAPUR", "ldapurb", "LDAPURB", "ldapurh", "LDAPURH", "ldapursb", "LDAPURSB", "ldapursh", "LDAPURSH", "LDAPURSW", "ldapursw", "ldar", "LDAR", "LDARB", "ldarb", "LDARH", "ldarh", "LDATXR", "ldatxr", "ldaxp", "LDAXP", "ldaxr", "LDAXR", "LDAXRB", "ldaxrb", "ldaxrh", "LDAXRH",
            "LDCLR", "ldclr", "LDCLRB", "ldclrb", "LDCLRH", "ldclrh", "ldclrp", "LDCLRP", "ldeor", "LDEOR", "ldeorb", "LDEORB", "ldeorh", "LDEORH", "LDG", "ldg", "LDGM", "ldgm", "LDIAPP", "ldiapp", "ldlar", "LDLAR", "ldlarb", "LDLARB", "LDLARH", "ldlarh", "ldnp", "LDNP", "ldp", "LDP",
            "ldpsw", "LDPSW", "LDR", "ldr", "LDRAA", "ldraa", "ldrb", "LDRB", "ldrh", "LDRH", "ldrsb", "LDRSB", "ldrsh", "LDRSH", "ldrsw", "LDRSW", "ldset", "LDSET", "ldsetb", "LDSETB", "ldseth", "LDSETH", "ldsetp", "LDSETP", "LDSMAX", "ldsmax", "LDSMAXB", "ldsmaxb", "LDSMAXH", "ldsmaxh",
            "LDSMIN", "ldsmin", "ldsminb", "LDSMINB", "LDSMINH", "ldsminh", "LDTADD", "ldtadd", "ldtclr", "LDTCLR", "ldtnp", "LDTNP", "LDTP", "ldtp", "ldtr", "LDTR", "ldtrb", "LDTRB", "LDTRH", "ldtrh", "LDTRSB", "ldtrsb", "LDTRSH", "ldtrsh", "ldtrsw", "LDTRSW", "LDTSET", "ldtset", "LDTXR", "ldtxr",
            "ldumax", "LDUMAX", "LDUMAXB", "ldumaxb", "LDUMAXH", "ldumaxh", "LDUMIN", "ldumin", "lduminb", "LDUMINB", "lduminh", "LDUMINH", "LDUR", "ldur", "LDURB", "ldurb", "ldurh", "LDURH", "ldursb", "LDURSB", "ldursh", "LDURSH", "LDURSW", "ldursw", "LDXP", "ldxp", "ldxr", "LDXR", "ldxrb", "LDXRB",
            "ldxrh", "LDXRH", "LSL", "lsl", "lslv", "LSLV", "LSR", "lsr", "lsrv", "LSRV", "madd", "MADD", "maddpt", "MADDPT", "mneg", "MNEG", "MOV", "mov", "movk", "MOVK", "movn", "MOVN", "movz", "MOVZ", "MRRS", "mrrs", "MRS", "mrs", "msr", "MSR",
            "MSRR", "msrr", "MSUB", "msub", "MSUBPT", "msubpt", "mul", "MUL", "MVN", "mvn", "neg", "NEG", "NEGS", "negs", "NGC", "ngc", "ngcs", "NGCS", "nop", "NOP", "orn", "ORN", "orr", "ORR", "PACDA", "pacda", "pacdb", "PACDB", "PACGA", "pacga",
            "pacia", "PACIA", "PACIA171615", "pacia171615", "paciasppc", "PACIASPPC", "pacib", "PACIB", "PACIB171615", "pacib171615", "PACIBSPPC", "pacibsppc", "PACM", "pacm", "pacnbiasppc", "PACNBIASPPC", "pacnbibsppc", "PACNBIBSPPC", "prfm", "PRFM", "PRFUM", "prfum", "psb", "PSB", "PSSBB", "pssbb", "rbit", "RBIT", "RCWCAS", "rcwcas",
            "rcwcasp", "RCWCASP", "rcwclr", "RCWCLR", "rcwclrp", "RCWCLRP", "rcwscas", "RCWSCAS", "RCWSCASP", "rcwscasp", "RCWSCLR", "rcwsclr", "RCWSCLRP", "rcwsclrp", "RCWSET", "rcwset", "rcwsetp", "RCWSETP", "rcwsset", "RCWSSET", "RCWSSETP", "rcwssetp", "rcwsswp", "RCWSSWP", "rcwsswpp", "RCWSSWPP", "RCWSWP", "rcwswp", "RCWSWPP", "rcwswpp",
            "ret", "RET", "retaa", "RETAA", "RETAASPPC", "retaasppc", "RETAASPPCR", "retaasppcr", "rev", "REV", "rev16", "REV16", "rev32", "REV32", "REV64", "rev64", "RMIF", "rmif", "ROR", "ror", "rorv", "RORV", "RPRFM", "rprfm", "SB", "sb", "SBC", "sbc", "sbcs", "SBCS",
            "sbfiz", "SBFIZ", "SBFM", "sbfm", "sbfx", "SBFX", "sdiv", "SDIV", "SETF8", "setf8", "SETGP", "setgp", "SETGPN", "setgpn", "SETGPT", "setgpt", "setgptn", "SETGPTN", "setp", "SETP", "SETPN", "setpn", "SETPT", "setpt", "setptn", "SETPTN", "sev", "SEV", "sevl", "SEVL",
            "SMADDL", "smaddl", "SMAX", "smax", "smc", "SMC", "SMIN", "smin", "SMNEGL", "smnegl", "smstart", "SMSTART", "SMSTOP", "smstop", "SMSUBL", "smsubl", "SMULH", "smulh", "smull", "SMULL", "SSBB", "ssbb", "ST2G", "st2g", "st64b", "ST64B", "st64bv", "ST64BV", "st64bv0", "ST64BV0",
            "STADD", "stadd", "STADDB", "staddb", "STADDH", "staddh", "STCLR", "stclr", "STCLRB", "stclrb", "stclrh", "STCLRH", "steor", "STEOR", "steorb", "STEORB", "STEORH", "steorh", "stg", "STG", "stgm", "STGM", "stgp", "STGP", "stilp", "STILP", "stllr", "STLLR", "STLLRB", "stllrb",
            "stllrh", "STLLRH", "stlr", "STLR", "STLRB", "stlrb", "stlrh", "STLRH", "STLTXR", "stltxr", "STLUR", "stlur", "STLURB", "stlurb", "STLURH", "stlurh", "STLXP", "stlxp", "stlxr", "STLXR", "stlxrb", "STLXRB", "STLXRH", "stlxrh", "STNP", "stnp", "stp", "STP", "str", "STR",
            "STRB", "strb", "STRH", "strh", "STSET", "stset", "STSETB", "stsetb", "STSETH", "stseth", "stshh", "STSHH", "stsmax", "STSMAX", "stsmaxb", "STSMAXB", "stsmaxh", "STSMAXH", "stsmin", "STSMIN", "stsminb", "STSMINB", "stsminh", "STSMINH", "STTADD", "sttadd", "sttclr", "STTCLR", "STTNP", "sttnp",
            "STTP", "sttp", "sttr", "STTR", "sttrb", "STTRB", "sttrh", "STTRH", "STTSET", "sttset", "STTXR", "sttxr", "STUMAX", "stumax", "STUMAXB", "stumaxb", "stumaxh", "STUMAXH", "stumin", "STUMIN", "stuminb", "STUMINB", "stuminh", "STUMINH", "stur", "STUR", "sturb", "STURB", "sturh", "STURH",
            "stxp", "STXP", "STXR", "stxr", "STXRB", "stxrb", "stxrh", "STXRH", "stz2g", "STZ2G", "stzg", "STZG", "stzgm", "STZGM", "SUB", "sub", "SUBG", "subg", "SUBP", "subp", "subps", "SUBPS", "subpt", "SUBPT", "subs", "SUBS", "SVC", "svc", "SWP", "swp",
            "swpb", "SWPB", "swph", "SWPH", "swpp", "SWPP", "SWPT", "swpt", "sxtb", "SXTB", "SXTH", "sxth", "SXTW", "sxtw", "sys", "SYS", "sysl", "SYSL", "SYSP", "sysp", "tbnz", "TBNZ", "TBZ", "tbz", "tcancel", "TCANCEL", "tcommit", "TCOMMIT", "TLBI", "tlbi",
            "TLBIP", "tlbip", "trcit", "TRCIT", "TSB", "tsb", "TST", "tst", "tstart", "TSTART", "ttest", "TTEST", "ubfiz", "UBFIZ", "UBFM", "ubfm", "UBFX", "ubfx", "UDF", "udf", "UDIV", "udiv", "UMADDL", "umaddl", "umax", "UMAX", "UMIN", "umin", "UMNEGL", "umnegl",
            "umsubl", "UMSUBL", "UMULH", "umulh", "umull", "UMULL", "UXTB", "uxtb", "UXTH", "uxth", "WFE", "wfe", "WFET", "wfet", "wfi", "WFI", "wfit", "WFIT", "XAFLAG", "xaflag", "xpacd", "XPACD", "yield", "YIELD"
        ],

        // Registers taken from: https://github.com/qilingframework/qiling/blob/master/qiling/arch/arm64_const.py
        registers: [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
            "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
            "sp", "pc", "lr", "cpacr_el1", "tpidr_el0", "pstate",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
            "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23", "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
            "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
            "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15",
            "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23", "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
            "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
            "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
            "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
            "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
        ],

        // Directives taken from: https://developer.arm.com/documentation/den0013/d/Introduction-to-Assembly-Language/Introduction-to-the-GNU-Assembler/Assembler-directives
        directives: [
            ".align", ".ascii", ".asciz", ".byte", ".hword", ".word", ".data", ".end", ".equ", ".extern", ".global", ".include", ".quad", ".space", ".text", ".xword",
        ],

        // Operators, symbols, and escapes from default monarch example.
        operators: [
            '[', ']', '#', '!', '~', '?', ':', '==', '<=', '>=', '!=',
            '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^', '%',
            '<<', '>>', '>>>', '+=', '-=', '*=', '/=', '&=', '|=', '^=',
            '%=', '<<=', '>>=', '>>>='
        ],
        symbols: /[=><!~?:&|+\-*\/\^%]+\./,
        escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

        // The main tokenizer for our languages.
        tokenizer: {
            root: [
                // Instructions, directives, registers to color things differently.
                [/(\.)?[a-zA-Z_$][\w\.$]*(\d+)?/, {
                    cases: {
                        '@instructions': 'keyword',
                        '@directives': 'constant',
                        '@registers': 'number.hex',
                        '@default': 'identifier'
                    }
                }],
                // Numbers to handle possible negative and the leading # sign.
                [/(\#)?\d*\.\d+([eE][\-+]?\d+)?/, 'number'],
                [/(\#)?0[xX][0-9a-fA-F]+/, 'number'],
                [/(\#)?(-)?\d+/, 'number'],

                // Whitespace, delimiters, strings, characters from default monarch exammple.
                // whitespace
                { include: '@whitespace' },
                // delimiters and operators
                [/[{}()\[\]]/, '@brackets'],
                [/[<>](?!@symbols)/, '@brackets'],
                [/@symbols/, {
                    cases: {
                        '@operators': 'operator',
                        '@default': ''
                    }
                }],
                // delimiter: after number because of .\d floats
                [/[;,.]/, 'delimiter'],
                // strings
                [/"([^"\\]|\\.)*$/, 'string.invalid'],  // non-teminated string
                [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
                // characters
                [/'[^\\']'/, 'string'],
                [/(')(@escapes)(')/, ['string', 'string.escape', 'string']],
                [/'/, 'string.invalid']
            ],
            // Comments, strings, whitespace taken from default monarch example.
            comment: [
                [/[^\/*]+/, 'comment'],
                [/\/\*/, 'comment', '@push'],    // nested comment
                ["\\*/", 'comment', '@pop'],
                [/[\/*]/, 'comment']
            ],
            string: [
                [/[^\\"]+/, 'string'],
                [/@escapes/, 'string.escape'],
                [/\\./, 'string.escape.invalid'],
                [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
            ],
            whitespace: [
                [/[ \t\r\n]+/, 'white'],
                [/\/\*/, 'comment', '@comment'],
                [/\/\/.*$/, 'comment']
            ]
        }
    };
}

const ARM64HoverInfo = {
    // Initial information taken from Swarthmore's cheat sheet: https://www.cs.swarthmore.edu/~kwebb/cs31/resources/ARM64_Cheat_Sheet.pdf
    // TODO: add more instructions to this map.
    "mov": {
        "format": "mov D, S",
        "action": "D = S",
    },

    "ldr": {
        "format": "ldr D, [R]",
        "action": "D = Mem[R]",
    },

    "ldp": {
        "format": "ldp D1, D2, [R]",
        "action": "D1 = Mem[R] *and* D2 = Mem[R + 8]",
    },

    "str": {
        "format": "str S, [R]",
        "action": "Mem[R] = S",
    },

    "stp": {
        "format": "stp S1, S2, [R]",
        "action": "Mem[R] = S1 *and* Mem[R + 8] = S2",
    },

    "add": {
        "format": "add D, O1, O2",
        "action": "D = O1 + O2",
    },

    "sub": {
        "format": "sub D, O1, O2",
        "action": "D = O1 - O2",
    },

    "neg": {
        "format": "neg D, O1",
        "action": "D = -(O1)",
    },

    "mul": {
        "format": "mul D, O1, O2",
        "action": "D = O1 * O2",
    },

    "udiv": {
        "format": "udiv D, O1, O2",
        "action": "D = O1 / O2 (unsigned)",
    },

    "sdiv": {
        "format": "sdiv D, O1, O2",
        "action": "D = O1 / O2 (signed)",
    },

    "lsl": {
        "format": "lsl D, R, #v",
        "action": "D = R << v",
    },

    "lsr": {
        "format": "lsr D, R, #v",
        "action": "D = R >> v (logical)",
    },

    "asr": {
        "format": "asr D, R, #v",
        "action": "D = R >> v (arithmetic)",
    },

    "and": {
        "format": "and D, O1, O2",
        "action": "D = O1 & O2",
    },

    "orr": {
        "format": "orr D, O1, O2",
        "action": "D = O1 | O2",
    },

    "eor": {
        "format": "eor D, O1, O2",
        "action": "D = O1 ^ O2",
    },

    "mvn": {
        "format": "mvn D, O",
        "action": "D = ~O",
    },

    "cmp": {
        "format": "cmp O1, O2",
        "action": "Sets CCs: O1 - O2",
    },

    "tst": {
        "format": "tst O1, O2",
        "action": "Sets CCs: O1 & O2",
    },

    "br": {
        "format": "br address",
        "action": "PC = address",
    },

    "cbz": {
        "format": "cbz R, label",
        "action": "If R == 0, PC = addr of label",
    },

    "cbnz": {
        "format": "cbnz R, label",
        "action": "If R != 0, PC = addr of label",
    },

    "b": {
        "format": "b label",
        "action": "branch (PC = address of label)",
    },

    "b.eq": {
        "format": "b.eq label",
        "action": "branch if equal",
    },

    "b.ne": {
        "format": "b.ne label",
        "action": "branch if not equal",
    },

    "b.mi": {
        "format": "b.mi label",
        "action": "branch if negative",
    },

    "b.pl": {
        "format": "b.pl label",
        "action": "branch if non-negative",
    },

    "b.gt": {
        "format": "b.gt label",
        "action": "branch if greater than",
    },

    "b.ge": {
        "format": "b.ge label",
        "action": "branch if greater or equal",
    },

    "b.lt": {
        "format": "b.lt label branch",
        "action": "if less than",
    },

    "b.le": {
        "format": "b.le label branch",
        "action": "if less or equal",
    },

    "bl": {
        "format": "bl address <fname>",
        "action": "x30 = PC + 4 *and* PC = address",
    },

    "blr": {
        "format": "blr R <fname>",
        "action": "x30 = PC + 4 *and* PC = R",
    },

    "ret": {
        "format": "ret",
        "action": "PC = x30 *and* value of x0 returned",
    },

    "svc": {
        "format": "svc N",
        "action": "asks OS to perform syscall N",
    }

}

function isPossibleBranch(token) {
    const conditionalBranchInstructions = new Set(["b", "bc"]);
    return conditionalBranchInstructions.has(token);
}

function isPossibleCondition(token) {
    const conditionalBranchInstructions = new Set(["eq", "ne", "mi", "pl", "gt", "ge", "lt", "le"]);
    return conditionalBranchInstructions.has(token);
}

function isPossibleBranchOrCondition(token) {
    if (isPossibleBranch(token)) return 1;
    if (isPossibleCondition(token)) return 2;
    return 0;
}

function getToken(model, position) {
    // Get token from the hovering position and make it lowercase.
    let hover = model.getWordAtPosition(position);
    if (!hover) return hover;
    let token = hover.word.toLowerCase();
    let startCol = hover.startColumn;
    let endCol = hover.endColumn;
    let lineNum = position.lineNumber;

    // Check if it's a possible branch or condition position.
    let isBranchStatus = isPossibleBranchOrCondition(token);
    switch (isBranchStatus) {
        case 1:
            // If it's a branch instruction, we need to check if there's a condition attached to it.
            // First, check if there is a period after the instruction.
            let nextChar = model.getValueInRange(
                new monaco.Range(
                    position.lineNumber,
                    hover.endColumn,
                    position.lineNumber,
                    hover.endColumn + 1,
                )
            );
            if (nextChar != ".") {
                // No period, so possibly an unconditional jump (i.e., "b").
                break;
            }
            // If there is a period, parse the condition from after it.
            let cc = model.getWordAtPosition(
                new monaco.Position(
                    position.lineNumber,
                    hover.endColumn + 2,
                )
            );

            // Construct the full token.
            token += "." + cc.word;
            // Update end column.
            endCol = cc.endColumn;
            break;

        case 2:
            // If it's a condition, we need to move back and check the instruction before that.
            // First, check if there is a period before the condition.
            let prevChar = model.getValueInRange(
                new monaco.Range(
                    position.lineNumber,
                    hover.startColumn - 1,
                    position.lineNumber,
                    hover.startColumn,
                )
            );
            if (prevChar != ".") {
                // No period, it's not something in the form of b.CC.
                break;
            }
            // If there is a period, parse the instruction from before it.
            baseInstr = model.getWordUntilPosition(
                new monaco.Position(
                    position.lineNumber,
                    hover.startColumn - 1,
                )
            );

            // Construct the full token.
            token = baseInstr.word + "." + token;
            // Update start column.
            startCol = baseInstr.startColumn;
            break;

        default:
            // If it's neither, then we already have the correct token.
            break;
    }

    // Finally, return the token.
    return { token: token, startCol: startCol, endCol: endCol, lineNum: lineNum };
}

function getARM64HoverInfo(model, position) {
    let tokenInfo = getToken(model, position);
    if (!tokenInfo) return null;
    let instrInfo = ARM64HoverInfo[tokenInfo.token];

    if (!instrInfo) {
        return null;
    }

    return {
        range: new monaco.Range(
            tokenInfo.lineNum,
            tokenInfo.startCol,
            tokenInfo.lineNum,
            tokenInfo.endCol,
        ),
        contents: [
            {
                supportHtml: true,
                value: `<b>Format:</b> ${instrInfo.format}<hr/><b>Action(s):</b> ${instrInfo.action}`,
            }
        ]
    };

}
