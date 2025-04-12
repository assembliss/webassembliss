const ARCH_ID = "riscv64_linux";

function createEditor(default_code) {
    BASE_createEditor(default_code, ARCH_ID, getRISCVSyntaxHighlighting)
}

function runCode() {
    BASE_runCode(ARCH_ID);
}

function startTracing() {
    BASE_startTracing(ARCH_ID);
}

function getRISCVSyntaxHighlighting() {
    return {
        // First draft of a RISC-V 64 assembly syntax.
        instructions: [
            // Instructions taken from: https://marks.page/riscv/
            "ADD", "add", "ADDI", "addi", "ADDIW", "addiw", "ADDW", "addw", "AND", "and",
            "ANDI", "andi", "AUIPC", "auipc", "BEQ", "beq", "BGE", "bge", "BGEU", "bgeu",
            "BLT", "blt", "BLTU", "bltu", "BNE", "bne", "DIV", "div", "DIVU", "divu",
            "DIVUW", "divuw", "DIVW", "divw", "FENCE", "fence", "FENCE.I", "fence.i", "JAL", "jal",
            "JALR", "jalr", "LB", "lb", "LBU", "lbu", "LD", "ld", "LH", "lh", "LHU", "lhu",
            "LUI", "lui", "LW", "lw", "LWU", "lwu", "MUL", "mul", "MULH", "mulh", "MULHSU", "mulhsu",
            "MULHU", "mulhu", "MULW", "mulw", "OR", "or", "ORI", "ori", "REM", "rem", "REMU", "remu",
            "REMUW", "remuw", "REMW", "remw", "SB", "sb", "SD", "sd", "SH", "sh", "SLL", "sll",
            "SLLI", "slli", "SLLI", "slli", "SLLIW", "slliw", "SLLW", "sllw", "SLT", "slt",
            "SLTI", "slti", "SLTIU", "sltiu", "SLTU", "sltu", "SRA", "sra", "SRAI", "srai",
            "SRAI", "srai", "SRAIW", "sraiw", "SRAW", "sraw", "SRL", "srl", "SRLI", "srli",
            "SRLI", "srli", "SRLIW", "srliw", "SRLW", "srlw", "SUB", "sub", "SUBW", "subw",
            "SW", "sw", "XOR", "xor", "XORI", "xori",
            // Pseudo-instructions taken from: https://marks.page/riscv/asm
            "BEQZ", "beqz", "BGEZ", "bgez", "BGT", "bgt", "BGTU", "bgtu", "BGTZ", "bgtz",
            "BLE", "ble", "BLEU", "bleu", "BLEZ", "blez", "BLTZ", "bltz", "BNEZ", "bnez",
            "FABS.D", "fabs.d", "FABS.S", "fabs.s", "FMV.D", "fmv.d", "FMV.S", "fmv.s",
            "FNEG.D", "fneg.d", "FNEG.S", "fneg.s", "J", "j", "JR", "jr", "LA", "la",
            "LI", "li", "MV", "mv", "NEG", "neg", "NEGW", "negw", "NOP", "nop", "NOT", "not",
            "RET", "ret", "SEQZ", "seqz", "SEXT.W", "sext.w", "SGTZ", "sgtz", "SLTZ", "sltz",
            "SNEZ", "snez",
            // Syscall
            "ECALL", "ecall"
        ],

        // Registers taken from: https://github.com/qilingframework/qiling/blob/master/qiling/arch/riscv_const.py
        registers: [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "fp",
            "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
            "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5",
            "t6", "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0",
            "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2",
            "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11", "ft8",
            "ft9", "ft10", "ft11", "pc", "x0", "x1", "x2", "x3", "x4", "x5", "x6",
            "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
            "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
            "x29", "x30", "x31"
        ],

        // Directives taken from: https://marks.page/riscv/asm
        directives: [
            ".text", ".data", ".rodata", ".bss", ".2byte", ".4byte", ".8byte", ".half", ".word",
            ".dword", ".byte", ".dtpreldword", ".dtprelword", ".sleb128", ".uleb128", ".asciz",
            ".string", ".incbin", ".zero", ".align", ".balign", ".p2align", ".globl", ".local",
            ".equ", ".text", ".data", ".rodata", ".bss", ".comm", ".common", ".section", ".option",
            ".macro", ".endm", ".file", ".ident", ".size", ".type", ".ascii", ".global"
        ],

        // Operators, symbols, and escapes from default monarch example.
        operators: [
            '[', ']', '!', '~', '?', ':', '==', '<=', '>=', '!=',
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
                [/(\.)?[a-zA-Z_$][\w$]*(\d+)?/, {
                    cases: {
                        '@instructions': 'keyword',
                        '@directives': 'constant',
                        '@registers': 'number.hex',
                        '@default': 'identifier'
                    }
                }],
                // Numbers to handle possible negative.
                [/\d*\.\d+([eE][\-+]?\d+)?/, 'number'],
                [/0[xX][0-9a-fA-F]+/, 'number'],
                [/(-)?\d+/, 'number'],

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
                [/\#.*$/, 'comment'],
            ],
            string: [
                [/[^\\"]+/, 'string'],
                [/@escapes/, 'string.escape'],
                [/\\./, 'string.escape.invalid'],
                [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
            ],
            whitespace: [
                [/[ \t\r\n]+/, 'white'],
                [/\#.*$/, 'comment']
            ]
        }
    };
}
