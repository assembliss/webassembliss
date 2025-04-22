const ARCH_ID = "x8664_linux";
const ARCH_NUM_BITS = 64;

// Add registers we want to display to the register table.
const qilingX8664Registers = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
    "r10", "r11", "r12", "r13", "r14", "r15", "rip", "cs", "ss", "ds", "es", "fs", "gs", "eflags"];
populateRegisterTable(qilingX8664Registers);

function createEditor(default_code) {
    BASE_createEditor(default_code, getX8664SyntaxHighlighting)
}

function startTracing(combineAllSteps) {
    // Initialize all flags as false.
    document.getElementById("sfFlag").innerHTML = ERROR_SYMBOL;
    document.getElementById("zfFlag").innerHTML = ERROR_SYMBOL;
    document.getElementById("cfFlag").innerHTML = ERROR_SYMBOL;
    document.getElementById("ofFlag").innerHTML = ERROR_SYMBOL;
    BASE_startTracing(combineAllSteps);
}

function getX8664SyntaxHighlighting() {
    return {
        // First draft of a x86-64 assembly syntax.
        // Instructions taken from: http://ref.x86asm.net/coder64-abc.html
        instructions: [
            "adc", "ADC", "add", "ADD", "addpd", "ADDPD", "addps", "ADDPS", "addsd", "ADDSD", "addss", "ADDSS", "addsubpd", "ADDSUBPD", "addsubps", "ADDSUBPS", "and", "AND", "andnpd", "ANDNPD",
            "andnps", "ANDNPS", "andpd", "ANDPD", "andps", "ANDPS", "blendpd", "BLENDPD", "blendps", "BLENDPS", "bsf", "BSF", "bsr", "BSR", "bswap", "BSWAP", "bt", "BT", "btc", "BTC", "btr", "BTR",
            "bts", "BTS", "call", "CALL", "callf", "CALLF", "cbw", "CBW", "cdq", "CDQ", "cdqe", "CDQE", "clc", "CLC", "cld", "CLD", "clflush", "CLFLUSH", "cli", "CLI", "clts", "CLTS", "cmc", "CMC",
            "cmova", "CMOVA", "cmovae", "CMOVAE", "cmovb", "CMOVB", "cmovbe", "CMOVBE", "cmovc", "CMOVC", "cmove", "CMOVE", "cmovg", "CMOVG", "cmovge", "CMOVGE", "cmovl", "CMOVL", "cmovle", "CMOVLE",
            "cmovna", "CMOVNA", "cmovnae", "CMOVNAE", "cmovnb", "CMOVNB", "cmovnbe", "CMOVNBE", "cmovnc", "CMOVNC", "cmovne", "CMOVNE", "cmovng", "CMOVNG", "cmovnge", "CMOVNGE", "cmovnl", "CMOVNL",
            "cmovnle", "CMOVNLE", "cmovno", "CMOVNO", "cmovnp", "CMOVNP", "cmovns", "CMOVNS", "cmovnz", "CMOVNZ", "cmovo", "CMOVO", "cmovp", "CMOVP", "cmovpe", "CMOVPE", "cmovpo", "CMOVPO",
            "cmovs", "CMOVS", "cmovz", "CMOVZ", "cmp", "CMP", "cmppd", "CMPPD", "cmpps", "CMPPS", "cmps", "CMPS", "cmpsb", "CMPSB", "cmpsd", "CMPSD", "cmpsq", "CMPSQ", "cmpss", "CMPSS", "cmpsw", "CMPSW",
            "cmpxchg", "CMPXCHG", "cmpxchg16b", "CMPXCHG16B", "cmpxchg8b", "CMPXCHG8B", "comisd", "COMISD", "comiss", "COMISS", "cpuid", "CPUID", "cqo", "CQO", "crc32", "CRC32", "cvtdq2pd", "CVTDQ2PD",
            "cvtdq2ps", "CVTDQ2PS", "cvtpd2dq", "CVTPD2DQ", "cvtpd2pi", "CVTPD2PI", "cvtpd2ps", "CVTPD2PS", "cvtpi2pd", "CVTPI2PD", "cvtpi2ps", "CVTPI2PS", "cvtps2dq", "CVTPS2DQ", "cvtps2pd", "CVTPS2PD",
            "cvtps2pi", "CVTPS2PI", "cvtsd2si", "CVTSD2SI", "cvtsd2ss", "CVTSD2SS", "cvtsi2sd", "CVTSI2SD", "cvtsi2ss", "CVTSI2SS", "cvtss2sd", "CVTSS2SD", "cvtss2si", "CVTSS2SI", "cvttpd2dq", "CVTTPD2DQ",
            "cvttpd2pi", "CVTTPD2PI", "cvttps2dq", "CVTTPS2DQ", "cvttps2pi", "CVTTPS2PI", "cvttsd2si", "CVTTSD2SI", "cvttss2si", "CVTTSS2SI", "cwd", "CWD", "cwde", "CWDE", "dec", "DEC", "div", "DIV",
            "divpd", "DIVPD", "divps", "DIVPS", "divsd", "DIVSD", "divss", "DIVSS", "dppd", "DPPD", "dpps", "DPPS", "emms", "EMMS", "enter", "ENTER", "extractps", "EXTRACTPS", "f2xm1", "F2XM1", "fabs", "FABS",
            "fadd", "FADD", "faddp", "FADDP", "fbld", "FBLD", "fbstp", "FBSTP", "fchs", "FCHS", "fclex", "FCLEX", "fcmovb", "FCMOVB", "fcmovbe", "FCMOVBE", "fcmove", "FCMOVE", "fcmovnb", "FCMOVNB", "fcmovnbe", "FCMOVNBE",
            "fcmovne", "FCMOVNE", "fcmovnu", "FCMOVNU", "fcmovu", "FCMOVU", "fcom", "FCOM", "fcom2", "FCOM2", "fcomi", "FCOMI", "fcomip", "FCOMIP", "fcomp", "FCOMP", "fcomp3", "FCOMP3", "fcomp5", "FCOMP5", "fcompp", "FCOMPP",
            "fcos", "FCOS", "fdecstp", "FDECSTP", "fdiv", "FDIV", "fdivp", "FDIVP", "fdivr", "FDIVR", "fdivrp", "FDIVRP", "ffree", "FFREE", "ffreep", "FFREEP", "fiadd", "FIADD", "ficom", "FICOM", "ficomp", "FICOMP",
            "fidiv", "FIDIV", "fidivr", "FIDIVR", "fild", "FILD", "fimul", "FIMUL", "fincstp", "FINCSTP", "finit", "FINIT", "fist", "FIST", "fistp", "FISTP", "fisttp", "FISTTP", "fisub", "FISUB", "fisubr", "FISUBR",
            "fld", "FLD", "fld1", "FLD1", "fldcw", "FLDCW", "fldenv", "FLDENV", "fldl2e", "FLDL2E", "fldl2t", "FLDL2T", "fldlg2", "FLDLG2", "fldln2", "FLDLN2", "fldpi", "FLDPI", "fldz", "FLDZ", "fmul", "FMUL", "fmulp", "FMULP",
            "fnclex", "FNCLEX", "fndisi", "FNDISI", "fneni", "FNENI", "fninit", "FNINIT", "fnop", "FNOP", "fnsave", "FNSAVE", "fnsetpm", "FNSETPM", "fnstcw", "FNSTCW", "fnstenv", "FNSTENV", "fnstsw", "FNSTSW", "fpatan", "FPATAN",
            "fprem", "FPREM", "fprem1", "FPREM1", "fptan", "FPTAN", "frndint", "FRNDINT", "frstor", "FRSTOR", "fs", "FS", "fsave", "FSAVE", "fscale", "FSCALE", "fsin", "FSIN", "fsincos", "FSINCOS", "fsqrt", "FSQRT", "fst", "FST",
            "fstcw", "FSTCW", "fstenv", "FSTENV", "fstp", "FSTP", "fstp1", "FSTP1", "fstp8", "FSTP8", "fstp9", "FSTP9", "fstsw", "FSTSW", "fsub", "FSUB", "fsubp", "FSUBP", "fsubr", "FSUBR", "fsubrp", "FSUBRP", "ftst", "FTST",
            "fucom", "FUCOM", "fucomi", "FUCOMI", "fucomip", "FUCOMIP", "fucomp", "FUCOMP", "fucompp", "FUCOMPP", "fwait", "FWAIT", "fxam", "FXAM", "fxch", "FXCH", "fxch4", "FXCH4", "fxch7", "FXCH7", "fxrstor", "FXRSTOR",
            "fxsave", "FXSAVE", "fxtract", "FXTRACT", "fyl2x", "FYL2X", "fyl2xp1", "FYL2XP1", "getsec", "GETSEC", "gs", "GS", "haddpd", "HADDPD", "haddps", "HADDPS", "hint_nop", "HINT_NOP", "hlt", "HLT", "hsubpd", "HSUBPD",
            "hsubps", "HSUBPS", "icebp", "ICEBP", "idiv", "IDIV", "imul", "IMUL", "in", "IN", "inc", "INC", "ins", "INS", "insb", "INSB", "insd", "INSD", "insertps", "INSERTPS", "insw", "INSW", "int", "INT", "int1", "INT1",
            "into", "INTO", "invd", "INVD", "invept", "INVEPT", "invlpg", "INVLPG", "invvpid", "INVVPID", "iret", "IRET", "iretd", "IRETD", "iretq", "IRETQ", "ja", "JA", "jae", "JAE", "jb", "JB", "jbe", "JBE", "jc", "JC",
            "je", "JE", "jecxz", "JECXZ", "jg", "JG", "jge", "JGE", "jl", "JL", "jle", "JLE", "jmp", "JMP", "jmpf", "JMPF", "jna", "JNA", "jnae", "JNAE", "jnb", "JNB", "jnbe", "JNBE", "jnc", "JNC", "jne", "JNE", "jng", "JNG",
            "jnge", "JNGE", "jnl", "JNL", "jnle", "JNLE", "jno", "JNO", "jnp", "JNP", "jns", "JNS", "jnz", "JNZ", "jo", "JO", "jp", "JP", "jpe", "JPE", "jpo", "JPO", "jrcxz", "JRCXZ", "js", "JS", "jz", "JZ", "lahf", "LAHF",
            "lar", "LAR", "lddqu", "LDDQU", "ldmxcsr", "LDMXCSR", "lea", "LEA", "leave", "LEAVE", "lfence", "LFENCE", "lfs", "LFS", "lgdt", "LGDT", "lgs", "LGS", "lidt", "LIDT", "lldt", "LLDT", "lmsw", "LMSW", "lock", "LOCK",
            "lods", "LODS", "lodsb", "LODSB", "lodsd", "LODSD", "lodsq", "LODSQ", "lodsw", "LODSW", "loop", "LOOP", "loope", "LOOPE", "loopne", "LOOPNE", "loopnz", "LOOPNZ", "loopz", "LOOPZ", "lsl", "LSL", "lss", "LSS",
            "ltr", "LTR", "maskmovdqu", "MASKMOVDQU", "maskmovq", "MASKMOVQ", "maxpd", "MAXPD", "maxps", "MAXPS", "maxsd", "MAXSD", "maxss", "MAXSS", "mfence", "MFENCE", "minpd", "MINPD", "minps", "MINPS", "minsd", "MINSD",
            "minss", "MINSS", "monitor", "MONITOR", "mov", "MOV", "movapd", "MOVAPD", "movaps", "MOVAPS", "movbe", "MOVBE", "movd", "MOVD", "movddup", "MOVDDUP", "movdq2q", "MOVDQ2Q", "movdqa", "MOVDQA", "movdqu", "MOVDQU",
            "movhlps", "MOVHLPS", "movhpd", "MOVHPD", "movhps", "MOVHPS", "movlhps", "MOVLHPS", "movlpd", "MOVLPD", "movlps", "MOVLPS", "movmskpd", "MOVMSKPD", "movmskps", "MOVMSKPS", "movntdq", "MOVNTDQ", "movnti", "MOVNTI",
            "movntpd", "MOVNTPD", "movntps", "MOVNTPS", "movntq", "MOVNTQ", "movq", "MOVQ", "movq2dq", "MOVQ2DQ", "movs", "MOVS", "movsb", "MOVSB", "movsd", "MOVSD", "movshdup", "MOVSHDUP", "movsldup", "MOVSLDUP", "movsq", "MOVSQ",
            "movss", "MOVSS", "movsw", "MOVSW", "movsx", "MOVSX", "movsxd", "MOVSXD", "movupd", "MOVUPD", "movups", "MOVUPS", "movzx", "MOVZX", "mpsadbw", "MPSADBW", "mul", "MUL", "mulpd", "MULPD", "mulps", "MULPS", "mulsd", "MULSD",
            "mulss", "MULSS", "mwait", "MWAIT", "neg", "NEG", "nop", "NOP", "not", "NOT", "or", "OR", "orpd", "ORPD", "orps", "ORPS", "out", "OUT", "outs", "OUTS", "outsb", "OUTSB", "outsd", "OUTSD", "outsw", "OUTSW",
            "packssdw", "PACKSSDW", "packsswb", "PACKSSWB", "packuswb", "PACKUSWB", "paddb", "PADDB", "paddd", "PADDD", "paddq", "PADDQ", "paddsb", "PADDSB", "paddsw", "PADDSW", "paddusb", "PADDUSB", "paddusw", "PADDUSW",
            "paddw", "PADDW", "palignr", "PALIGNR", "pand", "PAND", "pandn", "PANDN", "pause", "PAUSE", "pavgb", "PAVGB", "pavgw", "PAVGW", "pblendw", "PBLENDW", "pcmpeqb", "PCMPEQB", "pcmpeqd", "PCMPEQD", "pcmpeqw", "PCMPEQW",
            "pcmpestri", "PCMPESTRI", "pcmpestrm", "PCMPESTRM", "pcmpgtb", "PCMPGTB", "pcmpgtd", "PCMPGTD", "pcmpgtw", "PCMPGTW", "pcmpistri", "PCMPISTRI", "pcmpistrm", "PCMPISTRM", "pextrb", "PEXTRB", "pextrd", "PEXTRD",
            "pextrq", "PEXTRQ", "pextrw", "PEXTRW", "pinsrb", "PINSRB", "pinsrd", "PINSRD", "pinsrq", "PINSRQ", "pinsrw", "PINSRW", "pmaddwd", "PMADDWD", "pmaxsw", "PMAXSW", "pmaxub", "PMAXUB", "pminsw", "PMINSW", "pminub", "PMINUB",
            "pmovmskb", "PMOVMSKB", "pmulhuw", "PMULHUW", "pmulhw", "PMULHW", "pmullw", "PMULLW", "pmuludq", "PMULUDQ", "pop", "POP", "popcnt", "POPCNT", "popf", "POPF", "popfq", "POPFQ", "por", "POR", "prefetchnta", "PREFETCHNTA",
            "prefetcht0", "PREFETCHT0", "prefetcht1", "PREFETCHT1", "prefetcht2", "PREFETCHT2", "psadbw", "PSADBW", "pshufd", "PSHUFD", "pshufhw", "PSHUFHW", "pshuflw", "PSHUFLW", "pshufw", "PSHUFW", "pslld", "PSLLD", "pslldq", "PSLLDQ",
            "psllq", "PSLLQ", "psllw", "PSLLW", "psrad", "PSRAD", "psraw", "PSRAW", "psrld", "PSRLD", "psrldq", "PSRLDQ", "psrlq", "PSRLQ", "psrlw", "PSRLW", "psubb", "PSUBB", "psubd", "PSUBD", "psubq", "PSUBQ", "psubsb", "PSUBSB",
            "psubsw", "PSUBSW", "psubusb", "PSUBUSB", "psubusw", "PSUBUSW", "psubw", "PSUBW", "punpckhbw", "PUNPCKHBW", "punpckhdq", "PUNPCKHDQ", "punpckhqdq", "PUNPCKHQDQ", "punpckhwd", "PUNPCKHWD", "punpcklbw", "PUNPCKLBW",
            "punpckldq", "PUNPCKLDQ", "punpcklqdq", "PUNPCKLQDQ", "punpcklwd", "PUNPCKLWD", "push", "PUSH", "pushf", "PUSHF", "pushfq", "PUSHFQ", "pxor", "PXOR", "rcl", "RCL", "rcpps", "RCPPS", "rcpss", "RCPSS", "rcr", "RCR",
            "rdmsr", "RDMSR", "rdpmc", "RDPMC", "rdtsc", "RDTSC", "rdtscp", "RDTSCP", "rep", "REP", "repe", "REPE", "repne", "REPNE", "repnz", "REPNZ", "repz", "REPZ", "retf", "RETF", "retn", "RETN", "rex", "REX", "rol", "ROL",
            "ror", "ROR", "roundpd", "ROUNDPD", "roundps", "ROUNDPS", "roundsd", "ROUNDSD", "roundss", "ROUNDSS", "rsm", "RSM", "rsqrtps", "RSQRTPS", "rsqrtss", "RSQRTSS", "sahf", "SAHF", "sal", "SAL", "sar", "SAR", "sbb", "SBB",
            "scas", "SCAS", "scasb", "SCASB", "scasd", "SCASD", "scasq", "SCASQ", "scasw", "SCASW", "seta", "SETA", "setae", "SETAE", "setb", "SETB", "setbe", "SETBE", "setc", "SETC", "sete", "SETE", "setg", "SETG", "setge", "SETGE",
            "setl", "SETL", "setle", "SETLE", "setna", "SETNA", "setnae", "SETNAE", "setnb", "SETNB", "setnbe", "SETNBE", "setnc", "SETNC", "setne", "SETNE", "setng", "SETNG", "setnge", "SETNGE", "setnl", "SETNL", "setnle", "SETNLE",
            "setno", "SETNO", "setnp", "SETNP", "setns", "SETNS", "setnz", "SETNZ", "seto", "SETO", "setp", "SETP", "setpe", "SETPE", "setpo", "SETPO", "sets", "SETS", "setz", "SETZ", "sfence", "SFENCE", "sgdt", "SGDT", "shl", "SHL",
            "shld", "SHLD", "shr", "SHR", "shrd", "SHRD", "shufpd", "SHUFPD", "shufps", "SHUFPS", "sidt", "SIDT", "sldt", "SLDT", "smsw", "SMSW", "sqrtpd", "SQRTPD", "sqrtps", "SQRTPS", "sqrtsd", "SQRTSD", "sqrtss", "SQRTSS", "stc",
            "STC", "std", "STD", "sti", "STI", "stmxcsr", "STMXCSR", "stos", "STOS", "stosb", "STOSB", "stosd", "STOSD", "stosq", "STOSQ", "stosw", "STOSW", "str", "STR", "sub", "SUB", "subpd", "SUBPD", "subps", "SUBPS", "subsd", "SUBSD",
            "subss", "SUBSS", "swapgs", "SWAPGS", "syscall", "SYSCALL", "sysenter", "SYSENTER", "sysexit", "SYSEXIT", "sysret", "SYSRET", "test", "TEST", "ucomisd", "UCOMISD", "ucomiss", "UCOMISS", "ud", "UD", "ud2", "UD2",
            "unpckhpd", "UNPCKHPD", "unpckhps", "UNPCKHPS", "unpcklpd", "UNPCKLPD", "unpcklps", "UNPCKLPS", "verr", "VERR", "verw", "VERW", "vmcall", "VMCALL", "vmclear", "VMCLEAR", "vmlaunch", "VMLAUNCH", "vmptrld", "VMPTRLD",
            "vmptrst", "VMPTRST", "vmread", "VMREAD", "vmresume", "VMRESUME", "vmwrite", "VMWRITE", "vmxoff", "VMXOFF", "vmxon", "VMXON", "wait", "WAIT", "wbinvd", "WBINVD", "wrmsr", "WRMSR", "xadd", "XADD", "xchg", "XCHG",
            "xgetbv", "XGETBV", "xlat", "XLAT", "xlatb", "XLATB", "xor", "XOR", "xorpd", "XORPD", "xorps", "XORPS", "xrstor", "XRSTOR", "xsave", "XSAVE", "xsetbv", "XSETBV",
        ],

        // Registers taken from: https://web.stanford.edu/class/cs107/resources/x86-64-reference.pdf
        registers: [
            "rax", "eax", "ax", "al", "rbx", "ebx", "bx", "bl", "rcx", "ecx", "cx", "cl", "rdx", "edx", "dx", "dl",
            "rsi", "esi", "si", "sil", "rdi", "edi", "di", "dil", "rbp", "ebp", "bp", "bpl", "rsp", "esp", "sp", "spl",
            "r8", "r8d", "r8w", "r8b", "r9", "r9d", "r9w", "r9b", "r10", "r10d", "r10w", "r10b", "r11", "r11d", "r11w", "r11b",
            "r12", "r12d", "r12w", "r12b", "r13", "r13d", "r13w", "r13b", "r14", "r14d", "r14w", "r14b", "r15", "r15d", "r15w", "r15b",
        ],

        // Directives taken from: https://sourceware.org/binutils/docs/as/Pseudo-Ops.html
        directives: [
            ".abort", ".ABORT", ".align", ".altmacro", ".ascii", ".asciz", ".attach_to_group", ".balign", ".base64", ".bss", ".byte", ".comm",
            ".data", ".dc", ".dcb", ".ds", ".def", ".desc", ".dim", ".double", ".eject", ".else", ".elseif", ".end", ".endef", ".endfunc", ".endif",
            ".equ", ".equiv", ".eqv", ".err", ".error", ".exitm", ".extern", ".fail", ".file", ".fill", ".float", ".func", ".global", ".globl", ".gnu_attribute",
            ".hidden", ".hword", ".ident", ".if", ".incbin", ".include", ".int", ".internal", ".irp", ".irpc", ".lcomm", ".lflags", ".line", ".linkonce",
            ".list", ".ln", ".loc", ".loc_mark_labels", ".local", ".long", ".macro", ".mri", ".noaltmacro", ".nolist", ".nop", ".nops", ".octa", ".offset",
            ".org", ".p2align", ".popsection", ".previous", ".print", ".protected", ".psize", ".purgem", ".pushsection", ".quad", ".reloc", ".rept", ".sbttl",
            ".scl", ".section", ".set", ".short", ".single", ".size", ".skip", ".sleb128", ".space", ".stabd", ".string", ".struct", ".subsection", ".symver",
            ".tag", ".text", ".title", ".tls_common", ".type", ".uleb128", ".val", ".version", ".vtable_entry", ".vtable_inherit", ".warning", ".weak",
            ".weakref", ".word", ".zero", ".2byte", ".4byte", ".8byte",
        ],

        // Operators, symbols, and escapes from default monarch example.
        operators: [
            '[', ']', '#', '!', '~', '?', ':', '==', '<=', '>=', '!=',
            '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^',
            '<<', '>>', '>>>', '+=', '-=', '*=', '/=', '&=', '|=', '^=', '<<=', '>>=', '>>>='
        ],
        symbols: /[=><!~?:&|+\-*\/\^]+\./,
        escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

        // The main tokenizer for our languages.
        tokenizer: {
            root: [
                // Instructions, directives, registers to color things differently.
                [/(\.)?[a-zA-Z_][\w$]*(\d+)?/, {
                    cases: {
                        '@instructions': 'keyword',
                        '@directives': 'constant',
                        '@registers': 'number.hex',
                        '@default': 'identifier'
                    }
                }],
                // Numbers to handle possible negative and the leading # sign.
                [/(\$)?\d*\.\d+([eE][\-+]?\d+)?/, 'number'],
                [/(\$)?0[xX][0-9a-fA-F]+/, 'number'],
                [/(\$)?(-)?\d+/, 'number'],

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
                [/\#.*$/, 'comment'],
            ]
        }
    };
}
