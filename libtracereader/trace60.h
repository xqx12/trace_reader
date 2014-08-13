/* 
 *  definitions for v60 execution traces
 *
 *  Copyright (C) 2013 Juan Caballero <juan.caballero@imdea.org>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _TRACE60_H_
#define _TRACE60_H_

/** @file */

#include <inttypes.h>

/* segment registers */
#define es_reg 100
#define cs_reg 101
#define ss_reg 102
#define ds_reg 103
#define fs_reg 104
#define gs_reg 105

/* address-modifier dependent registers */
#define eAX_reg 108
#define eCX_reg 109
#define eDX_reg 110
#define eBX_reg 111
#define eSP_reg 112
#define eBP_reg 113
#define eSI_reg 114
#define eDI_reg 115

/* 8-bit registers */
#define al_reg 116
#define cl_reg 117
#define dl_reg 118
#define bl_reg 119
#define ah_reg 120
#define ch_reg 121
#define dh_reg 122
#define bh_reg 123

/* 16-bit registers */
#define ax_reg 124
#define cx_reg 125
#define dx_reg 126
#define bx_reg 127
#define sp_reg 128
#define bp_reg 129
#define si_reg 130
#define di_reg 131

/* 32-bit registers */
#define eax_reg 132
#define ecx_reg 133
#define edx_reg 134
#define ebx_reg 135
#define esp_reg 136
#define ebp_reg 137
#define esi_reg 138
#define edi_reg 139

/* 32-bit EFLAGS register */
#define eflags_reg 145

/* 64-bit MMX registers */
#define mm0_reg 164
#define mm1_reg 165
#define mm2_reg 166
#define mm3_reg 167
#define mm4_reg 168
#define mm5_reg 169
#define mm6_reg 170
#define mm7_reg 171

/* 128-bit XMM registers */
#define xmm0_reg 172
#define xmm1_reg 173
#define xmm2_reg 174
#define xmm3_reg 175
#define xmm4_reg 176
#define xmm5_reg 177
#define xmm6_reg 178
#define xmm7_reg 179
#define xmm8_reg 180
#define xmm9_reg 181
#define xmm10_reg 182
#define xmm11_reg 183
#define xmm12_reg 184
#define xmm13_reg 185
#define xmm14_reg 186
#define xmm15_reg 187

/* 80-bit float registers */
#define st0_reg 188
#define st1_reg 189
#define st2_reg 190
#define st3_reg 191
#define st4_reg 192
#define st5_reg 193
#define st6_reg 194
#define st7_reg 195

/* 16-bit float control registers */
#define fpuc_reg 196
#define fpus_reg 197
#define fputag_reg 198


/* Size of buffer to store instructions */
#define FILEBUFSIZE 104857600

/* Trace header values */
#define VERSION_NUMBER 60
#define MAGIC_NUMBER 0xFFFFFFFF
#define TRAILER_BEGIN 0xFFFFFFFF
#define TRAILER_END 0x41AA42BB

/* Taint origins */
#define TAINT_SOURCE_NIC_IN 0
#define TAINT_SOURCE_KEYBOARD_IN 1
#define TAINT_SOURCE_FILE_IN 2
#define TAINT_SOURCE_NETWORK_OUT 3
#define TAINT_SOURCE_API_TIME_IN 4
#define TAINT_SOURCE_API_FILE_IN 5
#define TAINT_SOURCE_API_REGISTRY_IN 6
#define TAINT_SOURCE_API_HOSTNAME_IN 7
#define TAINT_SOURCE_API_FILE_INFO_IN 8
#define TAINT_SOURCE_API_SOCK_INFO_IN 9
#define TAINT_SOURCE_API_STR_IN 10
#define TAINT_SOURCE_API_SYS_IN 11
#define TAINT_SOURCE_HOOKAPI 12
#define TAINT_SOURCE_LOOP_IV 13
#define TAINT_SOURCE_MODULE 14

/* Starting origin for network connections */
#define TAINT_ORIGIN_START_TCP_NIC_IN 10000
#define TAINT_ORIGIN_START_UDP_NIC_IN 11000
#define TAINT_ORIGIN_MODULE           20000

/* Taint propagation definitions */
#define TP_NONE 0           // No taint propagation
#define TP_SRC 1            // Taint propagated from SRC to DST
#define TP_CJMP 2           // Cjmp using tainted EFLAG
#define TP_MEMREAD_INDEX 3  // Memory read with tainted index
#define TP_MEMWRITE_INDEX 4 // Memory write with tainted index
#define TP_REP_COUNTER 5    // Instruction with REP prefix and tainted counter
#define TP_SYSENTER 6       // Sysenter

/*
 * Macro that specifies the maxium number of operands an instruction can have
 * It supports FNSAVE which has a memory operand of 108 bytes
 * (broken into 4-byte consecutive memory operands)
 * FXSAVE has a memory operand of 512 bytes, but we only save 30*4=120 bytes
 * because XED does not return the read operands for FXSAVE
 */
#define MAX_NUM_OPERANDS 30

/* 
 * Macro that specifies the maximum number of memory addressing operands in
 * the EntryHeader memregs array
 * See EntryHeader description for what each index in the array represents
 */
#define MAX_NUM_MEMREGS 7

/*
 * Macro that specifies the maximum number of taint labels stored for a byte
 */
#define MAX_NUM_TAINTBYTE_RECORDS 3

/* 
 * Macro that specifies the maximum length for the process name and module name
 * in the ProcRecord and ModuleRecord data types
 * This corresponds to the maxime length saved in the traces
 */
#define MAX_STRING_LEN 32

/* 
 * Macro that specifies the maximum length of an operand in bytes
 * This limitation comes from the size of the 'tainted' field in OperandVal
 * This is enough for all x86 registers (MMX,XMM,Float)
 * Memory operands longer than 4 bytes are typically split in the trace into 
 *   consecutive 4-byte-long memory operands 
 */
#define MAX_OPERAND_LEN 16

/* 
 * Macro that defines the maximum number of bytes in a x86 instruction
 */
#define MAX_INSN_BYTES 15


/* Some floating point definitions from QEMU/fpu/softfloat.h */
typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

typedef struct {
    uint32_t v;
} float32;

typedef struct {
    uint64_t v;
} float64;

/* An XMM register (from QEMU/target-i386/cpu.h) */
typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
    float32 _s[4];
    float64 _d[2];
} XMMReg;

/* 
 * The type of an operand
 */
enum OpType { TNone = 0, TRegister, TMemLoc, TImmediate, TJump, TFloatRegister, TMemAddress, TMMXRegister, TXMMRegister, TFloatControlRegister, TDisplacement };

/*
 * The usage of an operand. Used for unserializing instructions.
 */
enum OpUsage { unknown = 0, esp, counter, membase, memindex, memsegment,
  memsegent0, memsegent1, memdisplacement, memscale, eflags };

/*
 * A taint label
 */
typedef struct _taint_byte_record {
  uint32_t source;         /**< Taint source (e.g., network,keyboard...) */
  uint32_t origin;         /**< Taint origin (e.g., network flow) */
  uint32_t offset;         /**< Taint offset in origin (e.g., byte in flow) */
} TaintByteRecord;

#define TAINT_RECORD_FIXED_SIZE 1

/*
 * A taint record for a byte
 */
typedef struct _taint_record {
  /*
   * The number of taint labels for this byte
   */
  uint8_t numRecords;
  /*
   * The array of taint labels for this byte
   */
  TaintByteRecord taintBytes[MAX_NUM_TAINTBYTE_RECORDS];
} taint_record_t;

/*
 * Operand value union, check operand 'type' field to know which entry to use
 */
typedef union _opval {
  uint32_t val32;          /**< 32-bit value (or smaller) */
  uint64_t val64;          /**< 64-bit value */
  XMMReg xmm_val;          /**< XMM register value */
  floatx80 float_val;      /**< Float register value */
} opval;

/* 
 * Operand address union, check operand 'type' field to know which entry to use
 *   TImmediate, TDisplacement, and TJump have no address, i.e., is zero
 */
typedef union _opaddr {
  uint8_t reg_addr;
  uint32_t mem32_addr;
  uint64_t mem64_addr;
} opaddr;

#define OPERAND_VAL_FIXED_SIZE 4
#define OPERAND_VAL_ENUMS_REAL_SIZE 2

/**
  * An operand in an instruction
  */
typedef struct _operand_val {
  /* 
   * Operand access (e.g., read, written, read and written, ...)
   * It is a value from xed_operand_action_enum_t encoded with one byte
   */
  uint8_t access;
  /* 
   * Operand size in bytes
   */
  uint8_t length;
  /* 
   * Operand taint mask
   * One bit correspond to a byte in the operand, i.e., 
   * if the lowest bit is set the lowest byte in the operand is tainted
   * The maximum operand size is thus limited to 16 bytes
   */
  uint16_t tainted;
  /* 
   * Operand type (e.g., register, memory, float register, ...)
   */
  enum OpType type;
  /* 
   * Operand usage. Used for serialization.
   */
  enum OpUsage usage;
  /* 
   * Operand address
   */
  opaddr addr;
  /* 
   * Operand value
   */
  opval value;
  /* 
   * Array of taint records for the operands
   * records[0] is for the lowest byte, records[1] for the second lowest, etc.
   */
  taint_record_t records[MAX_OPERAND_LEN];
} OperandVal;

#define ENTRY_HEADER_FIXED_SIZE 24

/*
 * An executed instruction and its operand values
 * This is the main data structure to do analysis
 */
typedef struct _entry_header {
  /* 
   * Instruction address (lowest address where instruction is loaded in memory)
   */
  uint32_t address;
  /* 
   * The identifier of the process that executed the instruction
   * For v50 traces, it is not stored and is -1
   */
  uint32_t pid;
  /* 
   * The identifier of the thread that executed the instruction
   */
  uint32_t tid;
  /* 
   * The size of the instruction in bytes
   */
  uint8_t inst_size;
  /* 
   * The total number of operands in the instruction
   * Includes both the entries in the operand and memregs arrays
   * Used for serialization 
   */
  uint8_t num_operands;
  /* 
   * The taint propagation type
   * DEPRECATED, kept for compatibility
   */
  uint8_t tp;
  /* 
   * The direction flag
   * For legacy reasons it can have two value: -1 (x86_df=1) or 1 (x86_df = 0)
   */
  uint8_t df;
  /* 
   * The value of the EFLAGS register
   * This value is only updated for instructions that read the EFLAGS register 
   */
  uint32_t eflags;
  /* 
   * Operation performed by QEMU on CC_SRC,CC_DST
   * DEPRECATED, kept for compatibility
   */
  uint32_t cc_op;
  /* 
   * An array with the rawbytes for the instruction
   * rawbytes[0] has the lowest byte in the instruction's code
   */
  unsigned char rawbytes[MAX_INSN_BYTES];
  /* 
   * The operand array
   * It contains an entry for each operand used by the instruction
   * Make no assumptions on the operand order
   */
  OperandVal operand[MAX_NUM_OPERANDS + 1];
  /* 
   * The memory addressing operand array
   * If operand[i] uses memory addressing (e.g., TMemLoc or TMemAddress)
   * then memregs[i][].type contains the addressing operands
   * If memregs[i][idx].type == TNone, the addressing operand is not used
   *     idx == 0 -> Segment register
   *     idx == 1 -> Base register
   *     idx == 2 -> Index register
   *     idx == 3 -> Segent0
   *     idx == 4 -> Segent1
   *     idx == 5 -> Displacement
   *     idx == 6 -> Scale
   */
  OperandVal memregs[MAX_NUM_OPERANDS + 1][MAX_NUM_MEMREGS];
} EntryHeader;

/* 
 * A process record
 * There is one of this for each process that appears in the trace
 */
typedef struct _proc_record {
  char name[MAX_STRING_LEN];/**< The process name */
  uint32_t pid;             /**< The process identifier */
  int n_mods;               /**< The number of modules loaded by the process */
  uint32_t ldt_base;        /**< The base address of the LDT table */
} ProcRecord;

/*
 * A module record
 * There is one of this for each module loaded by the process
 * when the trace starts (trace header) or ends (trace trailer)
 */
typedef struct _module_record {
  char name[MAX_STRING_LEN];/**< The module name */
  uint32_t base;            /**< The base (lowest) address for the module */
  uint32_t size;            /**< The size of the module in bytes */
} ModuleRecord;

/* 
 * The trace header
 */
typedef struct _trace_header {
  int magicnumber;         /**< MAGIC_NUMBER */
  int version;             /**< The trace version */
  int n_procs;             /**< The number of processes traced */
  uint32_t gdt_base;       /**< The base address of the GDT table */
  uint32_t idt_base;       /**< The base address of the IDT table */
} TraceHeader;

#endif // _TRACE60_H_

