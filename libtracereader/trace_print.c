/* 
 *  formatting functions for information in execution traces
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <xed-interface.h>
#include <trace_print.h>

#define MAX_STR_SIZE 2048

const char optype[11] = 
  {'N', 'R', 'M', 'I', 'J', 'R', 'A', 'R', 'R', 'R', 'D'};

const char maccess[8][4] = {
  {""}, {"RW"}, {"R"}, {"W"}, {"RCW"}, {"CW"}, {"CRW"}, {"CR"}
};

const char regname[104][6] = {
/*100*/ {"es"}, {"cs"}, {"ss"}, {"ds"}, {"fs"}, {"gs"}, {""}, {""}, 
/*108*/ {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
/*116*/ {"al"}, {"cl"}, {"dl"}, {"bl"}, {"ah"}, {"ch"}, {"dh"}, {"bh"}, 
/*124*/ {"ax"}, {"cx"}, {"dx"}, {"bx"}, {"sp"}, {"bp"}, {"si"}, {"di"},
/*132*/ {"eax"}, {"ecx"}, {"edx"}, {"ebx"}, {"esp"}, {"ebp"}, {"esi"}, {"edi"},
/*140*/ {""}, {""}, {""}, {""}, {""}, {"eflags"}, {""}, {""},
/*148*/ {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
/*156*/ {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
/*164*/ {"mm0"}, {"mm1"}, {"mm2"}, {"mm3"}, {"mm4"}, {"mm5"}, {"mm6"}, {"mm7"},
/*172*/ {"xmm0"}, {"xmm1"}, {"xmm2"}, {"xmm3"}, {"xmm4"}, {"xmm5"}, {"xmm6"}, 
        {"xmm7"},
/*180*/ {"xmm8"}, {"xmm9"}, {"xmm10"}, {"xmm11"}, {"xmm12"}, {"xmm13"}, 
        {"xmm14"}, {"xmm15"},
/*188*/ {"st0"}, {"st1"}, {"st2"}, {"st3"}, {"st4"}, {"st5"}, {"st6"}, {"st7"},
/*196*/ {"fpuc"}, {"fpus"}, {"fputag"}, {""}, {""}, {""}, {""}, {""},
};

const char taintprop_str[6][16] = {
  {"TPNone"}, {"TPSrc"}, {"TPCjmp"}, 
  {"TPMemReadIndex"}, {"TPMemWriteIndex"}, {"TPRepCounter"}
};


int module_str(module_t * mod, char * out, size_t out_size, 
                char * pre_sep, char * post_sep)
{
  uint32_t last;
  size_t curr_size;

  if (!mod || !out)
    return -1;

  last = mod->base + mod->size -1;

  return snprintf(out + curr_size, out_size - curr_size, 
                   "%s%s @ 0x%08x--0x%08x (%d bytes)%s",
                   pre_sep, mod->name, mod->base, last, mod->size, post_sep);

}

int operand_taint_str(operand_t * op, char * out, size_t out_size) 
{
  size_t curr_size = 0;
  int i;

  if (!op || !out || (out_size <= 0))
    return -1;

  if (op->tainted == 0) {
    return 0;
  }

  curr_size += snprintf(out, out_size, " {%u ", op->tainted);

  for (i = 0; i < op->length; i++) {
    if (op->records[i].numRecords > 0) {
      TaintByteRecord * byte_record = &(op->records[i].taintBytes[0]);
      curr_size += 
        snprintf(out + curr_size, out_size - curr_size, "(%u,%u,%u) ", 
                byte_record->source, byte_record->origin, byte_record->offset);
    }
    else {
      curr_size +=
        snprintf(out + curr_size, out_size - curr_size, "() ");
    }
  }
  out[curr_size-1] = '}';

  return curr_size;
}

int operand_str(operand_t * op, char * out, size_t out_size, char *pre_sep, 
                int include_taint_bytes) 
{
  size_t curr_size = 0;

  if (!op || !out || (out_size <= 0))
    return -1;

  switch(op->type) {
    case TNone:
      out[0] = '\0';
      return 0;

    case TRegister:
    case TFloatControlRegister:
      curr_size = 
        snprintf(out, out_size, "%sR@%s[0x%08x][%d](%s) T%d", 
          pre_sep,
          regname[op->addr.reg_addr - 100], 
          op->value.val32, 
          op->length, 
          maccess[op->access], 
          (op->tainted > 0));
      if (include_taint_bytes) {
        curr_size += 
          operand_taint_str(op, out + curr_size, out_size - curr_size);
      }
      return curr_size;

    case TFloatRegister:
      return
        snprintf(out, out_size, "%sR@%s[0x%04x%016llx][%d](%s) T%d",
          pre_sep,
          regname[op->addr.reg_addr - 100],
          op->value.float_val.high,
          op->value.float_val.low,
          op->length,
          maccess[op->access],
          (op->tainted > 0));

    case TMMXRegister:
      return
        snprintf(out, out_size, "%sR@%s[0x%016llx][%d](%s) T%d",
          pre_sep,
          regname[op->addr.reg_addr - 100],
          op->value.xmm_val._q[0],
          op->length,
          maccess[op->access],
          (op->tainted > 0));

    case TXMMRegister:
      return 
        snprintf(out, out_size, "%sR@%s[0x%016llx%016Lx][%d](%s) T%d",
          pre_sep,
          regname[op->addr.reg_addr - 100],
          op->value.xmm_val._q[1],
          op->value.xmm_val._q[0],
          op->length,
          maccess[op->access],
          (op->tainted > 0));

    default:
      curr_size = 
        snprintf(out, out_size, "%s%c@0x%08x[0x%08x][%d](%s) T%d",
          pre_sep,
          optype[op->type],
          op->addr.mem32_addr,
          op->value.val32,
          op->length,
          maccess[op->access],
          (op->tainted > 0));
      if (include_taint_bytes) {
        curr_size += 
          operand_taint_str(op, out + curr_size, out_size - curr_size);
      }
      return curr_size;
  }
}

int print_operand(FILE * stream, operand_t * op, char * pre_sep)
{
  char op_str[256];
  size_t curr_size = 0;

  if (!stream || !op)
    return -1;

  curr_size = operand_str(op, op_str, sizeof(op_str), pre_sep, 1);
  fputs(op_str, stream);

  return curr_size;
}

int print_operands(FILE * stream, entry_header_t * eh)
{
  int i;
  int curr_size = 0;

  if (!stream || !eh)
    return -1;

  for (i = 0; (eh->operand[i].type != TNone) && (i < MAX_NUM_OPERANDS); i++)
    curr_size += print_operand(stream, &(eh->operand[i]), "\t");

  return curr_size;
}

int insn_str(x86_inst_t * insn, char * out, size_t out_size, int intel_format, 
              int verbose, int print_counter, char *pre_sep, char *post_sep)
{
  int i;
  int curr_size = 0;
  char ctr_str[11] = "";

  EntryHeader * eh = &(insn->eh);

  // Select syntax
  xed_syntax_enum_t xed_syntax = 
    intel_format ? XED_SYNTAX_INTEL : XED_SYNTAX_ATT;

  // Set instruction counter if needed
  if (print_counter) {
    snprintf(ctr_str, sizeof(ctr_str), "(%08llu)", insn->insn_ctr);
  }

  // Add pre_sep, instruction counter, and address
  uint64_t addr = eh->address;
  curr_size += snprintf(out, out_size, "%s%s%llx:   ", 
                        pre_sep, ctr_str, addr);

  // Add instruction mnemonic
  xed_bool_t xed_result =
    xed_format_context(xed_syntax, &(insn->xed_inst), out + curr_size,
                        out_size - curr_size, addr, NULL);
  assert(xed_result == 1);

  // Find current size (needed because XED does not return mnemonic size)
  curr_size = strlen(out);
 
  // Add operands
  size_t num_ops = eh->num_operands;
  for (i = 0; i < num_ops; i++)
    curr_size += operand_str(&(eh->operand[i]), out+curr_size, 
                              out_size-curr_size, "\t", 1);

  // Add extra information
  if (verbose) {
    // Add ESP

    // Add other 
    curr_size += snprintf(out+curr_size, out_size-curr_size, 
        " NUM_OP: %d PID: %d TID: %d TP: %s EFLAGS: 0x%08X",
        num_ops, eh->pid, eh->tid, taintprop_str[eh->tp], eh->eflags);

    // Add DF

    // Add rawbytes
    size_t tmp_size = (out_size-curr_size > 8) ? 8 : out_size-curr_size;
    strncpy(out+curr_size, " RAW: 0x", tmp_size+1);
    curr_size+=tmp_size;
    for (i = 0; i < eh->inst_size; i++) {
      curr_size+= snprintf(out+curr_size, out_size-curr_size, "%02x", 
                            (unsigned char)eh->rawbytes[i]);
    }

    // Add memory addressing registers if any
    for (i = 0; i < eh->num_operands; i++) {
      if ((eh->operand[i].type == TMemLoc) || 
          (eh->operand[i].type == TMemAddress)) 
      {
        // Add segment, base, index 
        curr_size+= snprintf(out+curr_size, out_size-curr_size, 
                              " MEMREGS(%d): ", i);
        curr_size += operand_str(&(eh->memregs[i][0]), out+curr_size,
                                  out_size-curr_size, "\t", 1);
        curr_size += operand_str(&(eh->memregs[i][1]), out+curr_size,
                                  out_size-curr_size, "\t", 1);
        curr_size += operand_str(&(eh->memregs[i][2]), out+curr_size,
                                  out_size-curr_size, "\t", 1);

        // Add displacement
        if (eh->memregs[i][5].type != TNone) {
          curr_size+= snprintf(out+curr_size, out_size-curr_size, 
                                " disp: 0x%x", eh->memregs[i][5].value.val32);
        }
        // Add scale
        if (eh->memregs[i][6].type != TNone) {
          curr_size+= snprintf(out+curr_size, out_size-curr_size,
                                " scale: %d", eh->memregs[i][6].value.val32);
        }

        // Add segment descriptor
        if (eh->memregs[i][3].type != TNone) {
          curr_size+= snprintf(out+curr_size, out_size-curr_size,
                                " seg descrs: ");
          curr_size += operand_str(&(eh->memregs[i][3]), out+curr_size,
                                    out_size-curr_size, "\t", 1);
          curr_size += operand_str(&(eh->memregs[i][4]), out+curr_size,
                                    out_size-curr_size, "\t", 1);
        }
      }
    }
  }

  // Add post delimiter
  curr_size += 
    snprintf(out+curr_size, out_size-curr_size, "%s", post_sep); 

  return curr_size;
}


int print_insn(FILE * stream, x86_inst_t * insn, int intel_format, 
                int verbose, int print_counter)
{
  char insn_buf[MAX_STR_SIZE] = {0};
  size_t curr_size = 0;

  // Select syntax
  xed_syntax_enum_t xed_syntax = 
    intel_format ? XED_SYNTAX_INTEL : XED_SYNTAX_ATT;

  // Build instruction string
  curr_size = insn_str(insn, insn_buf, sizeof(insn_buf), intel_format, verbose,
            print_counter, "", "\n");

  // Print instruction string
  fputs(insn_buf, stream);

  // Return number of bytes written
  return curr_size;
}

int print_percent(FILE * stream, int percent)
{
  static int tty_width = -1;
  static struct winsize wsize;
  static unsigned char * output = NULL;

  if (percent < 0 || percent > 100 || !stream) {
    return;
  }

  int ret = ioctl(0, TIOCGWINSZ, &wsize);
  assert(ret != -1);

  if (wsize.ws_col != tty_width) {

    tty_width = wsize.ws_col;

    output = realloc(output, tty_width);
    assert(output != NULL);

    memset(output, 0, tty_width);
  }

  int dots = (percent * (tty_width - 8)) / 100;

  memset(output, '#', dots);
  memset(output + dots, ' ', tty_width - dots - 8);

  return fprintf(stream, "\r[%s] %3d%% ", output, percent);
}

int print_trace_header(FILE * stream, trace_interface_t * trace, 
                        int print_modules)
{
  size_t curr_size;
  int i, j;
  char mod_str[256];

  if (!stream || !trace)
    return;

  curr_size = fprintf(stream, 
                  "Trace version: %d\n"
                  "Number of instructions: %lld\n",
                  trace->trace_version,
                  trace->trace_num_insn);

  if (!trace->trace_procs || !trace->trace_mods)
    return curr_size;

  for (i = 0; i < trace->trace_nprocs; i ++) {
    curr_size = fprintf(stream, "Process: %s PID: %d\n",
                  trace->trace_procs[i].name, trace->trace_procs[i].pid);
    if (print_modules) {
      for (j = 0; j < trace->trace_procs[i].n_mods; j++) {
        curr_size += module_str(&(trace->trace_mods[i][j]), 
                                mod_str, sizeof(mod_str), "\t", "\n");
        fputs(mod_str, stream);
      }
    }
  }

  return curr_size;
}

