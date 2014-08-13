/* 
 *  interface for traces
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

#ifndef _TRACE_INTERFACE_H_
#define _TRACE_INTERFACE_H_

/** @file */

#include <xed-interface.h>
#include "trace60.h"

/* Type definitions for structures in trace60.h */
typedef ProcRecord proc_t;
typedef TraceHeader theader_t;
typedef ModuleRecord module_t;
typedef OperandVal operand_t;
typedef EntryHeader entry_header_t;

/* Forward declarations to break circular typedef dependencies */
struct _x86_inst;
struct _trace_interface;

/** 
  * A function pointer for the trace_read_next_insn function
  * @param trace the interface for the trace to be read
  * @param insn a pointer where the read instruction is copied
  * @param disassemble_insn if non-zero, the read instruction is disassembled
  * @return zero if successful, -1 if it fails
  */
typedef int (read_insn_t)(struct _trace_interface * trace, 
                          struct _x86_inst * insn, int disassemble_insn);

/** 
  * A trace interface 
  */
typedef struct _trace_interface
{
  /**
    * The path to the trace file
    */
  char * trace_path;
  /**
    * The trace version
    */
  unsigned int trace_version;
  /** 
    * The stream of the opened trace file
    */
  FILE * trace_stream;
  /** 
    * The stream of the opened index file
    */
  FILE * trace_idx_stream;
  /** 
    * The size of the trace file in bytes
    */
  unsigned long long trace_byte_size;
  /**
    *  The number of instructions in the trace file
    */
  unsigned long long trace_num_insn;
  /** 
    * The counter for the next instruction to be read
    */
  unsigned long long trace_next_insn_ctr;
  /** 
    * The file offset in the trace at the first instruction
    */
  uint64_t trace_first_filepos;
  /** 
    * A function pointer to the function to read the next instruction
    */
  read_insn_t * trace_read_next_insn;
  /** 
    * The number of processes traced
    */
  size_t trace_nprocs;
  /** 
    * Array of traced processes
    */
  proc_t * trace_procs;
  /** 
    * Array of pointers to module array for each process
    */
  module_t ** trace_mods;
} trace_interface_t;

/** 
  * An x86 instruction 
  */
typedef struct _x86_inst
{
  unsigned long long insn_ctr;  /**< The instruction number in the trace */
  EntryHeader eh;               /**< The instruction's EntryHeader */
  xed_decoded_inst_t xed_inst;  /**< The disassembled instruction */
} x86_inst_t;

/** 
  * A function pointer for the trace_fold functions
  * @param insn a pointer to the instruction to be processed
  * @param ctx a pointer to an opaque context that the caller 
  *   can use to pass state between invocations for each instruction
  * @return if the invocation returns zero, iteration continues, 
  *   otherwise iteration stops
  */
typedef int (process_insn_t)(x86_inst_t * insn, void * ctx);

/** 
  * Open a trace 
  * @param trace_path the path to the trace file to be opened
  * @return a pointer to the trace interface, NULL if it fails 
  */
trace_interface_t * trace_open(const char * trace_path);

/** 
  * Close a trace 
  * @param trace the interface for the trace to be closed
  */
void trace_close(trace_interface_t * trace);

/**
  * Create an index for the given trace file
  * @param trace_path the path to the trace file 
  * @return zero if successful, -1 if it fails
  */
int trace_create_index(const char * trace_path);

/** 
  * Read next instruction from the trace file 
  * This is simply a wrapper for the trace_read_next_insn function pointer in
  * trace_interface_t
  * @param trace the interface for the trace to be read
  * @param insn a pointer where the read instruction is copied
  * @param disassemble_insn if non-zero, the read instruction is disassembled
  *   Normally you want this set to one 
  * @return zero if successful, -1 if it fails
  */
int trace_read_next_insn(trace_interface_t * trace, x86_inst_t * insn, 
                    int disassemble_insn);

/** 
  * Move the trace file offset so that the next instruction to be read is 
  *   the given one
  * @param trace the interface for the trace to be seeked
  * @param insn_ctr the counter of the instruction to seek
  * @return zero if successful, -1 if it fails
  * NOTE: Expensive operation, i.e., avoid frequent invocations 
  */
int trace_seek_insn(trace_interface_t * trace, unsigned long long insn_ctr);

/** 
  * Move the trace file offset so that the next instruction to be read is 
  *   the first one in the trace
  * @param trace the interface for the trace to be seeked
  * @return zero if successful, -1 if it fails
  * NOTE: Expensive operation, i.e., avoid frequent invocations 
  */
int trace_seek_first(trace_interface_t * trace);

/** 
  * Get the current trace file offset 
  * @param trace the interface for the trace to be queried
  * @return the current file offset of the trace
  * NOTE: Expensive operation, i.e., avoid frequent invocations 
  */
off_t trace_get_curr_filepos(trace_interface_t * trace);

/** 
  * Iterate forward on the trace applying function f to each instruction 
  * in given range 
  * @param trace the interface for the trace to be iterated
  * @param start the counter of the instruction to start the iteration
  * @param end the counter of the instruction to stop the iteration
  * @param restore_position if non-zero, after iteration completes 
  *   the trace file offset is restored to the value befoe iteration starts
  * @param f the function to apply to each instruction
  * @param ctx a pointer to an opaque context that the caller 
  *   can use to pass state between invocations for each instruction
  * @return zero if successul, -1 if it fails
  */
int trace_fold(trace_interface_t * trace,
                unsigned long long start, unsigned long long end,
                int restore_position, process_insn_t f, void * ctx);

/** 
  * Iterate backward on the trace applying function f to each instruction 
  * in given range 
  * @param trace the interface for the trace to be iterated
  * @param start the counter of the instruction to start the iteration
  * @param end the counter of the instruction to stop the iteration
  *   This parameter needs to be larger than start parameter
  * @param restore_position if non-zero after iteration completes 
  *   the trace file offset is restored to the value befoe iteration starts
  * @param f the function to apply to each instruction
  *   invocations for each instruction
  * @return zero if successul, -1 if it fails
  * NOTE: Expensive operation, i.e., avoid frequent invocations 
  */
int trace_fold_right(trace_interface_t * trace,
                unsigned long long start, unsigned long long end,
                int restore_position, process_insn_t f, void * ctx);

#endif // #ifndef _TRACE_INTERFACE_H_

