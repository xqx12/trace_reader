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

#ifndef _TRACE_PRINT_H_
#define _TRACE_PRINT_H_

/** @file */

#include "trace60.h"
#include "trace_interface.h"

/** 
  * Return the given operand as a string 
  * @param op a pointer to the operand to be returned as a string
  * @param out a pointer to output buffer where the string is returned
  * @param out_size the size in bytes of the output buffer
  * @param pre_sep a pointer to a string to prepend to the operand string
  * @param include_taint_bytes if non-zero, the taint information for each 
  *   byte in the operand is added to the operand string
  * @return the number of bytes in the returned string, -1 if it fails
  */
int operand_str(operand_t * op, char * out, size_t out_size, char *pre_sep, 
                int include_taint_bytes);

/** 
  * Return the given instruction as a string
  * @param insn a pointer to the instruction to be returned as a string
  * @param out a pointer to output buffer where the string is returned
  * @param out_size the size in bytes of the output buffer
  * @param intel_format if non-zero, the instruction mnemonic is in 
  *   Intel format, otherwise it is in ATT format
  * @param verbose if non-zero, additional information such as 
  *   thread identifier and memory addressing operands is added to the string
  * @param print_counter if non-zero, the instruction counter is prepended
  * @param pre_sep a pointer to a string to prepend to the operand string
  * @param post_sep a pointer to a string to append to the operand string
  * @return the number of bytes in the returned string, -1 if it fails
  */
int insn_str(x86_inst_t * insn, char * out, size_t out_size, int intel_format, 
              int verbose, int print_counter, char *pre_sep, char *post_sep);

/** 
  * Return the given module as a string 
  * @param mod a pointer to the module to be returned as a string
  * @param out a pointer to output buffer where the string is returned
  * @param out_size the size in bytes of the output buffer
  * @param pre_sep a pointer to a string to prepend to the module string
  * @param post_sep a pointer to a string to append to the module string
  * @return the number of bytes in the returned string, -1 if it fails
  */
int module_str(module_t* mod, char * out, size_t out_size,
                char * pre_sep, char * post_sep);

/** 
  * Print the given operand on the given stream
  * @param stream the stream where the operand string is printed
  * @param op a pointer to the operand to be printed as a string
  * @param pre_sep a pointer to a string to prepend to the operand string
  * @return the number of bytes printed, -1 if it fails
  */
int print_operand(FILE * stream, operand_t * op, char *pre_sep);

/** 
  * Print an instruction on the given stream 
  * @param stream the stream where the operand string is printed
  * @param insn a pointer to the instruction to be printed as a string
  * @param intel_format if non-zero, the instruction mnemonic is in 
  *   Intel format, otherwise it is in ATT format
  * @param verbose if non-zero, additional information such as 
  *   thread identifier and memory addressing operands is added to the string
  * @param print_counter if non-zero, the instruction counter is prepended
  * @return the number of bytes printed, -1 if it fails
  */
int print_insn(FILE * stream, x86_inst_t * insn, int intel_format, 
                int verbose, int print_counter);

/** 
  * Print processing status bar on the given stream
  * @param stream the stream where the status bar string is printed
  * @param percent the percentage of work completed in the range [0,100]
  * @return the number of bytes printed, -1 if it fails
  */
int print_percent(FILE * stream, int percent);

/** 
  * Print trace information on the given stream
  * @param stream the stream where the status bar string is printed
  * @param trace pointer to the interface of the trace 
  * @param print_modules if non-zero, the modules for the traced process are
  *   also printed
  * @return the number of bytes printed, -1 if it fails
  */
int print_trace_header(FILE * stream, trace_interface_t * trace, 
                        int print_modules);

#endif // #ifndef _TRACE_PRINT_H_

