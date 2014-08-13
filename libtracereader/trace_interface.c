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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <xed-interface.h>
#include <trace_interface.h>

// Maximum length of a module line
#define LINE_SIZE 1024

/* Forward declarations */
static int read_instruction_v50(trace_interface_t * trace, x86_inst_t * insn,
                    int disassemble_insn);
static int read_instruction_v60(trace_interface_t * trace, x86_inst_t * insn,
                    int disassemble_insn);

/* Disassembler state */
static xed_state_t dstate;


/* XED2 initialization */
void xed2_init() 
{
  xed_tables_init ();
  xed_state_zero (&dstate);

  xed_state_init(&dstate,
    XED_MACHINE_MODE_LEGACY_32,
    XED_ADDRESS_WIDTH_32b,
    XED_ADDRESS_WIDTH_32b);

  // Format options
  xed_format_options_t xed_foptions;
  xed_foptions.hex_address_before_symbolic_name = 1;
  xed_foptions.no_sign_extend_signed_immediates = 1;
  xed_foptions.omit_unit_scale = 1;
  xed_foptions.xml_a = 0;
  xed_foptions.xml_f = 0;
  xed_format_set_options(xed_foptions);
}


off_t trace_get_curr_filepos(trace_interface_t * trace)
{
  if (!trace || !(trace->trace_stream))
    return -1;

  return ftello(trace->trace_stream);
}

int trace_seek_first(trace_interface_t * trace)
{
  if (!trace || !(trace->trace_stream))
    return -1;

  if (fseeko(trace->trace_stream, trace->trace_first_filepos, SEEK_SET) != 0) {
    return -1;
  }

  trace->trace_next_insn_ctr = 1;

  return 0;
}

int trace_seek_insn(trace_interface_t * trace, unsigned long long insn_ctr)
{
  off_t trace_filepos;

  if (!trace || !(trace->trace_stream) || (insn_ctr <= 0)) 
    return -1;

  if (insn_ctr == 1) {
    if (fseeko(trace->trace_stream, trace->trace_first_filepos, SEEK_SET) != 0)
    {
      fprintf(stderr, "libtracereader: trace_seek failed to seek first.\n");
      return -1;
    }
    trace->trace_next_insn_ctr = 1;
    return 0;
  }

  if (!(trace->trace_idx_stream)) {
    fprintf(stderr, "libtracereader: trace_seek invoked with no index.\n");
    return -1;
  }

  if (fseeko(trace->trace_idx_stream, (insn_ctr - 1) * 8, SEEK_SET) != 0) {
    fprintf(stderr, "libtracereader: failed seeking in trace index.\n");
    return -1;
  }

  if (fread(&(trace_filepos), 8, 1, trace->trace_idx_stream) != 1) {
    fprintf(stderr, "libtracereader: failed reading from trace index.\n");
    return -1;
  }

  if (fseeko(trace->trace_stream, trace_filepos, SEEK_SET) != 0) {
    fprintf(stderr, "libtracereader: failed seeking in trace file.\n");
    return -1;
  }

  trace->trace_next_insn_ctr = insn_ctr;

  return 0;
}

static int read_processes(FILE * stream, size_t num_procs, 
                              proc_t ** procs_ptr, module_t *** mods_ptr)
{
  int i;
  size_t num_proc_mods;

  /* Allocate process structure */
  *procs_ptr = (proc_t *) malloc (sizeof(proc_t)*num_procs);
  proc_t * procs = *procs_ptr;
  if (!procs) {
    fprintf(stderr, "libtracereader: failed to allocate process array.\n");
    goto fail;
  }

  /* Allocate module array */
  *mods_ptr = (module_t **) malloc (sizeof(module_t *)*num_procs);
  module_t ** mods = *mods_ptr;
  if (!mods) {
    fprintf(stderr, "libtracereader: failed to allocate module matrix.\n");
    goto fail;
  }

  /* Read process information from trace file */
  for (i = 0; i < num_procs; i++) {
    if (fread(&(procs[i]), sizeof(proc_t), 1, stream) != 1) {
      fprintf(stderr, "libtracereader: could not read process.\n");
      goto fail;
    }

    num_proc_mods = procs[i].n_mods;
    if (num_proc_mods <= 0) {
      fprintf(stderr,
        "libtracereader: could not find any modules for process %d.\n",
        procs[i].pid);
      goto fail;
    }

    mods[i] = (module_t *) malloc (sizeof(module_t)*num_proc_mods);
    if (!mods[i]) {
      fprintf(stderr, "libtracereader: failed to allocate module array.\n");
      goto fail;
    }

    /* Read module information from trace file */
    if (fread(mods[i], sizeof(module_t), num_proc_mods, stream)
         != num_proc_mods)
    {
      fprintf(stderr,
        "libtracereader: failed to read all modules for process %d.\n",
        procs[i].pid);
      goto fail;
    }
  }
  return 0;

fail:
  if (procs) {
    free(procs);
    *procs_ptr = NULL;
  }
  if (mods) {
    for (i = 0; i < num_procs; i++) {
      if (mods[i])
        free(mods[i]);
    }
    free(mods);
    *mods_ptr = NULL;
  }
  return -1;
}

int trace_read_trailer(trace_interface_t * trace, int restore_position) 
{
  off_t original_next_insn_ctr;
  size_t trailer_size, num_procs = 0;
  uint32_t magic_number;
  FILE * stream;
  int i;

  if (!trace || trace->trace_version != 60)
    return -1;

  stream = trace->trace_stream;

  // Save current file position
  if (restore_position) {
    original_next_insn_ctr = trace->trace_next_insn_ctr;
  }

  // Read end of trace
  if (fseeko(stream, trace->trace_byte_size - 12, SEEK_SET) != 0) {
    fprintf(stderr, "libtracereader: failed seeking end of trace.\n");
    return -1;
  }

  // Read trailer size
  if (fread(&trailer_size, 4, 1, stream) != 1) {
    fprintf(stderr, "libtracereader: failed reading trailer size.\n");
    return -1;
  }

  // Read number of processes size
  if (fread(&num_procs, 4, 1, stream) != 1) {
    fprintf(stderr, 
            "libtracereader: failed reading number ot trailer processes .\n");
    return -1;
  }

  // Read magic number
  if (fread(&magic_number, 4, 1, stream) != 1) {
    fprintf(stderr, "libtracereader: failed reading trailer magic number.\n");
    return -1;
  }

  // Make sure it looks like a trailer
  if (magic_number != TRAILER_END) {
    fprintf(stderr, "libtracereader: invalid trailer magic number.\n");
    return -1;
  }

  if (num_procs > 0) {
    // Seek start of trailer process information
    off_t proc_filepos = trace->trace_byte_size - (trailer_size + 12);
    if (fseeko(stream, proc_filepos, SEEK_SET) != 0) {
      fprintf(stderr, "libtracereader: failed seeking trailer processes.\n");
      return -1;
    }

    // Read processes and modules
    proc_t * procs = NULL;
    module_t ** mods = NULL;
    if (read_processes(stream, num_procs, &procs, &mods) != 0)
    {
      fprintf(stderr, "libtracereader: failed reading trailer processes.\n");
      return -1;
    }

    // Free current processes and modules structures
    if (trace->trace_procs) {
      free(trace->trace_procs);
      trace->trace_procs = NULL;
    }
    if (trace->trace_mods) {
      for (i = 0; i < trace->trace_nprocs; i++) {
        if (trace->trace_mods[i])
          free(trace->trace_mods[i]);
      }
      free(trace->trace_mods);
      trace->trace_mods = NULL;
    }

    // Update process and module information
    trace->trace_procs = procs;
    trace->trace_mods = mods;
    trace->trace_nprocs = num_procs;
  }

  // Restore original position
  if (restore_position) {
    if (trace_seek_insn(trace, original_next_insn_ctr) != 0) {
      return -1;
    }
  }

  return 0;
}

trace_interface_t * trace_open(const char * trace_path)
{
  FILE * stream = NULL;
  FILE * idx_stream = NULL;
  struct stat file_info;
  theader_t trace_header;
  char index_path[128] = {0};
  size_t num_proc_mods;
  int i;

  /* Open trace file */
  if ((stream = fopen(trace_path, "r")) == NULL) {
    fprintf(stderr, "libtracereader: could not open %s.\n", trace_path);
    return NULL;
  }

  /* Get size of trace file */
  if (fstat(fileno(stream), &file_info) != 0) {
    fprintf(stderr, "libtracereader: fstat failed on trace file.\n");
    return NULL;
  }

  if (file_info.st_size < sizeof(trace_header)) {
    fprintf(stderr, "libtracereader: trace is too small.\n");
    return NULL;
  }

  /* Read header from trace file */
  if (fread(&trace_header, sizeof(trace_header), 1, stream) != 1) {
    fprintf(stderr, "libtracereader: could not read trace header.\n");
    return NULL;
  }

  if (trace_header.magicnumber != MAGIC_NUMBER) {
    fprintf(stderr, "libtracereader: invalid trace file.\n");
    return NULL;
  }

  /* Allocate trace interface */
  trace_interface_t * trace = 
    (trace_interface_t *) malloc (sizeof(trace_interface_t));
  if (!trace) {
    fprintf(stderr, "libtracereader: failed to allocate trace interface.\n");
    return NULL;
  }
  trace->trace_stream = stream;
  trace->trace_version = trace_header.version;
  trace->trace_nprocs = trace_header.n_procs;
  trace->trace_byte_size = file_info.st_size;
  trace->trace_procs = NULL;
  trace->trace_mods = NULL;
  trace->trace_path = NULL;

  /* Set read instruction function pointer */
  switch (trace_header.version) {
    case 50:
      trace->trace_read_next_insn = read_instruction_v50;
      break;
    case 60:
      trace->trace_read_next_insn = read_instruction_v60;
      break;
    default:
      fprintf(stderr, "libtracereader: unsupported trace version.\n");
      goto fail;
  }

  /* Read process information from trace file */
  if (read_processes(trace->trace_stream, trace_header.n_procs,
                        &(trace->trace_procs), &(trace->trace_mods)) != 0) 
  {
    goto fail;
  }

  /* Copy file path */
  size_t path_len = strlen(trace_path);
  trace->trace_path = (char *) malloc (path_len + 1);
  if (trace->trace_path == NULL) {
    fprintf(stderr,
      "libtracereader: could not allocate memory for trace path.\n");
    goto fail;
  }
  strncpy(trace->trace_path, trace_path, path_len);

  /* Fill remaining fields in trace_file */
  trace->trace_first_filepos = ftello(stream);
  trace->trace_next_insn_ctr = 1;

  /* Read trailer if needed */
  if (trace_header.version == 60) {
    trace_read_trailer(trace, 1);
  }

  /* Open index file if it exists */
  snprintf(index_path, sizeof(index_path), "%s.idx", trace_path);
  if ((idx_stream = fopen(index_path, "r")) != NULL) {
    trace->trace_idx_stream = idx_stream;
    if (fstat(fileno(idx_stream), &file_info) != 0) {
      fprintf(stderr, "libtracereader: fstat failed on trace file.\n");
      goto fail;
    }
    trace->trace_num_insn = file_info.st_size / 8;
  }
  else {
    trace->trace_idx_stream = NULL;
    trace->trace_num_insn = -1;
  }

  /* Initialize disassembler */
  xed2_init();

  return trace;

fail:
  if (trace->trace_path) {
    free(trace->trace_path);
    trace->trace_path = NULL;
  }
  if (trace->trace_procs) {
    free(trace->trace_procs);
    trace->trace_procs = NULL;
  }
  if (trace->trace_mods) {
    for (i = 0; i < trace_header.n_procs; i++) {
      if (trace->trace_mods[i])
        free(trace->trace_mods[i]);
    }
    free(trace->trace_mods);
    trace->trace_mods = NULL;
  }
  if (trace)
    free(trace);
  return NULL;
}

void trace_close(trace_interface_t * trace)
{
  if (!trace)
    return;

  // Close trace file
  if (trace->trace_stream) {
    fclose(trace->trace_stream);
    trace->trace_stream = NULL;
  }

  // Close index file
  if (trace->trace_idx_stream) {
    fclose(trace->trace_idx_stream);
    trace->trace_idx_stream = NULL;
  }

  // Free trace path
  if (trace->trace_path) {
    free(trace->trace_path);
    trace->trace_path = NULL;
  }

  // Free trace interface
  free(trace);
  trace = NULL;
}

int trace_create_index(const char * trace_path) 
{
  FILE * idx_stream;
  static char idx_file[128] = {0};
  size_t num_written;
  off_t curr_filepos = 0;
  x86_inst_t insn;

  /* Open the trace */
  trace_interface_t * trace = trace_open(trace_path);
  if (trace == NULL) {
    return -1;
  }

  // Check that the path does not overflow the buffer
  num_written = snprintf(idx_file, sizeof(idx_file), "%s.idx", trace_path);
  if (num_written == (sizeof(idx_file) - 1)) {
    fprintf(stderr, "libtracereader: file path longer than maximum %d char.\n",
            sizeof(idx_file));
    return -1;
  }

  // Create index file
  if ((idx_stream = fopen(idx_file, "w")) == NULL) {
    fprintf(stderr, "error : could not create index file.\n");
    return -1;
  }

  // Populate index
  while (1) {
    curr_filepos = ftello(trace->trace_stream);
    if (trace->trace_read_next_insn(trace, &insn, 0) == 0) {
      fwrite(&(curr_filepos), 8, 1, idx_stream);
    }
    else {
      break;
    }
  }

  // Close trace
  trace_close(trace);

  // Close trace index (do not assume trace_open will)
  fclose(idx_stream);

  return 0;
}

static int read_operand_v50(FILE * stream, operand_t * op)
{
  int i = 0;

  // Read access, length, tainted
  if (fread(op, OPERAND_VAL_FIXED_SIZE, 1, stream) != 1)
    return -1;

  // Nullify address and value
  memset(&(op->addr), 0, sizeof(opaddr)+sizeof(opval));

  // Read operand address
  if (fread(&(op->addr), 4, 1, stream) != 1)
    return -1;

  // Read operand value
  if (fread(&(op->value), 4, 1, stream) != 1)
    return -1;

  // Read operand type
  if (fread(&(op->type), 1, 1, stream) != 1)
    return -1;

  // Read operand usage
  if (fread(&(op->usage), 1, 1, stream) != 1)
    return -1;

  // Read operand taint
  for (i = 0; i < op->length; i++) {
    if(op->tainted & (1 << i)) {
      /* Read number of TaintByteRecord entries */
      fread(&(op->records[i]), TAINT_RECORD_FIXED_SIZE, 1, stream);

      /* Read TaintByteRecord array */
      fread(&(op->records[i].taintBytes), sizeof(TaintByteRecord), 
            op->records[i].numRecords, stream);
    }
  }

  return 0;
}

static int read_instruction_v50(trace_interface_t * trace, x86_inst_t * insn, 
                    int disassemble_insn)
{
  int i, j;
  int count = 0;

  if (!trace || !insn)
    return -1;

  entry_header_t * eh = &(insn->eh);
  FILE *stream = trace->trace_stream;

  // Read address
  if (fread(eh, 4, 1, stream) < 1)
    return -1;
 
  // Set PID (not in trace)
  eh->pid = -1;

  // Read thread identifier
  if (fread(&(eh->tid), 4, 1, stream) < 1)
    return -1;

  // Read instruction size
  if (fread(&(eh->inst_size), 2, 1, stream) < 1)
    return -1;
 
  // Read num_operands and tp
  if (fread(&(eh->num_operands), 2, 1, stream) < 1)
    return -1;

  // Read eflags and cc_op
  if (fread(&(eh->eflags), 8, 1, stream) < 1)
    return -1;

  // Read df
  uint32_t df;
  if (fread(&df, 4, 1, stream) < 1)
    return -1;
  eh->df = (df == 1) ? 1 : -1;

  // Read rawbytes
  if (fread(&(eh->rawbytes), eh->inst_size, 1, stream) < 1)
    return -1;

  assert(eh->num_operands <= MAX_NUM_OPERANDS);

  // Read operands
  for (i = 0; i < eh->num_operands; i++) {
    // Read the operand tentatively into the operand array
    if (read_operand_v50(stream, &(eh->operand[count])) != 0) 
      return -1;

    // If memory addressing register, move to memreg array correct position
    switch (eh->operand[count].usage) {
      case membase:
        memcpy(&(eh->memregs[count-1][1]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memindex:
        memcpy(&(eh->memregs[count-1][2]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memsegment:
        memcpy(&(eh->memregs[count-1][0]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memsegent0:
        memcpy(&(eh->memregs[count-1][3]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memsegent1:
        memcpy(&(eh->memregs[count-1][4]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memdisplacement:
      case memscale:
      case eflags:
        fprintf(stderr, "Found invalid operand usage for trace v50\n");
        return -1;

      default:
        for (j = 0; j < MAX_NUM_MEMREGS; j++) {
          eh->memregs[count][j].type = TNone;
        }
        count++;
        break;
    }
  }

  eh->operand[count].type = TNone;

  /* Set instruction counter and increase next instruction counter */
  insn->insn_ctr = trace->trace_next_insn_ctr++;

  /* Disassemble instruction if requested */
  if (disassemble_insn) {
    xed_decoded_inst_zero_set_mode(&(insn->xed_inst), &dstate);
    xed_error_enum_t xed_error =
      xed_decode(&(insn->xed_inst), 
                  XED_STATIC_CAST(const xed_uint8_t*,(insn->eh).rawbytes),
                  MAX_INSN_BYTES);
    assert(xed_error == XED_ERROR_NONE);
  }

  return 0;
}

static int read_operand_v60(FILE * stream, operand_t * op)
{
  int i = 0;
  uint8_t float_addr;

  // Read access, length, tainted
  if (fread(op, OPERAND_VAL_FIXED_SIZE, 1, stream) != 1)
    return -1;

  // Read operand type
  if (fread(&(op->type), 1, 1, stream) != 1)
    return -1;

  // Read operand usage
  if (fread(&(op->usage), 1, 1, stream) != 1)
    return -1;

  // Nullify address and value
  memset(&(op->addr), 0, sizeof(opaddr)+sizeof(opval));

  // Read address and value
  switch(op->type) {
    /* Should not have TNone here */
    case TNone:
      return -1;
      break;

    /* Register (does not include MMX or Float registers): 
     *   Address is 1 byte
     *   Value is 4 bytes
     */
    case TRegister:
      if(fread(&(op->addr.reg_addr), 1, 1, stream) != 1)
        return -1;
      if(fread(&(op->value.val32), 4, 1, stream) != 1)
        return -1;
      break;

    /* Memory location: 
     *   Address is 4 bytes
     *   Value is 4 bytes
     */
    case TMemLoc:
      if (fread(&(op->addr.mem32_addr), 4, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.val32), 4, 1, stream) != 1)
        return -1;
      break;

    /* Immediate: 
     *   No address
     *   Value is 4 bytes
     */
    case TImmediate:
    case TDisplacement:
      if (fread(&(op->value.val32), 4, 1, stream) != 1)
        return -1;
      op->addr.mem32_addr = 0;
      break;

    /* Jump: 
     *   No address
     *   Value is 4 bytes
     */
    case TJump:
      if (fread(&(op->value.val32), 4, 1, stream) != 1)
        return -1;
      break;

    /* Float register: 
     *   Address is 1 byte
     *   Value is 10 bytes (2 bytes for exponent/sign, 8 bytes for significand)
     */
    case TFloatRegister:
      if (fread(&float_addr, 1, 1, stream) != 1)
        return -1;
      op->addr.reg_addr = 188 + (float_addr & 0xF); 
      if (fread(&(op->value.float_val.high), 2, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.float_val.low), 8, 1, stream) != 1)
        return -1;
      break;

    /* Memory address: 
     *   Address is 4 bytes
     *   Value is 4 bytes
     */
    case TMemAddress:
      if (fread(&(op->addr.mem32_addr), 4, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.val32), 4, 1, stream) != 1)
        return -1;
      break;

    /* MMX Register: 
     *   Address is 1 byte
     *   Value is 8 bytes
     */
    case TMMXRegister:
      if (fread(&(op->addr.reg_addr), 1, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.val64), 8, 1, stream) != 1)
        return -1;
      break;

    /* XMM Register: 
     *   Address is 1 byte
     *   Value is 16 bytes
     */
    case TXMMRegister:
      if (fread(&(op->addr.reg_addr), 1, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.xmm_val._q[1]), 8, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.xmm_val._q[0]), 8, 1, stream) != 1)
        return -1;
      break;

    /* Float Control Register: 
     *   Address is 1 byte
     *   Value is 4 bytes
     */
    case TFloatControlRegister:
      if (fread(&(op->addr.reg_addr), 1, 1, stream) != 1)
        return -1;
      if (fread(&(op->value.val32), 4, 1, stream) != 1)
        return -1;
      break;

    default:
      fprintf(stderr, "libtracereader: Unknown optype inside operand v60\n");
      return -1;
  }

  // Read operand taint
  assert(op->length <= MAX_OPERAND_LEN);
  for (i = 0; i < op->length; i++) {
    if (op->tainted & (1 << i)) {
      /* Read number of TaintByteRecord entries */
      fread(&(op->records[i]), TAINT_RECORD_FIXED_SIZE, 1, stream);

      /* Read TaintByteRecord array */
      assert(op->records[i].numRecords <= MAX_NUM_TAINTBYTE_RECORDS);
      fread(&(op->records[i].taintBytes), sizeof(TaintByteRecord),
            op->records[i].numRecords, stream);
    }
  }

  return 0;
}

static int read_instruction_v60(trace_interface_t * trace, x86_inst_t * insn,
                    int disassemble_insn)
{
  int i, j;
  int count = 0;

  if (!trace || !insn)
    return -1;

  entry_header_t * eh = &(insn->eh);
  FILE *stream = trace->trace_stream;

  // Read address, pid, tid, inst_size, num_operands, tp, df, eflags, cc_op
  if (fread(eh, ENTRY_HEADER_FIXED_SIZE, 1, stream) < 1)
    return -1;

  // Special return if found trailer
  if (eh->address == 0xffffffff)
    return -2;

  // Read rawbytes
  if (fread(&(eh->rawbytes), eh->inst_size, 1, stream) < 1)
    return -1;

  assert(eh->num_operands <= MAX_NUM_OPERANDS);

  // Build operand and memregs arrays
  for (i = 0; i < eh->num_operands; i++) {
    // Read the operand tentatively into the operand array
    if (read_operand_v60(stream, &(eh->operand[count])) != 0)
      return -1;

    // If memory addressing register, move to memreg array correct position
    switch (eh->operand[count].usage) {
      case membase:
        memcpy(&(eh->memregs[count-1][1]), &(eh->operand[count]), 
          sizeof(OperandVal));
        break;

      case memindex:
        memcpy(&(eh->memregs[count-1][2]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memsegment:
        memcpy(&(eh->memregs[count-1][0]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memsegent0:
        memcpy(&(eh->memregs[count-1][3]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memsegent1:
        memcpy(&(eh->memregs[count-1][4]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memdisplacement:
        memcpy(&(eh->memregs[count-1][5]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      case memscale:
        memcpy(&(eh->memregs[count-1][6]), &(eh->operand[count]),
          sizeof(OperandVal));
        break;

      default:
        for (j = 0; j < MAX_NUM_MEMREGS; j++) {
          eh->memregs[count][j].type = TNone;
        }
        count++;
        break;
    }
  }

  eh->operand[count].type = TNone;

  /* Set instruction counter and increase next instruction counter */
  insn->insn_ctr = trace->trace_next_insn_ctr++;

  /* Disassemble instruction if requested */
  if (disassemble_insn) {
    xed_decoded_inst_zero_set_mode(&(insn->xed_inst), &dstate);
    xed_error_enum_t xed_error =
      xed_decode(&(insn->xed_inst),
                  XED_STATIC_CAST(const xed_uint8_t*,(insn->eh).rawbytes),
                  MAX_INSN_BYTES);
    assert(xed_error == XED_ERROR_NONE);
  }

  return 0;
}

int trace_read_next_insn(trace_interface_t * trace, x86_inst_t * insn,
                    int disassemble_insn)
{
  if (!trace || !trace->trace_read_next_insn)
    return -1;
  return trace->trace_read_next_insn(trace, insn, disassemble_insn);
}

int trace_fold(trace_interface_t * trace, 
                unsigned long long start, unsigned long long end, 
                int restore_position, process_insn_t f, void * ctx)
{
  size_t original_next_insn_ctr;
  x86_inst_t insn;
  int err;

  if (!trace || ! f || (start > end))
    return -1;

  // Save current file position
  if (restore_position) {
    original_next_insn_ctr = trace->trace_next_insn_ctr;
  }

  // Seek start instruction
  if (err = trace_seek_insn(trace, start) != 0)
    goto finish;

  /* Loop over instructions */
  while (err = trace->trace_read_next_insn(trace, &insn, 1) == 0)
  {
    // Apply function and break if non-zero returned
    if (f(&insn, ctx) != 0) {
      break;
    }

    // If we have reached the last instruction, break loop
    if (insn.insn_ctr >= end)
      break;
  }

finish:
  // Restore original position
  if (restore_position) {
    if (trace_seek_insn(trace, original_next_insn_ctr) != 0) {
      return -1;
    }
  }

  if (err == -1)
    return -1;
  else
    return 0;
}

int trace_fold_right(trace_interface_t * trace,
                unsigned long long start, unsigned long long end,
                int restore_position, process_insn_t f, void * ctx)
{
  size_t original_next_insn_ctr;
  unsigned long long start_ctr, stop_ctr, next_insn_ctr; 
  x86_inst_t insn;

  if (!trace || !f)
    return -1;

  if (!(trace->trace_idx_stream)) {
    fprintf(stderr, "libtracereader: iterating backwards with no index.\n");
    return -1;
  }

  // If start larger than trace size, set to end of trace
  start_ctr = (start > trace->trace_num_insn) ? trace->trace_num_insn : start;

  // If end less than 1 set it to one
  stop_ctr = (end < 1) ? 1 : end;

  // Fail if stop beyond start
  if (stop_ctr > start_ctr)
    return -1;

  // Set current counter
  next_insn_ctr = start_ctr;

  // Save current file position
  if (restore_position) {
    original_next_insn_ctr = trace->trace_next_insn_ctr;
  }

  /* Loop over instructions */
  while (next_insn_ctr >= stop_ctr) {
    // Seek instruction
    if (trace_seek_insn(trace, next_insn_ctr) != 0) {
      return -1;
    }

    // Read instruction
    if (trace->trace_read_next_insn(trace, &insn, 1) != 0) {
      return -1;
    }

    // Apply function and break if non-zero returned
    if (f(&insn, ctx) != 0) {
      break;
    }

    // Decrease counter
    next_insn_ctr--;
  }

  // Restore original position
  if (restore_position) {
    if (trace_seek_insn(trace, original_next_insn_ctr) != 0) {
      return -1;
    }
  }

  return 0;
}

