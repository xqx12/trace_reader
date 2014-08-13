/* 
 *  a tool to read an execution trace and output its information
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
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <xed-interface.h>
#include <trace60.h>
#include <trace_interface.h>
#include <trace_print.h>

#define OUTPUT_BUF 1024*1024*4

/* How often to report on trace progress */
#define PROGRESS_GAP 100000

/* Maximum file path length */
#define MAX_FILE_PATH_SIZE 128

static FILE * out_stream;
static char trace_file[MAX_FILE_PATH_SIZE] = {0};
static char output_file[MAX_FILE_PATH_SIZE] = {0};
static char outbuf[OUTPUT_BUF] = {0};
static int create_index = 0;
static int intel_format = 0;
static int print_header = 0;
static int print_counter = 0;
static int verbose = 0;
static unsigned long long last = ULLONG_MAX;
static unsigned long long first = 1LL;

void print_usage() {
  fprintf(stderr, "Usage: trace_creader\n"
                  "  -count <> Display instruction counter\n"
                  "  -createindex <> Create trace index (no other output)\n"
                  "  -first <int64> First instruction to read\n"
                  "  -header <> Print trace header information and exit\n"
                  "  -intel <> Use intel format insted of ATT\n"
                  "  -last <int64> Last instruction to read\n"
                  "  -out <string> Output file (default is stdout)\n"
                  "  -trace <string> Name of input trace file\n"
                  "  -v <> Verbose. Prints more info per instruction\n"
                  "\n"
  );
}

/* Function to apply to all instruction that need printing */
int process_insn(x86_inst_t * insn, void * ctx) {
  trace_interface_t * trace = (trace_interface_t *) ctx;
  /* Print analysis progress */
  if ((insn->insn_ctr % PROGRESS_GAP) == 0) {
    int percent = (trace_get_curr_filepos(trace) * 101) /
                    trace->trace_byte_size;
    print_percent(stderr, percent);
  }

  /* Print instruction */
  print_insn(out_stream, insn, intel_format, verbose, print_counter);

  return 0;
}


int main(int argc, char ** argv)
{
  int opt = -1;
  int long_index =0;
  char *endptr = NULL;
  size_t len;

  static struct option long_options[] =
  {
    {"count",       no_argument,   0, 'c'},
    {"createindex", no_argument,   0, 'd'},
    {"first",   required_argument, 0, 'f'},
    {"header",  no_argument,       0, 'h'},
    {"intel",   no_argument,       0, 'i'},
    {"last",    required_argument, 0, 'l'},
    {"out",     required_argument, 0, 'o'},
    {"trace",   required_argument, 0, 't'},
    {"verbose", no_argument,       0, 'v'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long_only(argc, argv, "", 
                   long_options, &long_index )) != -1) 
  {
    switch (opt) {
      case 'c':
        print_counter = 1;
        break;
      case 'd':
        create_index = 1;
        break;
      case 'f':
        first = strtoull(optarg, &endptr, 0);
        len = strlen(optarg);
        if (endptr != optarg + len) {
          fprintf(stderr, "error : invalid -first <int64> argument.\n");
          return -1;
        }
        break;
      case 'h':
        print_header = 1;
        break;
      case 'i':
        intel_format = 1;
        break;
      case 'l':
        last = strtoull(optarg, &endptr, 0);
        len = strlen(optarg);
        if (endptr != optarg + len) {
          fprintf(stderr, "error : invalid -last <int64> argument.\n");
          return -1;
        }
        break;
      case 'o':
        sprintf(output_file, "%s", optarg);
        break;
      case 't':
        sprintf(trace_file, "%s", optarg);
        break;
      case 'v':
        verbose = 1;
        break;
      default: 
        print_usage(); 
        return -1;
    }
  }

  if(trace_file[0] == 0) {
    fprintf(stderr, "Usage: %s [-i] -t [trace file] -o [ouput file]\n", 
                    argv[0]);
    return -1;
  }
  if(output_file[0] != 0 && (out_stream = fopen(output_file, "w")) == NULL) {
    fprintf(stderr, "error : output file not accessible.\n");
    return -1;
  }
  if(out_stream == NULL) {
    out_stream = stdout;
  }

  setbuf(out_stream, outbuf);

  /* If create index requested, loop over instructions and exit */
  if (create_index) {
    return trace_create_index(trace_file);
  }

  /* Open trace */
  trace_interface_t * trace_iface = trace_open(trace_file);
  if (trace_iface == NULL) {
    return -1;
  }

  /* If requested, print header and exit */
  if (print_header) {
    print_trace_header(stdout, trace_iface, verbose);
    goto cleanup;
  }

  /* Loop over instructions */
  trace_fold(trace_iface, first, last, 0, process_insn, trace_iface);

  /* Update progress */
  print_percent(stderr, 100);

cleanup:
  /* Close files */
  trace_close(trace_iface);
  fclose(out_stream);

  return 0;
}

