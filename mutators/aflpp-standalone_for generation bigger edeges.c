#include "afl-fuzz.h"
#include "afl-mutations.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>

typedef struct my_mutator {

  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)seed;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->buf = malloc(1024*1024)) == NULL) {

    perror("afl_custom_init alloc");
    return NULL;

  } else {

    data->buf_size = 1024*1024;

  }

  /* fake AFL++ state */
  data->afl = calloc(1, sizeof(afl_state_t));
  data->afl->queue_cycle = 1;
  data->afl->fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (data->afl->fsrv.dev_urandom_fd < 0) { PFATAL("Unable to open /dev/urandom"); }
  rand_set_seed(data->afl, getpid());

  return data;

}
#define BUFFER_SIZE 4096  // Size of the buffer for copying

int copy_file(const char *src_filename, const char *dst_filename) {
    FILE *src_file, *dst_file;
    char buffer[BUFFER_SIZE];
    size_t bytes_read, bytes_written;
    src_file = fopen(src_filename, "rb");
    if (src_file == NULL) {
        perror("Error opening source file");
        return 1;
    }
    dst_file = fopen(dst_filename, "wb");
    if (dst_file == NULL) {
        perror("Error opening destination file");
        fclose(src_file);
        return 2;
    }    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, src_file)) > 0) {
        bytes_written = fwrite(buffer, 1, bytes_read, dst_file);
        if (bytes_written != bytes_read) {
            perror("Error writing to destination file");
            fclose(src_file);
            fclose(dst_file);
            return 3;
        }
    }
    fclose(src_file);
    fclose(dst_file);
    return 0;
}

int compare_files(const char *filename1, const char *filename2) {
    FILE *file1, *file2;
    int byte1, byte2;
    int result = 0;  // 0 means files are identical, 1 means files are different

    file1 = fopen(filename1, "rb");
    if (file1 == NULL) {
        perror("Error opening first file");
        return 1;
    }
    file2 = fopen(filename2, "rb");
    if (file2 == NULL) {
        perror("Error opening second file");
        fclose(file1);
        return 2;
    }
    do {
        byte1 = fgetc(file1);
        byte2 = fgetc(file2);
        if (byte1 != byte2) {
            result = 1;  
            break;
        }
    } while (byte1 != EOF && byte2 != EOF);
    if (byte1 != byte2) {
        result = 1;  
    }
    fclose(file1);
    fclose(file2);

    return result;
}

uint32_t disassemble() {

    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return;
    }
    
    while(true){
    uint32_t instruction =rand();
    uint8_t instruction_bytes[4];
    memcpy(instruction_bytes, &instruction, sizeof(uint32_t));
    count = cs_disasm(handle, instruction_bytes, 4, 0x1000, 0, &insn);
    if (count > 0) {
        cs_free(insn, count);
        cs_close(&handle);
        return instruction;
    } 
     memset(instruction_bytes, 0, sizeof(instruction_bytes));
    }
    
}
const  size_t start_offset = 0xd0;
const  size_t end_offset = 0x118;
const uint32_t nop = 0x1F2003D5;
uint8_t saved [4];
bool checked = false;
size_t check_start_offset = 0xd0;
size_t check_end_offset = 0xd4;
size_t top = 0xd4;
size_t bottom = 0xd4;
bool forward = true;
bool backward = false;
int nochange = 0;
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    const char *src_filename = "/home/alisher/arm_sim_fuzz/output_raspi3b/default/fuzz_bitmap";
    const char *dst_filename = "copy_bitmap";
    memcpy(data->buf, buf, buf_size);
    if((top == start_offset&&bottom == end_offset)|| nochange > 100){
      FILE *fp = fopen(dst_filename, "w");
      fclose(fp);
      uint32_t inst;
      bottom = 0xd4;
      forward = true;
      backward = false;
      for (size_t i = start_offset; i < end_offset; i = i + 0x4) {
        inst = disassemble();
        data->buf[i] = inst & 0xFF;
        data->buf[i+1] = (inst >> 8) & 0xFF;
        data->buf[i+2] = (inst >> 16) & 0xFF;
        data->buf[i+3] = (inst >> 24) & 0xFF;
      }
    }
    if((compare_files(src_filename, dst_filename)==1)){
     forward = true;
     copy_file(src_filename, dst_filename);
     nochange = 0;
    } else if ((compare_files(src_filename, dst_filename)==0) && (forward == true)){
      for (size_t i = check_start_offset; i < check_end_offset; i = i + 0x4) {
        saved[0]=data->buf[i];
        saved[1]=data->buf[i+1];
        saved[2]=data->buf[i+2];
        saved[3]=data->buf[i+3];
        data->buf[i] = nop & 0xFF;
        data->buf[i+1] = (nop >> 8) & 0xFF;
        data->buf[i+2] = (nop >> 16) & 0xFF;
        data->buf[i+3] = (nop >> 24) & 0xFF;
      }
      check_end_offset+=0x4;
    } else if ((compare_files(src_filename, dst_filename)==1) && (forward == true)){
      check_end_offset-=0x8;
      for (size_t i = check_start_offset; i < check_end_offset; i = i + 0x4) {
        data->buf[i] = nop & 0xFF;
        data->buf[i+1] = (nop >> 8) & 0xFF;
        data->buf[i+2] = (nop >> 16) & 0xFF;
        data->buf[i+3] = (nop >> 24) & 0xFF;
      }
      data->buf[check_end_offset]=saved[0];
      data->buf[check_end_offset+1]=saved[1];
      data->buf[check_end_offset+2]=saved[2];
      data->buf[check_end_offset+3]=saved[3];
      forward = false;
      backward = true;
      top = check_end_offset+0x4;
      check_end_offset=end_offset;
      check_start_offset= check_end_offset -0x4;

    } else if ((compare_files(src_filename, dst_filename)==0)&&(backward == true)){
      for (size_t i = check_start_offset; i < check_end_offset; i = i + 0x4) {
        saved[0]=data->buf[i];
        saved[1]=data->buf[i+1];
        saved[2]=data->buf[i+2];
        saved[3]=data->buf[i+3];
        data->buf[i] = nop & 0xFF;
        data->buf[i+1] = (nop >> 8) & 0xFF;
        data->buf[i+2] = (nop >> 16) & 0xFF;
        data->buf[i+3] = (nop >> 24) & 0xFF;
      }
      check_start_offset-=0x4;
    } else if ((compare_files(src_filename, dst_filename)==1) && backward){
      check_start_offset+=0x8;
      for (size_t i = check_start_offset; i < check_end_offset; i = i + 0x4) {
        data->buf[i] = nop & 0xFF;
        data->buf[i+1] = (nop >> 8) & 0xFF;
        data->buf[i+2] = (nop >> 16) & 0xFF;
        data->buf[i+3] = (nop >> 24) & 0xFF;
      }
      data->buf[check_start_offset-4]=saved[0];
      data->buf[check_start_offset-3]=saved[1];
      data->buf[check_start_offset-2]=saved[2];
      data->buf[check_start_offset-1]=saved[3];
      bottom = check_start_offset-0x4;
      check_end_offset=start_offset +0x4;
      check_start_offset= start_offset;
      backward = false;
    } else if (!backward && !forward && checked){
      uint32_t inst;
      for (size_t i = start_offset; i < top; i = i + 0x4) {
        inst = disassemble();
        data->buf[i] = inst & 0xFF;
        data->buf[i+1] = (inst >> 8) & 0xFF;
        data->buf[i+2] = (inst >> 16) & 0xFF;
        data->buf[i+3] = (inst >> 24) & 0xFF;
      }
      for (size_t i = bottom; i < end_offset; i = i + 0x4) {
        inst = disassemble();
        data->buf[i] = inst & 0xFF;
        data->buf[i+1] = (inst >> 8) & 0xFF;
        data->buf[i+2] = (inst >> 16) & 0xFF;
        data->buf[i+3] = (inst >> 24) & 0xFF;
      }
      nochange++;
    }
                
    memcpy(data->buf, buf, buf_size);
    *out_buf = data->buf;
    return buf_size;
}
int main(int argc, char *argv[]) {

  if (argc > 1 && strncmp(argv[1], "-h", 2) == 0) {
    printf("Syntax: %s [-v] [inputfile [outputfile [splicefile]]]\n\n", argv[0]);
    printf("Reads a testcase from stdin when no input file (or '-') is specified,\n");
    printf("mutates according to AFL++'s mutation engine, and write to stdout when '-' or\n");
    printf("no output filename is given. As an optional third parameter you can give a file\n");
    printf("for splicing. Maximum input and output length is 1MB.\n");
    printf("The -v verbose option prints debug output to stderr.\n");
    return 0;
  }

  FILE *in = stdin, *out = stdout, *splice = NULL;
  unsigned char *inbuf = malloc(1024 * 1024), *outbuf, *splicebuf = NULL;
  int verbose = 0, splicelen = 0;

  if (argc > 1 && strcmp(argv[1], "-v") == 0) {
    verbose = 1;
    argc--;
    argv++;
    fprintf(stderr, "Verbose active\n");
  }

  my_mutator_t *data = afl_custom_init(NULL, 0);

  if (argc > 1 && strcmp(argv[1], "-") != 0) {
    if ((in = fopen(argv[1], "r")) == NULL) {
      perror(argv[1]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Input: %s\n", argv[1]);
  }

  size_t inlen = fread(inbuf, 1, 1024*1024, in);
  
  if (!inlen) {
    fprintf(stderr, "Error: empty file %s\n", argv[1] ? argv[1] : "stdin");
    return -1;
  }

  if (argc > 2 && strcmp(argv[2], "-") != 0) {
    if ((out = fopen(argv[2], "w")) == NULL) {
      perror(argv[2]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Output: %s\n", argv[2]);
  }

  if (argc > 3) {
    if ((splice = fopen(argv[3], "r")) == NULL) {
      perror(argv[3]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Splice: %s\n", argv[3]);
    splicebuf = malloc(1024*1024);
    size_t splicelen = fread(splicebuf, 1, 1024*1024, splice);
    if (!splicelen) {
      fprintf(stderr, "Error: empty file %s\n", argv[3]);
      return -1;
    }
    if (verbose) fprintf(stderr, "Mutation splice length: %zu\n", splicelen);
  }

  if (verbose) fprintf(stderr, "Mutation input length: %zu\n", inlen);
  unsigned int outlen = afl_custom_fuzz(data, inbuf, inlen, &outbuf, splicebuf, splicelen, 1024*1024);

  if (outlen == 0 || !outbuf) {
    fprintf(stderr, "Error: no mutation data returned.\n");
    return -1;
  }

  if (verbose) fprintf(stderr, "Mutation output length: %u\n", outlen);

  if (fwrite(outbuf, 1, outlen, out) != outlen) {
    fprintf(stderr, "Warning: incomplete write.\n");
    return -1;
  }
  
  return 0;
}