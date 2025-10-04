#include "afl-fuzz.h"
#include "afl-mutations.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> 
#include <string.h>
#include <keystone/keystone.h>
#include <capstone/capstone.h>
#include <stdbool.h>


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

  if ((data->buf = malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init alloc");
    return NULL;

  } else {

    data->buf_size = MAX_FILE;

  }

  data->afl = afl;

  return data;

}
const char *arm64_instruction_templates[] = {
    "add x%d, x%d, x%d",
    "adds x%d, x%d, x%d",
    "sub x%d, x%d, x%d",
    "subs x%d, x%d, x%d",
    "add w%d, w%d, w%d",
    "sub w%d, w%d, w%d",
    "subs w%d, w%d, w%d",
    "and x%d, x%d, x%d",
    "orr x%d, x%d, x%d",
    "eor x%d, x%d, x%d",
    "add x%d, x%d, #%d",
    "adds x%d, x%d, #%d",
    "add w%d, w%d, #%d",
    "add w%d, w%d, w%d",
    "adds w%d, w%d, #%d",
    "adds w%d, w%d, w%d",
    "sub x%d, x%d, #%d",
    "sub w%d, w%d, #%d",
    "subs x%d, x%d, #%d",
    "subs w%d, w%d, #%d",
    "mul x%d, x%d, x%d",
    "mul w%d, w%d, w%d",
    "movz x%d, #%d",
    "movk x%d, #%d",
    "movk w%d, #%d",
    "movz w%d, #%d",
    "mov w%d, #%d",
    "mov x%d, #%d",
    "cmp x%d, #%d",
    "cmp w%d, #%d",
    "cmp x%d, x%d",
    "cmp w%d, w%d",
    "cmn x%d, #%d",
    "cmn x%d, x%d",
    "cmn w%d, w%d",
    "cmn w%d, #%d",
    "tst x%d, x%d",
    "tst w%d, w%d"
    };

uint32_t generate_random_instruction() {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;

    // Choose a random instruction template
    const char *template = arm64_instruction_templates[rand() % 
        (sizeof(arm64_instruction_templates) / sizeof(char*))];
    
    // Generate random registers and immediate
    int reg1 = rand() % 30;
    int reg2 = rand() % 30;
    int reg3 = rand() % 30;
    int imm = rand() %0x1000;  
    uint32_t nop_instruction = 0xD503201F;

    char instruction[128];

    snprintf(instruction, sizeof(instruction), template, reg1, reg2, (strstr(template, "#%d") ? imm : reg3));
    
    err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        ks_free(encode);
        return nop_instruction;
    }

    // Assemble instruction
    if (ks_asm(ks, instruction, 0, &encode, &size, &count) != KS_ERR_OK) {
        fprintf(stderr, "Error assembling instruction: %s\n", instruction);
        ks_free(encode);
        ks_close(ks);
        return nop_instruction;
    }

    // Extract 32-bit instruction
    uint32_t hex_instruction = 0;
    for (int i = 0; i < 4 && i < size; i++) {
        hex_instruction |= (encode[i] << (i * 8));
    }

    // Free resources
    ks_free(encode);
    ks_close(ks);

    return hex_instruction;
}


uint32_t disassemble() {
    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return 0xD503201F;
    }
    uint32_t instruction =rand();
    uint8_t instruction_bytes[4];
    memcpy(instruction_bytes, &instruction, sizeof(uint32_t));
    count = cs_disasm(handle, instruction_bytes, 4, 0x1000, 0, &insn);
    if (count > 0) {
        if (insn->id >= ARM64_INS_B && insn->id <= ARM64_INS_BL) {
          cs_free(insn, count);
          cs_close(&handle);
          return disassemble(); // Set instruction to NOP if it's a branch
        }
        cs_free(insn, count);
        cs_close(&handle);
        return instruction;
    } else{
      cs_free(insn, count);
      cs_close(&handle);
      return disassemble();
    }
  }


size_t begin_offset(){
  FILE *file = fopen("/home/alisher/arm_sim_fuzz/armshaker/algo.txt", "r");
  size_t hexValue;
  if(file == NULL) {
    return 0;
  } else{
    if (fscanf(file, "%zx", &hexValue) != 1) {
        fprintf(stderr, "Error reading the first hexadecimal value\n");
        fclose(file);
        return 0;
    }
    fclose(file);
    return hexValue;
  }
}

bool filesAreDifferent() {
    FILE *f1, *f2;
    int ch1, ch2;
    char *file1 = "/home/alisher/arm_sim_fuzz/armshaker/.cur_input";
    char *file2 = "/home/alisher/arm_sim_fuzz/output/default/.cur_input";
    f1 = fopen(file1, "rb");
    if (f1 == NULL ) {
        perror("Error opening first file");
        return true; 
    }
    f2 = fopen(file2, "rb");
    if ( f2 == NULL) {
        perror("Error opening second file");
        fclose(f1);
        return true; 
    }
    do {
        ch1 = fgetc(f1);
        ch2 = fgetc(f2);
        if (ch1 != ch2) {
            fclose(f1);
            fclose(f2);
            return true; 
        }
    } while (ch1 != EOF && ch2 != EOF);
    fclose(f1);
    fclose(f2);
    return (ch1 != EOF || ch2 != EOF);
}

size_t collect_values_after_hex(uint8_t *buffer, size_t buffer_size) {
    FILE *fptr;
    char *file_path="/home/alisher/arm_sim_fuzz/armshaker/algo.txt";
    size_t bytesRead = 0;
    unsigned int value;

    fptr = fopen(file_path, "r");
    if (fptr == NULL) {
        perror("Error opening file");
        return 0;
    }

    // Skip the first hexadecimal value
    if (fscanf(fptr, "%x", &value) != 1) {
        fprintf(stderr, "Error reading the first hexadecimal value\n");
        fclose(fptr);
        return 0;
    }
    while (fscanf(fptr, "%x", &value) == 1 && bytesRead < buffer_size) {
        buffer[bytesRead++] = (uint8_t)value; 
    }

    fclose(fptr);
    return bytesRead;
}

void copy_and_overwrite() {
    FILE *source, *destination;
    char buffer[1024];
    size_t bytesRead;
    char *file1 = "/home/alisher/arm_sim_fuzz/armshaker/.cur_input";
    char *file2 = "/home/alisher/arm_sim_fuzz/output/default/.cur_input";
    source = fopen(file2, "rb");
    if (source == NULL) {
        perror("Error opening source file");
        return;
    }
    destination = fopen(file1, "wb");
    if (destination == NULL) {
        perror("Error opening destination file");
        fclose(source);
        return;
    }
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        if (fwrite(buffer, 1, bytesRead, destination) != bytesRead) {
            perror("Error writing to destination file");
            fclose(source);
            fclose(destination);
            return;
        }
    }
    // Close both files
    fclose(source);
    fclose(destination);
}
const size_t start_offset = 0x200;
const size_t end_offset = 0x4ac;

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
    memcpy(data->buf, buf, buf_size);
    uint32_t inst;
    size_t begin_off = begin_offset();
    if (begin_off == 0){
      copy_and_overwrite();
      FILE *fptr;
      fptr = fopen("/home/alisher/arm_sim_fuzz/armshaker/algo.txt", "w");
      size_t off = (end_offset-start_offset)/10;
      fprintf(fptr, "0x%lX\n", off);
      fprintf(fptr, "\n");
      inst = 0xD503201F;
      for (size_t i = start_offset; i < end_offset; i = i + 0x4) {
        fprintf(fptr, "0x%02X ", data->buf[i]);
        fprintf(fptr, "0x%02X ", data->buf[i+1]);
        fprintf(fptr, "0x%02X ", data->buf[i+2]);
        fprintf(fptr, "0x%02X ", data->buf[i+3]);
        if(i>=start_offset+off){
          data->buf[i] = inst & 0xFF;
          data->buf[i+1] = (inst >> 8) & 0xFF;
          data->buf[i+2] = (inst >> 16) & 0xFF;
          data->buf[i+3] = (inst >> 24) & 0xFF;
        }else{
          
        }
      }
      fprintf(fptr, "\n");
      fclose(fptr);
    } else if(start_offset+begin_off >= end_offset){
        FILE *fptr;
        fptr = fopen("/home/alisher/arm_sim_fuzz/armshaker/algo.txt", "w");
        fprintf(fptr, "0x%X\n", 0x0);
        fprintf(fptr, "\n");
        for (size_t i = start_offset; i < end_offset; i = i + 0x4) {
        if(rand()%2){
        inst = generate_random_instruction();
        data->buf[i] = inst & 0xFF;
        data->buf[i+1] = (inst >> 8) & 0xFF;
        data->buf[i+2] = (inst >> 16) & 0xFF;
        data->buf[i+3] = (inst >> 24) & 0xFF;
        } else if(rand()%50<=20){
          inst = 0xD503201F;
          data->buf[i] = inst & 0xFF;
          data->buf[i+1] = (inst >> 8) & 0xFF;
          data->buf[i+2] = (inst >> 16) & 0xFF;
          data->buf[i+3] = (inst >> 24) & 0xFF;
        } else if(rand()%50<=1){
          inst = 0xd65f03c0;
          data->buf[i] = inst & 0xFF;
          data->buf[i+1] = (inst >> 8) & 0xFF;
          data->buf[i+2] = (inst >> 16) & 0xFF;
          data->buf[i+3] = (inst >> 24) & 0xFF;
        } else if(rand()%2) {
          inst = disassemble(inst);
          data->buf[i] = inst & 0xFF;
          data->buf[i+1] = (inst >> 8) & 0xFF;
          data->buf[i+2] = (inst >> 16) & 0xFF;
          data->buf[i+3] = (inst >> 24) & 0xFF;
        }
        fprintf(fptr, "0x%02X ", data->buf[i]);
        fprintf(fptr, "0x%02X ", data->buf[i+1]);
        fprintf(fptr, "0x%02X ", data->buf[i+2]);
        fprintf(fptr, "0x%02X ", data->buf[i+3]);
      }
      fclose(fptr);
    } else {
      if(filesAreDifferent()){
        FILE *fptr;
        uint8_t buffer[1024];
        collect_values_after_hex(buffer,1024);
        fptr = fopen("/home/alisher/arm_sim_fuzz/armshaker/algo.txt", "w");
        size_t off = (end_offset-start_offset)/10 + begin_off;
        fprintf(fptr, "0x%lX\n", off);
        fprintf(fptr, "\n");
        size_t j=0;
        for (size_t i = start_offset; i < end_offset; i = i + 0x4) {
          fprintf(fptr, "0x%02X ", buffer[j]);
          fprintf(fptr, "0x%02X ", buffer[j+1]);
          fprintf(fptr, "0x%02X ", buffer[j+2]);
          fprintf(fptr, "0x%02X ", buffer[j+3]);
          if(i< start_offset+off){
            data->buf[i] = buffer[j];
            data->buf[i+1] = buffer[j+1];
            data->buf[i+2] = buffer[j+2];
            data->buf[i+3] = buffer[j+3];
          }else{
            inst = 0xD503201F;
            data->buf[i] = inst & 0xFF;
            data->buf[i+1] = (inst >> 8) & 0xFF;
            data->buf[i+2] = (inst >> 16) & 0xFF;
            data->buf[i+3] = (inst >> 24) & 0xFF;
          }
          j = j+0x4;
        }
      } else  {
        FILE *fptr;
        uint8_t buffer[1024];
        collect_values_after_hex(buffer,1024);
        fptr = fopen("/home/alisher/arm_sim_fuzz/armshaker/algo.txt", "w");
        fprintf(fptr, "0x%X\n", 0x0);
        fprintf(fptr, "\n");
        size_t j=0;
        for (size_t i = start_offset+begin_off; i < end_offset; i = i + 0x4) {
          
          if (i<start_offset+begin_off){
            fprintf(fptr, "0x%02X ", buffer[j]);
            fprintf(fptr, "0x%02X ", buffer[j+1]);
            fprintf(fptr, "0x%02X ", buffer[j+2]);
            fprintf(fptr, "0x%02X ", buffer[j+3]);
            data->buf[i] = buffer[j];
            data->buf[i+1] = buffer[j+1];
            data->buf[i+2] = buffer[j+2];
            data->buf[i+3] = buffer[j+3];
            j = j+0x4;
          } else{
          if(rand()%2){
            inst = generate_random_instruction();
            data->buf[i] = inst & 0xFF;
            data->buf[i+1] = (inst >> 8) & 0xFF;
            data->buf[i+2] = (inst >> 16) & 0xFF;
            data->buf[i+3] = (inst >> 24) & 0xFF;
          } else if(rand()%50<=20){
            inst = 0xD503201F;
            data->buf[i] = inst & 0xFF;
            data->buf[i+1] = (inst >> 8) & 0xFF;
            data->buf[i+2] = (inst >> 16) & 0xFF;
            data->buf[i+3] = (inst >> 24) & 0xFF;
          } else if(rand()%50<=1){
            inst = 0xd65f03c0;
            data->buf[i] = inst & 0xFF;
            data->buf[i+1] = (inst >> 8) & 0xFF;
            data->buf[i+2] = (inst >> 16) & 0xFF;
            data->buf[i+3] = (inst >> 24) & 0xFF;
          } else if(rand()%2) {
            inst = disassemble(inst);
            data->buf[i] = inst & 0xFF;
            data->buf[i+1] = (inst >> 8) & 0xFF;
            data->buf[i+2] = (inst >> 16) & 0xFF;
            data->buf[i+3] = (inst >> 24) & 0xFF;
          }
          fprintf(fptr, "0x%02X ", data->buf[i]);
          fprintf(fptr, "0x%02X ", data->buf[i+1]);
          fprintf(fptr, "0x%02X ", data->buf[i+2]);
          fprintf(fptr, "0x%02X ", data->buf[i+3]);
        }
        }
        fclose(fptr);
      }
    }
    *out_buf = data->buf;
    return buf_size;
  }


/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->buf);
  free(data);

}

