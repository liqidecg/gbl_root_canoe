#include <cstdio>
#include <cstdlib>
#include <cstring>
int read_file(const char* filename, unsigned char** data, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return -1; // Failed to open file
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *data = new unsigned char[*size];
    if (fread(*data, 1, *size, file) != *size) {
        delete[] *data;
        fclose(file);
        return -1; // Failed to read file
    }

    fclose(file);
    return 0; // Success
}
int patch_abl_gbl(char* buffer, size_t size) {
    // Example patch: Replace "Hello" with "World"
    char target[] = "e\0f\0i\0s\0p";
    char replacement[] = "n\0u\0l\0l\0s";

    //find the target string in the buffer
    for (size_t i = 0; i < size - sizeof(target); ++i) {
        if (memcmp(buffer + i, target, sizeof(target)) == 0) {
            memcpy(buffer + i, replacement, sizeof(replacement));
            return 0; // Patch applied successfully』
        }
    }
    return -1; // Target string not found
}
/*
?? 00 00 34 28 00 80 52
06 00 00 14 E8 ?? 40 F9
08 01 40 39 1F 01 00 71
E8 07 9F 1A 08 79 1F 53
*/
int16_t Original[]={
    -1,0x00,0x00,0x34,0x28,0x00,0x80,0x52,
    0x06,0x00,0x00,0x14,0xE8,-1,0x40,0xF9,
    0x08,0x01,0x40,0x39,0x1F,0x01,0x00,0x71,
    0xE8,0x07,0x9F,0x1A,0x08,0x79,0x1F,0x53
};
int16_t Patched[]={
    -1,-1,-1,-1,0x08,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1
};

/**
 * @return 成功修补的位点数，0 表示未找到任何匹配
 */
int patch_abl_bootstate(char* buffer, size_t size) {
    size_t pattern_len = sizeof(Original) / sizeof(int16_t);
    int patched_count = 0;

    if (size < pattern_len) return 0;

    for (size_t i = 0; i <= size - pattern_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; ++j) {
            if (Original[j] != -1 &&
                (unsigned char)buffer[i + j] != (unsigned char)Original[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            for (size_t j = 0; j < pattern_len; ++j) {
                if (Patched[j] != -1) {
                    buffer[i + j] = (char)Patched[j];
                }
            }
            patched_count++;
            i += pattern_len - 1; // 跳过已修补区域，避免重叠匹配
        }
    }
    return patched_count;
}
/*
?? 04 80 52 ?? 4F 40 F9
?? ?? 00 90 F7 ?? ?? 91
?? 03 01 39 
*/
int16_t Original_lock_state[]={
    -1,0x04,0x80,0x52,-1,0x4F,0x40,0xF9,
    -1,-1,0x00,0x90,0xF7,-1,-1,0x91,
    -1,0x03,0x01,0x39
};
int16_t Patched_lock_state[]={
    -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,
    0xFF,-1,-1,-1
};
int patch_abl_lock_state(char* buffer, size_t size, int8_t *lock_register_num,int* offset) {
    size_t pattern_len = sizeof(Original_lock_state) / sizeof(int16_t);
    int patched_count = 0;

    if (size < pattern_len) return 0;

    for (size_t i = 0; i <= size - pattern_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; ++j) {
            if (Original_lock_state[j] != -1 &&
                (unsigned char)buffer[i + j] != (unsigned char)Original_lock_state[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            *offset = i;
            for (size_t j = 0; j < pattern_len; ++j) {
                if (Patched_lock_state[j] != -1) {

                    *lock_register_num = buffer[i + j]; // 记录锁状态寄存器的值
                    buffer[i + j] = (char)Patched_lock_state[j];
                }
            }
            patched_count++;
            i += pattern_len - 1; // 跳过已修补区域，避免重叠匹配
        }
    }
    // 如果未找到匹配，重置偏移量
    return patched_count;
}
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
bool is_ldrb(const char* buffer, size_t offset) {
    uint32_t instr =
        (uint8_t)buffer[offset]                  |
        ((uint8_t)buffer[offset + 1] << 8)       |
        ((uint8_t)buffer[offset + 2] << 16)      |
        ((uint8_t)buffer[offset + 3] << 24);

    return (instr & 0xFFC00000) == 0x39400000;
}
int8_t dump_register_from_LDRB(const char* instr) {
    int8_t first_byte = (int8_t)instr[0]; // 指令第一个字节（小端序）
    int8_t rt = first_byte & 0x1F;
    return (int8_t)rt; // 返回寄存器编号
}
int find_ldrB_instructio_reverse(char* buffer, size_t size, int8_t target_register) {
    int now_offset = size - 4; // 从最后一个指令开始检查
    while(1){
        if (is_ldrb(buffer , now_offset)) {

            if (dump_register_from_LDRB(buffer + now_offset) == target_register) { // 检查是否是访问 WZR/XZR 寄存器
                //MOV WXX #1
                printf("Found LDRB instruction at offset: 0x%X\n", now_offset);
                printf("Instruction bytes: %02X %02X %02X %02X\n", (unsigned char)buffer[now_offset], (unsigned char)buffer[now_offset + 1], (unsigned char)buffer[now_offset + 2], (unsigned char)buffer[now_offset + 3]); 
                uint32_t mov_inst = 0x52800020 | (uint8_t)target_register;

                // 小端序写入
                buffer[now_offset + 0] = (char)(mov_inst & 0xFF);
                buffer[now_offset + 1] = (char)((mov_inst >> 8) & 0xFF);
                buffer[now_offset + 2] = (char)((mov_inst >> 16) & 0xFF);
                buffer[now_offset + 3] = (char)((mov_inst >> 24) & 0xFF);
                printf("Instruction bytes: %02X %02X %02X %02X\n", (unsigned char)buffer[now_offset], (unsigned char)buffer[now_offset + 1], (unsigned char)buffer[now_offset + 2], (unsigned char)buffer[now_offset + 3]); 

                return 0; // 找到目标 LDRB 指令，返回其偏移
            }
        }
        now_offset -= 4; // ARM指令长度为4字节
    }
    return -1; // 未找到LDRB指令
}
int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned char* data = nullptr;
    size_t size = 0;

    if (read_file(argv[1], &data, &size) != 0) {
        printf("Failed to read file: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    if (patch_abl_gbl((char*)data, size) != 0) {
        printf("Failed to patch ABL GBL\n");
        delete[] data;
        return EXIT_FAILURE;
    }
    int num_patches = patch_abl_bootstate((char*)data, size);
     if (num_patches == 0) {
        printf("Failed to patch ABL Boot State\n");
        delete[] data;
        return EXIT_FAILURE;
    }
    printf("Patching completed successfully.\n");
    printf("Number of Boot State patches applied: %d\n", num_patches);
    int8_t lock_register_num = -1;
    int offset = -1;
    num_patches = patch_abl_lock_state((char*)data, size, &lock_register_num, &offset);
     if (num_patches == 0) {
        printf("Failed to patch ABL Lock State\n");
        delete[] data;
        return EXIT_FAILURE;
    }
    printf("Number of Lock State patches applied: %d\n", num_patches);
    //remove LSB to get the lock register number
    lock_register_num = lock_register_num & 0x1F;
    printf("Original lock register number W%d\n", (int)lock_register_num);
    if (find_ldrB_instructio_reverse((char*)data, offset, lock_register_num) != 0) {
        printf("Failed to find LDRB instruction accessing W%d\n", (int)lock_register_num);
        delete[] data;
        return EXIT_FAILURE;
    }
    FILE* output_file = fopen(argv[2], "wb");
    if (!output_file) {
        printf("Failed to open output file: %s\n", argv[2]);
        delete[] data;
        return EXIT_FAILURE;
    }

    fwrite(data, 1, size, output_file);
    fclose(output_file);
    delete[] data;

    printf("Patch applied successfully and saved to %s\n", argv[2]);
    return EXIT_SUCCESS;
}
