#include <windows.h>
#include <iostream>
#include <cstdlib>
#include <cstring>

int main() {
    void* exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    unsigned char payload[] = {
        0x90,  // NOP
        0x90,  // NOP
        0xcc,  // INT3
        0xc3   // RET
    };
    unsigned int payload_len = sizeof(payload);

    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
    printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

    RtlMoveMemory(exec_mem, payload, payload_len);

    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    std::cout << "Press Enter to execute payload\n";
    std::cin.get();

    if (rv != 0) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        WaitForSingleObject(th, INFINITE);
    } else {
        std::cout << "Failed to execute payload\n";
    }

    //return 0;
}