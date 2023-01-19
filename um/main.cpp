#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "driver.hpp"

uint64_t get_tick_count64() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (ts.tv_sec*1000 + ts.tv_nsec/(1000*1000));
}

int main(int argc, char const *argv[]) {

    pid_t pid = 12345;
    uintptr_t base = 0;
    uintptr_t addr = 0x55ea03c052a0;
    uint64_t result = 0;
    char module_name[0x100] = "get_mem";    //strlen(name) < 0xff or overflow
    
    driver->initialize(pid);

    base = driver->get_module_base(module_name);
    printf("base = %lx\n", base);

    //driver->write<uint64_t>(addr, 0xfedcba987654321); 
    {
		size_t number = 1;
		uint64_t now = get_tick_count64();
		for (size_t i = 0; i < number; i++) {
            result = driver->read<uint64_t>(addr);
		}
		printf("Read %ld times cost = %lfs\n",
			number,
			(double)(get_tick_count64() - now) / 1000);
	}
    printf("result = %lx\n", result);
    return 0;
}