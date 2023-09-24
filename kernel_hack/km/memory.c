#include "memory.h"
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
	
    phys_addr_t page_addr;
    uintptr_t page_offset;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
    	return 0;
    }
	pud = pud_offset(p4d,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
        return 0;
    }
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
        return 0;
    }
	if(!pte_present(*pte)) {
        return 0;
    }
	//页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE-1);
	
	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
	
    phys_addr_t page_addr;
    uintptr_t page_offset;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
	pud = pud_offset(pgd,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
        return 0;
    }
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
        return 0;
    }
	if(!pte_present(*pte)) {
        return 0;
    }
	//页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE-1);
	
	return page_addr + page_offset;
}
#endif

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static inline int valid_phys_addr_range(phys_addr_t addr, size_t count) {
    return addr + count <= __pa(high_memory);
}
#endif

bool read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }
    if (!valid_phys_addr_range(pa, size)) {
        return false;
    }
    mapped = ioremap_cache(pa, size);
    if (!mapped) {
        return false;
    }
    if(copy_to_user(buffer, mapped, size)) {
        iounmap(mapped);
        return false;
    }
    iounmap(mapped);
    return true;
}

bool write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa))) {
        return false;
    }
    if (!valid_phys_addr_range(pa, size)) {
        return false;
    }
    mapped = ioremap_cache(pa, size);
    if (!mapped) {
        return false;
    }
    if(copy_from_user(mapped, buffer, size)) {
        iounmap(mapped);
        return false;
    }
    iounmap(mapped);
    return true;
}

/*
static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size) {
	unsigned long sz;
	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));
	return min(sz, size);
}

static inline bool should_stop_iteration(void) {
	if (need_resched())
		cond_resched();
	return signal_pending(current);
}

static long x_probe_kernel_read(void *dst, const char *src, size_t size) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
    return copy_from_kernel_nofault(dst, src, size);
#else
    return probe_kernel_read(dst, src, size);
#endif
}

static long x_probe_kernel_write(void *dst, const char *src, size_t size) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
    return copy_to_kernel_nofault(dst, src, size);
#else
    return probe_kernel_write(dst, src, size);
#endif
}


bool read_physical_address(phys_addr_t pa, void* buffer, size_t size) {

    void* mapped;
    ssize_t sz;
	char* bounce;
    char* buf = buffer;
    
    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;

    if (!valid_phys_addr_range(pa, size))
        return false;
    
    bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		return false;

	while (size > 0) {
		unsigned long remaining;
		int probe;

		sz = size_inside_page(pa, size);

		mapped = xlate_dev_mem_ptr(pa);
		if (!mapped)
			goto failed;

		probe = x_probe_kernel_read(bounce, mapped, sz);
		unxlate_dev_mem_ptr(pa, mapped);
		if (probe)
			goto failed;

		remaining = copy_to_user(buf, bounce, sz);

		if (remaining)
			goto failed;

		buf += sz;
		pa += sz;
		size -= sz;
		if (should_stop_iteration())
			break;
	}
	kfree(bounce);
    return true;

failed:
	kfree(bounce);
	return false;
}

bool write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
    
    void* mapped;
    ssize_t sz;
	char* bounce;
    char* buf = buffer;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;

    if (!valid_phys_addr_range(pa, size))
        return false;
    
    bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		return false;

	while (size > 0) {
		unsigned long remaining;
		int probe;

		sz = size_inside_page(pa, size);

        remaining = copy_from_user(bounce, buf, sz);
		if (remaining)
			goto failed;

		mapped = xlate_dev_mem_ptr(pa);
		if (!mapped)
			goto failed;

		probe = x_probe_kernel_write(mapped, bounce, sz);
		unxlate_dev_mem_ptr(pa, mapped);
		if (probe)
			goto failed;

		buf += sz;
		pa += sz;
		size -= sz;
		if (should_stop_iteration())
			break;
	}
	kfree(bounce);
    return true;

failed:
	kfree(bounce);
	return false;
}
*/

bool read_process_memory(
    pid_t pid, 
    uintptr_t addr, 
    void* buffer, 
    size_t size) {
    
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    phys_addr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) {
        return false;
    }
    put_task_struct(task);
	mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    mmput(mm);
    pa = translate_linear_address(mm, addr);
    if (!pa) {
        return false;
    }
    //printk("[*] physical_address = %lx",pa);
    return read_physical_address(pa, buffer, size);
}

bool write_process_memory(
    pid_t pid, 
    uintptr_t addr, 
    void* buffer, 
    size_t size) {
    
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    phys_addr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return false;
    }
    put_task_struct(task);
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    mmput(mm);
    pa = translate_linear_address(mm, addr);
    if (!pa) {
        return false;
    }
    return write_physical_address(pa,buffer,size);
}
