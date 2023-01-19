#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>


extern struct mm_struct *get_task_mm(struct task_struct *task);

uintptr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
	
    pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;
	
    uintptr_t page_addr;
    uintptr_t page_offset;

	//if(!find_vma(mm,va))
    //    return 0;

	pgd = pgd_offset(mm, va);
	if(pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

    //arm cpu have p4d?
    p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;

	//pud = pud_offset(pgd,va);
	pud = pud_offset(p4d,va);
	if(pud_none(*pud) || pud_bad(*pud))
        return 0;

	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd))
        return 0;
	
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte))
        return 0;

	if(!pte_present(*pte))
        return 0;
	
	//页物理地址
	page_addr = (uintptr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE-1);
	
	return page_addr + page_offset;
}

bool read_physical_address(uintptr_t pa, void* buffer, size_t size) {

    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;
    
    if(copy_to_user(buffer, mapped, size)) {
        iounmap(mapped);
        return false;
    }
    iounmap(mapped);
    return true;
}   

bool write_physical_address(uintptr_t pa, void* buffer, size_t size) {

    void* mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;
    
    if(copy_from_user(mapped, buffer, size)) {
        iounmap(mapped);
        return false;
    }
    iounmap(mapped);
    return true;
}

bool read_process_memory(
    pid_t pid, 
    uintptr_t addr, 
    void* buffer, 
    size_t size) {
    
    struct task_struct* task;
    struct mm_struct* mm;
    struct pid* pid_struct;
    uintptr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
        return false;

	mm = get_task_mm(task);
    if (!mm)
        return false;

    pa = translate_linear_address(mm, addr);
    if (!pa)
        return false;
    
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
    uintptr_t pa;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    mm = get_task_mm(task);
    if (!mm)
        return false;
    
    pa = translate_linear_address(mm, addr);
    if (!pa)
        return false;

    return write_physical_address(pa,buffer,size);
}
