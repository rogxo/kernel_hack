#include <linux/kernel.h>
#include <linux/sched.h>
//#include <asm/cpu.h>
//#include <asm/io.h>

#define ARC_PATH_MAX 256


pid_t get_pid_by_name(char* name) {

    struct task_struct* task;
    struct pid* pid_struct;
    pid_t pid;
    char comm[16];

    for_each_process(task) {
        get_task_comm(comm, task);
        if (!strcmp(comm, name)) {
            pid_struct = get_task_pid(task, PIDTYPE_PID);
            pid = pid_nr(pid_struct);
            return pid;
        }
    }
    return 0;
}

uintptr_t get_module_base(pid_t pid, char* name) {

    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct *vma;

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

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
            if (!strcmp(kbasename(path_nm), name)) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}

uintptr_t get_module_bss_base(pid_t pid, char* name) {

    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct *vma;
    bool is_matched = false;

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

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);

            if (!strcmp(kbasename(path_nm), name)) {
                is_matched = true;
            }
        }
        if (is_matched && !vma->vm_file && vma->anon_name){
            if (!strcmp(".bss", vma->anon_name->name)) {
            //if (!strcmp(".bss", vma_get_anon_name(vma))) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}
