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
        if (!strcmp(comm,name)) {
            pid_struct = get_task_pid(task, PIDTYPE_PID);
            pid = pid_nr(pid_struct);
            //printk("%s[%d]\n", comm, pid);
            return pid;
        }
    }
    return 0;
}

void show_vma_attribute(struct vm_area_struct *vma) {
    struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	vm_flags_t flags = vma->vm_flags;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long start, end;
	dev_t dev = 0;
	const char *name = NULL;
    char buf[ARC_PATH_MAX];
	char *path_nm = "";
    char tmp_buffer[0xff];


	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;

        path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
	}

	start = vma->vm_start;
	end = vma->vm_end;

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name)
			goto done;
	}

	//name = arch_vma_name(vma);
	if (!name) {
        
		if (!mm) {
			name = "[vdso]";
			goto done;
		}

		if (vma->vm_start <= mm->brk &&
		    vma->vm_end >= mm->start_brk) {
			name = "[heap]";
			goto done;
		}

		if (vma->vm_start <= vma->vm_mm->start_stack &&
		    vma->vm_end >= vma->vm_mm->start_stack) {
			name = "[stack]";
			goto done;
		}

		if (!vma->vm_file && vma->anon_name) {
			sprintf(tmp_buffer, "[anon:%s]", vma->anon_name->name);
            name = tmp_buffer;
            goto done;
		}

        name = "";
	}

done:
    printk("%08lx-%08lx %c%c%c%c %08llx %02x:%02x %lu  \t\t  %s %s",
            start,
            end,
            flags & VM_READ ? 'r' : '-',
            flags & VM_WRITE ? 'w' : '-',
            flags & VM_EXEC ? 'x' : '-',
            flags & VM_MAYSHARE ? 's' : 'p',
            pgoff,
            MAJOR(dev), MINOR(dev), ino,
            path_nm,
            name);
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
        show_vma_attribute(vma);
        //To be continue......
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

