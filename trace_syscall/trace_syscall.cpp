// $ ~/Documents/test/trace_syscall$ /home/user/Documents/pin-2.14-71313-gcc.4.4.7-linux/pin -t obj-ia32/trace_syscall.so -- ../syscall_test/a.out

#include <syscall.h>
#include "pin.H"
#include <fstream>
#include <iomanip>
#include <string>


using namespace std;

ofstream fout;

#define NUM_SYSCALL 349

static const char* sys_name[NUM_SYSCALL]={
	"__NR_restart_syscall",
	"__NR_exit",
	"__NR_fork",
	"__NR_read",
	"__NR_write",
	"__NR_open",
	"__NR_close",
	"__NR_waitpid",
	"__NR_creat",
	"__NR_link",
	"__NR_unlink",
	"__NR_execve",
	"__NR_chdir",
	"__NR_time",
	"__NR_mknod",
	"__NR_chmod",
	"__NR_lchown",
	"__NR_break",
	"__NR_oldstat",
	"__NR_lseek",
	"__NR_getpid",
	"__NR_mount",
	"__NR_umount",
	"__NR_setuid",
	"__NR_getuid",
	"__NR_stime",
	"__NR_ptrace",
	"__NR_alarm",
	"__NR_oldfstat",
	"__NR_pause",
	"__NR_utime",
	"__NR_stty",
	"__NR_gtty",
	"__NR_access",
	"__NR_nice",
	"__NR_ftime",
	"__NR_sync",
	"__NR_kill",
	"__NR_rename",
	"__NR_mkdir",
	"__NR_rmdir",
	"__NR_dup",
	"__NR_pipe",
	"__NR_times",
	"__NR_prof",
	"__NR_brk",
	"__NR_setgid",
	"__NR_getgid",
	"__NR_signal",
	"__NR_geteuid",
	"__NR_getegid",
	"__NR_acct",
	"__NR_umount2",
	"__NR_lock",
	"__NR_ioctl",
	"__NR_fcntl",
	"__NR_mpx",
	"__NR_setpgid",
	"__NR_ulimit",
	"__NR_oldolduname",
	"__NR_umask",
	"__NR_chroot",
	"__NR_ustat",
	"__NR_dup2",
	"__NR_getppid",
	"__NR_getpgrp",
	"__NR_setsid",
	"__NR_sigaction",
	"__NR_sgetmask",
	"__NR_ssetmask",
	"__NR_setreuid",
	"__NR_setregid",
	"__NR_sigsuspend",
	"__NR_sigpending",
	"__NR_sethostname",
	"__NR_setrlimit",
	"__NR_getrlimit",
	"__NR_getrusage",
	"__NR_gettimeofday",
	"__NR_settimeofday",
	"__NR_getgroups",
	"__NR_setgroups",
	"__NR_select",
	"__NR_symlink",
	"__NR_oldlstat",
	"__NR_readlink",
	"__NR_uselib",
	"__NR_swapon",
	"__NR_reboot",
	"__NR_readdir",
	"__NR_mmap",
	"__NR_munmap",
	"__NR_truncate",
	"__NR_ftruncate",
	"__NR_fchmod",
	"__NR_fchown",
	"__NR_getpriority",
	"__NR_setpriority",
	"__NR_profil",
	"__NR_statfs",
	"__NR_fstatfs",
	"__NR_ioperm",
	"__NR_socketcall",
	"__NR_syslog",
	"__NR_setitimer",
	"__NR_getitimer",
	"__NR_stat",
	"__NR_lstat",
	"__NR_fstat",
	"__NR_olduname",
	"__NR_iopl",
	"__NR_vhangup",
	"__NR_idle",
	"__NR_vm86old",
	"__NR_wait4",
	"__NR_swapoff",
	"__NR_sysinfo",
	"__NR_ipc",
	"__NR_fsync",
	"__NR_sigreturn",
	"__NR_clone",
	"__NR_setdomainname",
	"__NR_uname",
	"__NR_modify_ldt",
	"__NR_adjtimex",
	"__NR_mprotect",
	"__NR_sigprocmask",
	"__NR_create_module",
	"__NR_init_module",
	"__NR_delete_module",
	"__NR_get_kernel_syms",
	"__NR_quotactl",
	"__NR_getpgid",
	"__NR_fchdir",
	"__NR_bdflush",
	"__NR_sysfs",
	"__NR_personality",
	"__NR_afs_syscall",
	"__NR_setfsuid",
	"__NR_setfsgid",
	"__NR__llseek",
	"__NR_getdents",
	"__NR__newselect",
	"__NR_flock",
	"__NR_msync",
	"__NR_readv",
	"__NR_writev",
	"__NR_getsid",
	"__NR_fdatasync",
	"__NR__sysctl",
	"__NR_mlock",
	"__NR_munlock",
	"__NR_mlockall",
	"__NR_munlockall",
	"__NR_sched_setparam",
	"__NR_sched_getparam",
	"__NR_sched_setschedul",
	"__NR_sched_getschedul",
	"__NR_sched_yield",
	"__NR_sched_get_priority_max",
	"__NR_sched_get_priority_min",
	"__NR_sched_rr_get_interval",
	"__NR_nanosleep",
	"__NR_mremap",
	"__NR_setresuid",
	"__NR_getresuid",
	"__NR_vm86",
	"__NR_query_module",
	"__NR_poll",
	"__NR_nfsservctl",
	"__NR_setresgid",
	"__NR_getresgid",
	"__NR_prctl",
	"__NR_rt_sigreturn",
	"__NR_rt_sigaction",
	"__NR_rt_sigprocmask",
	"__NR_rt_sigpending",
	"__NR_rt_sigtimedwait",
	"__NR_rt_sigqueueinfo",
	"__NR_rt_sigsuspend",
	"__NR_pread64",
	"__NR_pwrite64",
	"__NR_chown",
	"__NR_getcwd",
	"__NR_capget",
	"__NR_capset",
	"__NR_sigaltstack",
	"__NR_sendfile",
	"__NR_getpmsg",
	"__NR_putpmsg",
	"__NR_vfork",
	"__NR_ugetrlimit",
	"__NR_mmap2",
	"__NR_truncate64",
	"__NR_ftruncate64",
	"__NR_stat64",
	"__NR_lstat64",
	"__NR_fstat64",
	"__NR_lchown32",
	"__NR_getuid32",
	"__NR_getgid32",
	"__NR_geteuid32",
	"__NR_getegid32",
	"__NR_setreuid32",
	"__NR_setregid32",
	"__NR_getgroups32",
	"__NR_setgroups32",
	"__NR_fchown32",
	"__NR_setresuid32",
	"__NR_getresuid32",
	"__NR_setresgid32",
	"__NR_getresgid32",
	"__NR_chown32",
	"__NR_setuid32",
	"__NR_setgid32",
	"__NR_setfsuid32",
	"__NR_setfsgid32",
	"__NR_pivot_root",
	"__NR_mincore",
	"__NR_madvise",
	"__NR_getdents64",
	"__NR_fcntl64",
	"",
	"",
	"__NR_gettid",
	"__NR_readahead",
	"__NR_setxattr",
	"__NR_lsetxattr",
	"__NR_fsetxattr",
	"__NR_getxattr",
	"__NR_lgetxattr",
	"__NR_fgetxattr",
	"__NR_listxattr",
	"__NR_llistxattr",
	"__NR_flistxattr",
	"__NR_removexattr",
	"__NR_lremovexattr",
	"__NR_fremovexattr",
	"__NR_tkill",
	"__NR_sendfile64",
	"__NR_futex",
	"__NR_sched_setaffinit",
	"__NR_sched_getaffinit",
	"__NR_set_thread_area",
	"__NR_get_thread_area",
	"__NR_io_setup",
	"__NR_io_destroy",
	"__NR_io_getevents",
	"__NR_io_submit",
	"__NR_io_cancel",
	"__NR_fadvise64",
	"",
	"__NR_exit_group",
	"__NR_lookup_dcookie",
	"__NR_epoll_create",
	"__NR_epoll_ctl",
	"__NR_epoll_wait",
	"__NR_remap_file_pages",
	"__NR_set_tid_address",
	"__NR_timer_create",
	"__NR_timer_settime",
	"__NR_timer_gettime",
	"__NR_timer_getoverrun",
	"__NR_timer_delete",
	"__NR_clock_settime",
	"__NR_clock_gettime",
	"__NR_clock_getres",
	"__NR_clock_nanosleep",
	"__NR_statfs64",
	"__NR_fstatfs64",
	"__NR_tgkill",
	"__NR_utimes",
	"__NR_fadvise64_64",
	"__NR_vserver",
	"__NR_mbind",
	"__NR_get_mempolicy",
	"__NR_set_mempolicy",
	"__NR_mq_open",
	"__NR_mq_unlink",
	"__NR_mq_timedsend",
	"__NR_mq_timedreceive",
	"__NR_mq_notify",
	"__NR_mq_getsetattr",
	"__NR_kexec_load",
	"__NR_waitid",
	"",
	"__NR_add_key",
	"__NR_request_key",
	"__NR_keyctl",
	"__NR_ioprio_set",
	"__NR_ioprio_get",
	"__NR_inotify_init",
	"__NR_inotify_add_watc",
	"__NR_inotify_rm_watch",
	"__NR_migrate_pages",
	"__NR_openat",
	"__NR_mkdirat",
	"__NR_mknodat",
	"__NR_fchownat",
	"__NR_futimesat",
	"__NR_fstatat64",
	"__NR_unlinkat",
	"__NR_renameat",
	"__NR_linkat",
	"__NR_symlinkat",
	"__NR_readlinkat",
	"__NR_fchmodat",
	"__NR_faccessat",
	"__NR_pselect6",
	"__NR_ppoll",
	"__NR_unshare",
	"__NR_set_robust_list",
	"__NR_get_robust_list",
	"__NR_splice",
	"__NR_sync_file_range",
	"__NR_tee",
	"__NR_vmsplice",
	"__NR_move_pages",
	"__NR_getcpu",
	"__NR_epoll_pwait",
	"__NR_utimensat",
	"__NR_signalfd",
	"__NR_timerfd_create",
	"__NR_eventfd",
	"__NR_fallocate",
	"__NR_timerfd_settime",
	"__NR_timerfd_gettime",
	"__NR_signalfd4",
	"__NR_eventfd2",
	"__NR_epoll_create1",
	"__NR_dup3",
	"__NR_pipe2",
	"__NR_inotify_init1",
	"__NR_preadv",
	"__NR_pwritev",
	"__NR_rt_tgsigqueueinf",
	"__NR_perf_event_open",
	"__NR_recvmmsg",
	"__NR_fanotify_init",
	"__NR_fanotify_mark",
	"__NR_prlimit64",
	"__NR_name_to_handle_a",
	"__NR_open_by_handle_a",
	"__NR_clock_adjtime",
	"__NR_syncfs",
	"__NR_sendmmsg",
	"__NR_setns",
	"__NR_process_vm_readv",
	"__NR_process_vm_write"
};

int ins_instrument_count;

VOID ins_instrument(INS ins, VOID *v)
{
	ins_instrument_count++;
	fout << "*************************" << endl
		 << "*Ins Instrumentation: " << setiosflags(ios::left) << setw(2) << ins_instrument_count << "*" <<endl
		 << "*************************" << endl;
//	if (INS_IsSyscall(ins))
//		fout << "*****************************************" << endl;
	fout << "0x" << hex << INS_Address(ins) << dec << "\t" << INS_Disassemble(ins) << endl;
//	if(INS_Address(ins) == 0xb7fe6f11)
//		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_analysis, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_END);
//	if (INS_IsSyscall(ins))
//		fout << "*****************************************" << endl;

    // instrument the system call instruction.
//    if (INS_IsSyscall(ins))
//    {
//		if(RTN_Valid(INS_Rtn(ins)) && SEC_Valid(RTN_Sec(INS_Rtn(ins))) && IMG_Valid(SEC_Img(RTN_Sec(INS_Rtn(ins)))) && IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) == "/home/user/Documents/test/syscall_test/a.out")
//			fout << IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins)))) << endl;	
	
//		std::cout<<IMG_Name(SEC_Img(RTN_Sec(INS_Rtn(ins))))<<std::endl;
	
//    }
}

VOID switch_context(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
{
	fout << "--------------------Switch Context--------------------" << endl
		 << "ThreadIndex: " << threadIndex << endl
		 << "CONTEXT_CHANGE_REASON: ";
	switch(reason){
	case CONTEXT_CHANGE_REASON_FATALSIGNAL:
		fout << "CONTEXT_CHANGE_REASON_FATALSIGNAL";
		break;
	case CONTEXT_CHANGE_REASON_SIGNAL:
		fout << "CONTEXT_CHANGE_REASON_SIGNAL";
		break;
	case CONTEXT_CHANGE_REASON_SIGRETURN:
		fout << "CONTEXT_CHANGE_REASON_SIGRETURN";
		break;
	case CONTEXT_CHANGE_REASON_APC:
		fout << "CONTEXT_CHANGE_REASON_APC";
		break;
	case CONTEXT_CHANGE_REASON_EXCEPTION:
		fout << "CONTEXT_CHANGE_REASON_EXCEPTION";
		break;
	case CONTEXT_CHANGE_REASON_CALLBACK:
		fout << "CONTEXT_CHANGE_REASON_CALLBACK";
		break;
	default:
		fout << "other";
		break;
	}
	fout << endl;
}

VOID ins_analysis(ADDRINT addr, BOOL branch_taken, ADDRINT target, ADDRINT through)
{
//	fout << "**********************" << endl
//		 << "*Ins Analysis        *" << endl
//		 << "**********************" << endl
//	fout << "0x" << hex << addr << endl;
}

VOID sysenter_analysis(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	fout << "************************" << endl
		 << "*Syscall               *" << endl
		 << "************************" << endl;
	ADDRINT sysno = PIN_GetSyscallNumber(ctxt, std);
	if(sysno<0||sysno>=NUM_SYSCALL)
		fout << "Unkown  Syscall" << endl;
	else
		fout << "sysenter_analysis\n" << "0x" << hex << PIN_GetContextReg(ctxt, REG_EIP) << "\tSyscall:\t" << sys_name[sysno] << endl;
}

VOID sysexit_analysis(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	fout << "0x" << hex << PIN_GetContextReg(ctxt, REG_EIP) << endl;
}

VOID start_program(VOID *v)
{
	fout << "--------------------Start Program--------------------" << endl;
}

VOID thread_start(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	fout << "--------------------Thread Start--------------------" << endl;
}

VOID img_instrument(IMG img, VOID* v)
{
	fout << "**********************************************" << endl
		 << "*Image Instrumentation                       *" << endl
		 << "**********************************************" << endl
		 <<	"name:      \t" << IMG_Name(img) << endl
		 << "high addr: \t0x" << hex << IMG_HighAddress(img) << endl
		 << "low addr:  \t0x" << IMG_LowAddress(img) << endl
		 << "start addr:\t0x" << IMG_StartAddress(img) << endl;
}

VOID trace_instrument(TRACE trace, VOID* v)
{
	IMG img;
	SEC sec;
	RTN rtn;
//	if(INS_IsSyscall(BBL_InsTail(TRACE_BblTail(trace))))
	if(1)
	{
		fout << "*****************************************" << endl
			 << "*Trace Instrumentation                  *" << endl
			 << "*****************************************" << endl;
		if(!RTN_Valid(rtn=TRACE_Rtn(trace)))
			fout << "Invalid Routine" << endl;
		else if(!SEC_Valid(sec=RTN_Sec(rtn)))
			fout << "Invalid Section" << endl;
		else if(!IMG_Valid(img=SEC_Img(sec)))
			fout << "Invalid Image" << endl;
		else
		{
			if(IMG_Name(img)=="/lib/ld-linux.so.2")
				return;
			fout << "Image:  \t" << IMG_Name(img) << endl
				 << "Section:\t" << SEC_Name(sec) << endl
				 << "Routine:\t" << RTN_Name(rtn) << endl
				 << "Address:\t0x" << hex << TRACE_Address(trace) << dec << endl;
		}
		for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			fout << "***********************************" << endl
				 << "*BBL Travel                       *" << endl
				 << "***********************************" << endl;
			ins_instrument_count = 0;
			for(INS ins = BBL_InsHead(bbl);INS_Valid(ins); ins = INS_Next(ins))
			{
				fout << "0x" << hex << INS_Address(ins) << "\t"
					 << INS_Disassemble(ins) << endl;
//				if(INS_Address(ins) == 0xb7fe6f11)
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_analysis, IARG_INST_PTR, IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_FALLTHROUGH_ADDR, IARG_END);
			}
		}
	}
}

VOID Fini(INT32 code, VOID *v)
{
	fout.close();
}

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);

    fout.open("out");
	//程序启动时调用
//	PIN_AddApplicationStartFunction(start_program, 0);
//	INS_AddInstrumentFunction(ins_instrument, 0);
	IMG_AddInstrumentFunction(img_instrument, 0);
//	TRACE_AddInstrumentFunction(trace_instrument, 0);

	//注册线程启动回调函数
//	PIN_AddThreadStartFunction(thread_start, 0);
	//上下文切换时调用
//	PIN_AddContextChangeFunction(switch_context, 0);

//	PIN_AddSyscallEntryFunction(sysenter_analysis, 0);
//	PIN_AddSyscallExitFunction(sysexit_analysis, 0);

//	PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    
    return 0;
}
