/*
 * TaintList-linux.h
 *
 *  Created on: 2016年3月10日
 *      Author: wpf
 */

/*
 * TaintStructs.h
 *
 *  Created on: 2015年12月17日
 *      Author: wpf
 */

#ifndef TAINTSTRUCTS_H_
#define TAINTSTRUCTS_H_

#endif /* TAINTSTRUCTS_H_ */

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"

#include <iostream>
#include <fstream>
#include <list>
#include <map>

#define DEBUG 1

std::ofstream fout("/home/wpf/output.txt",std::ios::in | std::ios::out);
std::ofstream flog("/home/wpf/log.txt",std::ios::in | std::ios::out);
using namespace clang;
using namespace ento;

namespace {

std::string toStr(SVal val) {
	std::string str;
	llvm::raw_string_ostream rso(str);
	val.dumpToStream(rso);
	return rso.str();
}

std::string toStr(const Stmt* s) {
	std::string str;
	llvm::raw_string_ostream rso(str);
	s->dump(rso);
	return rso.str();
}


struct STATE{
private:
	std::string funcName;
	std::string locName;
	SVal val;
	unsigned int count;
	unsigned int taint;
	bool isLoc;
	bool isPtr;
	bool isBase;
	unsigned int timestamp;

public:
	STATE(std::string fn , std::string ln , SVal v, unsigned int c, int t = 0, bool l = false, bool p = false, bool b = false, unsigned int ti = 0){
		funcName = fn;
		locName = ln;
		val = v;
		count = c;
		taint = t;
		isLoc = l;
		isPtr = p;
		isBase = b;
		timestamp = ti;
	}

	std::string getLocName() const{
		return locName;
	}
	std::string getFuncName() const{
		return funcName;
	}
	unsigned int getCount() const{
		return count;
	}
	unsigned int getTimeStamp() const{
		return timestamp;
	}
	unsigned int getTaint() const{
		return taint;
	}
	bool isLocal() const{
		return isLoc;
	}
	bool isPtrType() const{
		return isPtr;
	}
	bool isBasePtr() const{
		return isBase;
	}
	STATE getAsIncre() const { return STATE(funcName, locName, val, count+1, taint, isLoc, isPtr, isBase, timestamp);}

	void showState(std::string str = "") const {
		fout<<str<<" funcName: "<<funcName<<"\tlocName: "<<locName<<"\tval: "<<toStr(val)<<"\tcount: "<<count<<"\ttaint: "<<taint
			<<"\tisLocalRegion: "<<isLoc<<"\tisPtrType: "<<isPtr<<"\tisBasePtr: "<<isBase<<"\ttimeStamp: "<<timestamp<<std::endl;
	}

	bool operator == ( const STATE &T) const{
		if (count == T.count && locName == T.locName && funcName == T.funcName && val == T.val
				&& taint == T.taint && isLoc == T.isLoc && isPtr == T.isPtr && isBase == T.isBase && timestamp == T.timestamp)
			return true;
		else
			return false;
	}
	void Profile(llvm::FoldingSetNodeID &ID) const {
		ID.AddInteger(count);
		ID.AddInteger(taint);
		ID.AddInteger(timestamp);
		ID.AddBoolean(isLoc);
		ID.AddBoolean(isPtr);
		ID.AddBoolean(isBase);

	}

};

struct ARG{
	std::string argName;
	std::string funcName;
	bool isPointer;
	bool isSyscall;
public:
	ARG() {
		argName = "";
		funcName = "";
		isPointer = false;
		isSyscall = false;
	}
	ARG(std::string func, std::string arg, bool t, bool s) {
		argName = arg;
		funcName = func;
		isPointer = t;
		isSyscall = s;
	}
};
struct FuncList{
	mutable std::list<ARG> alist;
public:
	FuncList(){};
	void Add(ARG arg) const {
		alist.push_back(arg);
	}
	bool isEmpty() const{
		if (alist.empty())
			return true;
		else
			return false;
	}
	bool containsPtrArg(std::string arg, std::string func) const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); ++i)
		{
			if ((*i).argName == arg && (*i).funcName == func && (*i).isPointer && !((*i).isSyscall))
				return true;
		}
		return false;
	}
	bool containsNPtrArg(std::string arg, std::string func) const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); ++i)
		{
			if ((*i).argName == arg && (*i).funcName == func && !((*i).isPointer) && !((*i).isSyscall))
				return true;
		}
		return false;
	}

	bool containsSysPtrArg(std::string arg, std::string func) const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); ++i)
		{
			if ((*i).argName == arg && (*i).funcName == func && (*i).isPointer && (*i).isSyscall)
				return true;
		}
		return false;
	}

	bool containsSysNPtrArg(std::string arg, std::string func) const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); ++i)
		{
			if ((*i).argName == arg && (*i).funcName == func && !((*i).isPointer) && (*i).isSyscall)
				return true;
		}
		return false;
	}


	bool containsFunc(std::string func) const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); ++i)
		{
			if ((*i).funcName == func &&  !((*i).isSyscall))
				return true;
		}
		return false;
	}
	void showArgs() const{
		std::list<ARG>::iterator i;
		for (i = alist.begin(); i != alist.end(); i++){
			fout<<"[show args]"<<"func name: "<<(*i).funcName<<"\targName:"<<(*i).argName<<"\tisPtr:"<<(*i).isPointer<<std::endl;
			return;
		}

	}
};


struct ArgStrArray{
	unsigned int num;
	std::string args[5];
	ArgStrArray(std::string a0, std::string a1, std::string a2, std::string a3, std::string a4){
		num = 5;
		args[0] = a0;
		args[1] = a1;
		args[2] = a2;
		args[3] = a3;
		args[4] = a4;
	}
	ArgStrArray(std::string a0, std::string a1, std::string a2, std::string a3){
		num = 4;
		args[0] = a0;
		args[1] = a1;
		args[2] = a2;
		args[3] = a3;
	}
	ArgStrArray(std::string a0, std::string a1, std::string a2){
		num = 3;
		args[0] = a0;
		args[1] = a1;
		args[2] = a2;
	}
	ArgStrArray( std::string a0, std::string a1){
		num = 2;
		args[0] = a0;
		args[1] = a1;
	}
	ArgStrArray(std::string a0){
		num = 1;
		args[0] = a0;
	}

	bool operator == ( const ArgStrArray &T) {
		if (num != T.num)
			return false;

		for(unsigned int i = 0; i < num; i++){
			if(args[i] != T.args[i])
				return false;
		}

		return true;
	}

	bool operator = ( const ArgStrArray &T) {
		num = T.num;
		for(unsigned int i = 0; i < num; i++)
			args[i] = T.args[i];

		return true;
	}

	bool contains(std::string a){
		for(unsigned int i = 0; i < num; i++){
			if(args[i] == a)
				return true;
		}
		return false;
	}
};

struct SyscallTable{
	std::map<std::string, ArgStrArray> mapTable;
	std::map<std::string, ArgStrArray>::iterator it;
	SyscallTable(){
		// net/socket.c   18
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_recv",ArgStrArray("ubuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_recvfrom",ArgStrArray("ubuf","addr","addr_len")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_socketpair",ArgStrArray("usockvec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_socketcall",ArgStrArray("args")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_recvmsg",ArgStrArray("msg")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_recvmmsg",ArgStrArray("mmsg","timeout")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sendmmsg",ArgStrArray("mmsg")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sendmsg",ArgStrArray("msg")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getsockopt",ArgStrArray("optval","optlen")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setsockopt",ArgStrArray("optval")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_send",ArgStrArray("buff")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sendto",ArgStrArray("buff","addr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getpeername",ArgStrArray("usockaddr","usockaddr_len")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getsockname",ArgStrArray("usockaddr","usockaddr_len")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_connect",ArgStrArray("uservaddr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_accept",ArgStrArray("upeer_sockaddr","upeer_addrlen")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_accept4",ArgStrArray("upeer_sockaddr","upeer_addrlen")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_bind",ArgStrArray("umyaddr")));//
		// fs/open.c  13
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_openat",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_open",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lchown",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_chown",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fchownat",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_chmod",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fchmodat",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_chroot",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_chdir",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_access",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_faccessat",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_truncate64",ArgStrArray("path")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_truncate",ArgStrArray("path")));//
		// Kernel/time/time.c 5
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_time",ArgStrArray("tloc")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_stime",ArgStrArray("tptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_gettimeofday",ArgStrArray("tv", "tz")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_settimeofday",ArgStrArray("tv", "tz")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_adjtimex",ArgStrArray("txc_p")));//
		// fs/read_write.c 11
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_read",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_llseek",ArgStrArray("result")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_write",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pread64",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pwrite64",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_readv",ArgStrArray("vec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_writev",ArgStrArray("vec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_preadv",ArgStrArray("vec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pwritev",ArgStrArray("vec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sendfile",ArgStrArray("offset")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sendfile64",ArgStrArray("offset")));//
		//Kernel/time/itimer.c 2
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getitimer",ArgStrArray("value")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setitimer",ArgStrArray("value", "ovalue")));//
		//kernel/sys.c  16
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getresuid",ArgStrArray("ruidp","euidp","suidp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getresgid",ArgStrArray("rgidp","egidp","sgidp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_times",ArgStrArray("tbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_newuname",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_uname",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_olduname",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sethostname",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_gethostname",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setdomainname",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getrlimit",ArgStrArray("rlim")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_old_getrlimit",ArgStrArray("rlim")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_prlimit64",ArgStrArray("new_rlim","old_rlim")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setrlimit",ArgStrArray("rlim")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getrusage",ArgStrArray("ru")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getcpu",ArgStrArray("cpup","nodep","unused")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sysinfo",ArgStrArray("info")));//
		//Kernel/time/posix-timers.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_timer_create",ArgStrArray("timer_event_spec","created_timer_id")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_timer_gettime",ArgStrArray("setting")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_timer_settime",ArgStrArray("new_setting","old_setting")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_clock_settime",ArgStrArray("tp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_clock_gettime",ArgStrArray("tp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_clock_adjtime",ArgStrArray("utx")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_clock_getres",ArgStrArray("tp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_clock_nanosleep",ArgStrArray("rqtp","rmtp")));//
		//Kernel/time/hrtimer.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_nanosleep",ArgStrArray("rqtp","rmtp")));//
		//Kernel/group.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getgroups",ArgStrArray("grouplist")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setgroups",ArgStrArray("grouplist")));//
		//Kernel/acct.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_acct",ArgStrArray("name")));//
		//Kernel/signal.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_sigprocmask",ArgStrArray("nset","oset")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_sigpending",ArgStrArray("uset")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_sigtimedwait",ArgStrArray("uthese","uinfo","uts")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_sigqueueinfo",ArgStrArray("uinfo")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_tgsigqueueinfo",ArgStrArray("uinfo")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sigaltstack",ArgStrArray("uss","uoss")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sigpending",ArgStrArray("set")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sigprocmask",ArgStrArray("nset","oset")));//
		//kernel/sched/core.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_setscheduler",ArgStrArray("param")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_setparam",ArgStrArray("param")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_setattr",ArgStrArray("uattr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_getparam",ArgStrArray("param")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_getattr",ArgStrArray("uattr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_setaffinity",ArgStrArray("user_mask_ptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_getaffinity",ArgStrArray("user_mask_ptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sched_rr_get_interval",ArgStrArray("interval")));//
		//fs/quota/compat.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("sys32_quotactl",ArgStrArray("special","addr")));//
		//kernel/reboot.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_reboot",ArgStrArray("arg")));//
		//kernel/kexec.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_kexec_load",ArgStrArray("segments")));//
		//kernel/kexec_file.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_kexec_file_load",ArgStrArray("cmdline_ptr")));//
		//kernel/exit.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_waitid",ArgStrArray("ru")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_wait4",ArgStrArray("ru")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_waitpid",ArgStrArray("stat_addr")));//
		//Mm/process_vm_readv.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_process_vm_readv",ArgStrArray("lvec","rvec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_process_vm_writev",ArgStrArray("lvec","rvec")));//
		//fs/namespace.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_umount",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_oldumount",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mount",ArgStrArray("dev_name","dir_name","type","data")));//
		//kernel/signal.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sigaction",ArgStrArray("act","oact")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_sigaction",ArgStrArray("act","oact")));//
		// fs/exec.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_execve",ArgStrArray("filename","argv","envp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_execveat",ArgStrArray("filename","argv","envp")));//
		//rest
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_set_tid_address",ArgStrArray("tidptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_futex",ArgStrArray("uaddr","utime","uaddr2")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_init_module",ArgStrArray("umod","uargs")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_delete_module",ArgStrArray("name_user")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rt_sigsuspend",ArgStrArray("unewset")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_stat",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_statfs",ArgStrArray("path","buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_statfs64",ArgStrArray("path","buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fstatfs",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fstatfs64",ArgStrArray("buf")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lstat",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fstat",ArgStrArray("statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_newstat",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_newlstat",ArgStrArray("rfilenameu","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_newfstat",ArgStrArray("statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_ustat",ArgStrArray("ubuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_stat64",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lstat64",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fstatat64",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setxattr",ArgStrArray("path","name","value")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lsetxattr",ArgStrArray("path","name","value")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fsetxattr",ArgStrArray("name","value")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getxattr",ArgStrArray("path","name","value")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lgetxattr",ArgStrArray("path","name","value")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fgetxattr",ArgStrArray("name","value")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_listxattr",ArgStrArray("path","list")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_llistxattr",ArgStrArray("path","list")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_flistxattr",ArgStrArray("list")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_removexattr",ArgStrArray("path","name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lremovexattr",ArgStrArray("path","name")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fremovexattr",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mincore",ArgStrArray("vec")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pivot_root",ArgStrArray("put_old")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_chroot",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mknod",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_link",ArgStrArray("oldname","newname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_symlink",ArgStrArray("old","new")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_unlink",ArgStrArray("pathname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rename",ArgStrArray("oldname","newname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pipe",ArgStrArray("fildes")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pipe2",ArgStrArray("fildes")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_io_setup",ArgStrArray("ctxp")));//ctx  fs/aio.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_io_getevents",ArgStrArray("events","timeout")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_io_submit",ArgStrArray("iocbpp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_io_cancel",ArgStrArray("iocb","result")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_readlink",ArgStrArray("path","buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_chown16",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lchown16",ArgStrArray("filename")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getresuid16",ArgStrArray("ruid","euid","suid")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getresgid16",ArgStrArray("rgid","egid","sgid")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getgroups16",ArgStrArray("grouplist")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_setgroups16",ArgStrArray("grouplist")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_utime",ArgStrArray("filename","times")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_utimes",ArgStrArray("filename","utimes")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getcwd",ArgStrArray("buf","size")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mkdir",ArgStrArray("pathname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_rmdir",ArgStrArray("pathname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_lookup_dcookie",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_quotactl",ArgStrArray("special","addr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getdents",ArgStrArray("dirent")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getdents64",ArgStrArray("dirent")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_poll",ArgStrArray("ufds")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_select",ArgStrArray("inp","outp","exp","tvp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_old_select",ArgStrArray("arg")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_epoll_ctl",ArgStrArray("event")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_epoll_wait",ArgStrArray("events")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_epoll_pwait",ArgStrArray("events","sigmask")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_msgsnd",ArgStrArray("msgp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_msgrcv",ArgStrArray("msgp")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_msgctl",ArgStrArray("buf")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_semop",ArgStrArray("sops")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_semtimedop",ArgStrArray("sops","timeout")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_shmat",ArgStrArray("shmaddr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_shmdt",ArgStrArray("shmaddr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_shmctl",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_ipc",ArgStrArray("ptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mq_open",ArgStrArray("name","attr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mq_unlink",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mq_timedsend",ArgStrArray("msg_ptr","abs_timeout")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mq_timedreceive",ArgStrArray("msg_ptr","msg_prio","abs_timeout")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mq_notify",ArgStrArray("notification")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mq_getsetattr",ArgStrArray("mqstat","omqstat")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pciconfig_read",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pciconfig_write",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_swapon",ArgStrArray("specialfile")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_swapoff",ArgStrArray("specialfile")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_sysctl",ArgStrArray("args")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_syslog",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_uselib",ArgStrArray("library")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_add_key",ArgStrArray("_type","_description","_payload")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_request_key",ArgStrArray("_type","_description","_callout_info")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_set_mempolicy",ArgStrArray("nmask")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_migrate_pages",ArgStrArray("from","to")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_move_pages",ArgStrArray("pages","status")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mbind",ArgStrArray("nmask")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_get_mempolicy",ArgStrArray("policy","nmask")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_inotify_add_watch",ArgStrArray("path")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_spu_run",ArgStrArray("unpc","ustatus")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_spu_create",ArgStrArray("name")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mknodat",ArgStrArray("filename")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_mkdirat",ArgStrArray("pathname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_unlinkat",ArgStrArray("pathname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_symlinkat",ArgStrArray("oldname","newname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_linkat",ArgStrArray("oldname","newname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_renameat",ArgStrArray("oldname","newname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_renameat2",ArgStrArray("oldname","newname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_futimesat",ArgStrArray("filename","utimes")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_newfstatat",ArgStrArray("filename","statbuf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_readlinkat",ArgStrArray("path","buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_utimensat",ArgStrArray("filename","utimes")));//

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_splice",ArgStrArray("off_in","off_out")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_vmsplice",ArgStrArray("iov")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_get_robust_list",ArgStrArray("head_ptr","len_ptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_set_robust_list",ArgStrArray("head")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_signalfd",ArgStrArray("user_mask")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_signalfd4",ArgStrArray("user_mask")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_timerfd_settime",ArgStrArray("utmr","otmr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_timerfd_gettime",ArgStrArray("otmr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_memfd_create",ArgStrArray("uname_ptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_old_readdir",ArgStrArray("dirent")));// fs/readdir.c

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_pselect6",ArgStrArray("inp","outp","exp","tsp","sig")));// fs/select.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_ppoll",ArgStrArray("ufds","tsp","sigmask")));// fs/select.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_fanotify_mark",ArgStrArray("pathname")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_clone",ArgStrArray("parent_tidptr","child_tidptr")));// kernel/fork.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_perf_event_open",ArgStrArray("attr_uptr")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_old_mmap",ArgStrArray("arg")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_name_to_handle_at",ArgStrArray("name","handle","mnt_id")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_open_by_handle_at",ArgStrArray("handle")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_finit_module",ArgStrArray("uargs")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_seccomp",ArgStrArray("uargs")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_getrandom",ArgStrArray("buf")));//
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("SYSC_bpf",ArgStrArray("attr")));//   union bpf_attr *attr


		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("get_compat_msghdr",ArgStrArray("umsg","save_addr"))); //net/compat.c
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("copy_msghdr_from_user",ArgStrArray("umsg","save_addr"))); //net/socket.c

		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("func_main",ArgStrArray("m")));
		mapTable.insert(std::map<std::string, ArgStrArray>::value_type("sys_call",ArgStrArray("uptr")));

		//mapTable["func_main"] = ArgStrArray("m");

	}
	bool isSysFuncArg(std::string func, std::string arg) {
		it = mapTable.find(func);
		if(it != mapTable.end() && it->second.contains(arg)){
			//fout<<"[find arg in func] func:"<<func<<"arg: "<<arg<<std::endl;
			return true;
		}
		else
			return false;
	}
	bool isSysFunc(std::string func) {
		it = mapTable.find(func);
		if(it != mapTable.end() ){
			//fout<<"[find  func] func:"<<func<<std::endl;
			return true;
		}
		else
			return false;
	}

};






}// namespace end

