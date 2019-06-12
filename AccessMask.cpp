// AccessMask.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

#define THREAD_ALERT 4

#define DUMP_ACCESS_RIGHT(ss, value, right)	\
	if((value & right) == right) ss << "  " << std::setw(35) << std::left << #right << " (0x" << std::hex << right << ")" << std::endl;

#define PORT_CONNECT 0x0001
#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)

bool CheckParam(const TCHAR* param, const TCHAR* value);
int Usage();
string DumpAccessMask(DWORD value, LPCTSTR type);

int _tmain(int argc, _TCHAR* argv[]) {
	if(argc == 1)
		return Usage();
	int index = 1;
	bool decimal = CheckParam(argv[1], _T("-d"));
	if(decimal)
		index++;
	if(argc == index) {
		cout << "Too few arguments." << endl;
		return Usage();
	}

	DWORD value;
	wstringstream ss;
	if(!decimal)
		ss << hex;
	ss << argv[index++];
	ss >> value;

	auto type = index == argc ? _T("") : argv[index];
	cout << DumpAccessMask(value, type) << endl;

	return 0;
}

string DumpAccessMask(DWORD value, LPCTSTR type) {
	stringstream ss;
	ss << "Access mask: 0x" << hex << value << " (" << dec << value << ")" << endl;
	ss << "Generic rights:" << endl;
	DUMP_ACCESS_RIGHT(ss, value, READ_CONTROL);
	//DUMP_ACCESS_RIGHT(ss, value, STANDARD_RIGHTS_READ);
	//DUMP_ACCESS_RIGHT(ss, value, STANDARD_RIGHTS_WRITE);
	//DUMP_ACCESS_RIGHT(ss, value, STANDARD_RIGHTS_EXECUTE);
	DUMP_ACCESS_RIGHT(ss, value, STANDARD_RIGHTS_REQUIRED);
	DUMP_ACCESS_RIGHT(ss, value, STANDARD_RIGHTS_ALL);
	DUMP_ACCESS_RIGHT(ss, value, DELETE);
	DUMP_ACCESS_RIGHT(ss, value, SYNCHRONIZE);
	DUMP_ACCESS_RIGHT(ss, value, WRITE_DAC);
	DUMP_ACCESS_RIGHT(ss, value, WRITE_OWNER);
	DUMP_ACCESS_RIGHT(ss, value, ACCESS_SYSTEM_SECURITY);
	DUMP_ACCESS_RIGHT(ss, value, GENERIC_READ);
	DUMP_ACCESS_RIGHT(ss, value, GENERIC_WRITE);
	DUMP_ACCESS_RIGHT(ss, value, GENERIC_EXECUTE);
	DUMP_ACCESS_RIGHT(ss, value, GENERIC_ALL);

	if(*type) {
		wstring wtype(type);
		string stype;
		stype.assign(wtype.begin(), wtype.end());
		transform(stype.begin(), stype.end(), stype.begin(), ::tolower);
		ss << endl << "Specific rights (" << stype << "):" << endl;

		if(stype == "process") {
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_QUERY_LIMITED_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_SUSPEND_RESUME);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_QUERY_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_SET_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_SET_QUOTA);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_CREATE_PROCESS);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_DUP_HANDLE);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_VM_WRITE);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_VM_READ);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_VM_OPERATION);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_CREATE_THREAD);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_TERMINATE);
			DUMP_ACCESS_RIGHT(ss, value, PROCESS_ALL_ACCESS);
		}
		else if(stype == "thread") {
			DUMP_ACCESS_RIGHT(ss, value, THREAD_ALL_ACCESS);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_QUERY_LIMITED_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_SET_LIMITED_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_DIRECT_IMPERSONATION);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_IMPERSONATE);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_SET_THREAD_TOKEN);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_QUERY_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_SET_INFORMATION);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_SET_CONTEXT);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_GET_CONTEXT);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_SUSPEND_RESUME);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_TERMINATE);
			DUMP_ACCESS_RIGHT(ss, value, THREAD_ALERT);
		}
		else if(stype == "event") {
			DUMP_ACCESS_RIGHT(ss, value, EVENT_MODIFY_STATE);
			DUMP_ACCESS_RIGHT(ss, value, EVENT_ALL_ACCESS);
		}
		else if(stype == "mutex" || stype == "mutant") {
			DUMP_ACCESS_RIGHT(ss, value, MUTANT_QUERY_STATE);
			DUMP_ACCESS_RIGHT(ss, value, MUTEX_MODIFY_STATE);
			DUMP_ACCESS_RIGHT(ss, value, MUTEX_ALL_ACCESS);
		}
		else if(stype == "semaphore") {
			DUMP_ACCESS_RIGHT(ss, value, SEMAPHORE_MODIFY_STATE);
			DUMP_ACCESS_RIGHT(ss, value, SEMAPHORE_ALL_ACCESS);
		}
		else if(stype == "timer") {
			DUMP_ACCESS_RIGHT(ss, value, TIMER_QUERY_STATE);
			DUMP_ACCESS_RIGHT(ss, value, TIMER_MODIFY_STATE);
			DUMP_ACCESS_RIGHT(ss, value, TIMER_ALL_ACCESS);
		}
		else if(stype == "desktop") {
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_SWITCHDESKTOP);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_WRITEOBJECTS);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_ENUMERATE);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_JOURNALPLAYBACK);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_JOURNALRECORD);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_HOOKCONTROL);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_CREATEMENU);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_CREATEWINDOW);
			DUMP_ACCESS_RIGHT(ss, value, DESKTOP_READOBJECTS);
		}
		else if(stype == "windowstation" || stype == "winsta") {
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_READSCREEN);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_ENUMERATE);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_EXITWINDOWS);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_ACCESSGLOBALATOMS);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_WRITEATTRIBUTES);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_CREATEDESKTOP);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_ACCESSCLIPBOARD);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_READATTRIBUTES);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_ENUMDESKTOPS);
			DUMP_ACCESS_RIGHT(ss, value, WINSTA_ALL_ACCESS);
		}
		else if(stype == "key") {
			DUMP_ACCESS_RIGHT(ss, value, KEY_CREATE_LINK);
			DUMP_ACCESS_RIGHT(ss, value, KEY_NOTIFY);
			DUMP_ACCESS_RIGHT(ss, value, KEY_ENUMERATE_SUB_KEYS);
			DUMP_ACCESS_RIGHT(ss, value, KEY_CREATE_SUB_KEY);
			DUMP_ACCESS_RIGHT(ss, value, KEY_SET_VALUE);
			DUMP_ACCESS_RIGHT(ss, value, KEY_QUERY_VALUE);
			DUMP_ACCESS_RIGHT(ss, value, KEY_WOW64_64KEY);
			DUMP_ACCESS_RIGHT(ss, value, KEY_WOW64_32KEY);
			DUMP_ACCESS_RIGHT(ss, value, KEY_EXECUTE);
			DUMP_ACCESS_RIGHT(ss, value, KEY_READ);
			DUMP_ACCESS_RIGHT(ss, value, KEY_WRITE);
			DUMP_ACCESS_RIGHT(ss, value, KEY_ALL_ACCESS);
		}
		else if (stype == "token") {
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_ASSIGN_PRIMARY);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_DUPLICATE);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_IMPERSONATE);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_QUERY);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_QUERY_SOURCE);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_ADJUST_PRIVILEGES);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_ADJUST_GROUPS);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_ADJUST_DEFAULT);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_ADJUST_SESSIONID);
			DUMP_ACCESS_RIGHT(ss, value, TOKEN_ALL_ACCESS);
		}
		else if (stype == "job") {
			DUMP_ACCESS_RIGHT(ss, value, JOB_OBJECT_ASSIGN_PROCESS);
			DUMP_ACCESS_RIGHT(ss, value, JOB_OBJECT_SET_ATTRIBUTES);
			DUMP_ACCESS_RIGHT(ss, value, JOB_OBJECT_QUERY);
			DUMP_ACCESS_RIGHT(ss, value, JOB_OBJECT_TERMINATE);
			DUMP_ACCESS_RIGHT(ss, value, JOB_OBJECT_SET_SECURITY_ATTRIBUTES);
			DUMP_ACCESS_RIGHT(ss, value, JOB_OBJECT_ALL_ACCESS);
		}
		else if (stype == "file" || stype == "directory") {
			DUMP_ACCESS_RIGHT(ss, value, FILE_GENERIC_READ);
			DUMP_ACCESS_RIGHT(ss, value, FILE_READ_ATTRIBUTES);
			DUMP_ACCESS_RIGHT(ss, value, FILE_READ_DATA);
			DUMP_ACCESS_RIGHT(ss, value, FILE_READ_EA);
			DUMP_ACCESS_RIGHT(ss, value, FILE_GENERIC_WRITE);
			DUMP_ACCESS_RIGHT(ss, value, FILE_WRITE_ATTRIBUTES);
			DUMP_ACCESS_RIGHT(ss, value, FILE_WRITE_DATA);
			DUMP_ACCESS_RIGHT(ss, value, FILE_WRITE_EA);
			DUMP_ACCESS_RIGHT(ss, value, FILE_APPEND_DATA);
			DUMP_ACCESS_RIGHT(ss, value, FILE_GENERIC_EXECUTE);
			DUMP_ACCESS_RIGHT(ss, value, FILE_DELETE_CHILD);
			DUMP_ACCESS_RIGHT(ss, value, FILE_ALL_ACCESS);
		}
		else if (stype == "alpc" || stype == "port") {
			DUMP_ACCESS_RIGHT(ss, value, PORT_CONNECT);
			DUMP_ACCESS_RIGHT(ss, value, PORT_ALL_ACCESS);
		}
	}
	else {
		ss << "  (no object type) 0x" << hex << (value & 0xffff) << endl;
	}

	return ss.str();
}

bool CheckParam(const TCHAR* param, const TCHAR* value) {
	return ::_tcsicmp(param, value) == 0;
}

int Usage() {
	cout << "Usage: AccessMask [-d] <value> [type]" << endl 
		<< "value is interpreted as hex, unless the -d switch is specified (decimal)." << endl
		<< "type is one of: port (alpc) file, directory, process, thread, job, token, timer," << endl 
		<< " key, event, mutex (mutant), semaphore, desktop, windowstation (winsta). " << endl
		<< "Specific access mask bits will not be interpreted if type is not specified." << endl;
	return 1;
}
