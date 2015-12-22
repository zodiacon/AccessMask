AccessMask is a command line tool that interprests handle access mask values (both generic and specific).

Usage: AccessMask [-d] <value> [type]
		
		value is interpreted as hex, unless the -d switch is specified (decimal).
		type is one of: process, thread, timer, key, event, mutex, semaphore, desktop, windowstation.
		
		Specific access mask bits will not be interpreted if type is not specified.
