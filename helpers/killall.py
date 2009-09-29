# Helper module to kill some lying process, there
# might be a command line to do this but it was easier
# to do the python so do not complain
# 
# email: agustingianni@gmail.com
#

import posix
import sys
import os

def main():
	if len(sys.argv) < 2:
		print "Argument missing, usage:\n"
		print "\t$ python %s process_name\n" %(sys.argv[0])
		sys.exit(0)

	readfd, writefd = posix.pipe()
	pid = os.fork()

	if pid:
    		os.close(writefd) # use os.close() to close a file descriptor

    		readfd = os.fdopen(readfd)
    		output = readfd.read()
		output = output.replace("\n", " ")		
    		
		os.waitpid(pid, 0) # make sure the child process gets cleaned up

		print "Killing " + output
		os.system("/bin/kill -9 " + output)
	else:
    		os.close(readfd)
		posix.dup2(writefd, 1)

		os.system("/usr/bin/pgrep " + sys.argv[1])

if __name__ == "__main__":
	main()
