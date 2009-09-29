#
# Helper module that mount a given image and then executes some
# action to trigger some kind of action over the newly mounted file
# system, you might edit this at will.
# Remember that the more actions you make the fuzzer perform, the more
# bugs you can find, but also adding actions increases the fuzzing time 
#
# email: agustingianni@gmail.com
#

import sys
import os

def main():
    if sys.argv[1] == None or sys.argv[2] == None:
        print "Error we need two arguments"
        os.exit(-1)
        
    filename  = sys.argv[1]
    directory = sys.argv[2]
    command   = "/bin/ls -l " + directory
    
    os.system("/bin/mount -t iso9660 -o loop " + filename + " " + directory)
    os.system(command)
    os.system("/bin/umount " + directory)

if __name__ == "__main__":
    main()
