import sys
import struct

#
#    Fuzzing String BNF Definition (?)
#
#    <fuzzingString> ::= <string> | <string> <fuzzingString>
#    <string>        ::= <hexchars> | <hexchars> <multiplicity>
#    <hexchars>      ::= <hexchar> | <hexchar> <hexchars>
#    <hexchar>       ::= \x00 | \x01 | ... | \xff
#    <multiplicity>  ::= 0 | 1 | ... | 2^32
#

class FuzzingStrings:
    def __init__(self, filename = None):
        self.filename = filename
        self.fd       = None
    
    def decodeFuzzingString(self, fstring):
        pass
    
    def openFuzzingStrings(self, filename = None):
        if filename == None and self.filename == None:
            raise "You need to specify a filename"
        
        try:
            self.fd = open(filename, "w+")
        except e:
            print str(e)
            return False
    
        return True
    
    def getFuzzingString(self, index):
        self.fd.seek(0,0)
        
        lindex = 0
        
        while lindex < index:
            size = struct.unpack('I', self.fd.read(4))
            
            # Seek size bytes from the actual position
            try:
                self.fd.seek(size, 1)
            except e:
                print str(e)
                return False
            
            lindex = lindex + 1
        
        if lindex != index:
            raise "Invalid index, lindex != index"
        
        try:
            size = struct.unpack('I', self.fd.read(4))
            string = self.fd.read(size)
        except e:
            print str(e)
            return False
            
        return string
    
    def saveFuzzingString(self, string):
        # Position ourselves at the end of the file so we cann add the fs
        self.seek(0, -1)
        
        # Test if len resturns the real len of the fuzzing string
        try:
            size = len(string)
            self.fd.write(struct.pack('I', size) + string)
        except e:
            print str(e)
            return False
        
        return True
    
    

class Reproduce:
    def __init__(self):
        pass
    
    def getString(self, index):
        pass
