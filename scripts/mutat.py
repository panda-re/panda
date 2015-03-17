
import random
import sys



def mutfile(fn, start, end, suf):

    bytes = open(fn).read()
    new_fn = fn + '.' + suf
    f = open(new_fn, "w")

    i=0
    for b in bytes:
        if i<start :
            f.write(b)
        if (i>=start) and (i<=end):
            f.write(chr(random.randint(0,255)))
        if i>end :
            f.write(b)
        i+=1

    print "wrote " + new_fn



def main():
    print len(sys.argv)
    
#    if len(sys.argv) != 5:
#        print "Usage: mutat.py orig_file suf num_mut [start_byte end_byte]"
#        print "creates a new file called orig_file.suf with bytes between start_byte and end_byte replaced with random" 
#        sys.exit()
        
    fn = sys.argv[1]
    suf = sys.argv[2]
    num_mut = int(sys.argv[3])

    if num_mut == 1:
        start = int(sys.argv[4])
        end = int(sys.argv[5])
        mutfile(fn, start, end, suf)
    else:
        i=0
        while i<num_mut:
            num_bytes = len(open(fn).read())
            end = num_bytes
            while end > num_bytes-1:
                start = random.randint(0, num_bytes-1)
                end = start + 100
            mutfile(fn, start, end, "%s-%d" % (suf, i))
            i+=1

                   


if __name__ == "__main__":
    main()

