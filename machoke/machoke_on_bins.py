import sys
import itertools


# file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT
NAME = 0
ARCH = 1
COMP = 2
VERS = 3
FLAG = 4
PLAT = 5



DB = [
  "random.txt",
  "different_archs.txt",
  "different_compilers.txt",
  "different_compiler_versions.txt",
  "different_flags.txt",
  "different_platforms.txt",
]
OUT_PATH = "../results/machoke_prog"

def main(argv):
    machoke = dict()
    file_write = list()
    with open(argv[1]) as f:
        for line in f: 
            file = line.split(',')[1]
            if 'ELF' in line.split(',')[1]:
                file_name = file.split('/')[-1]
                file_name = file_name[:-1] +  ".ELF"
            else:
                file_name = file.split('/')[-1] 
                file_name = file_name[:-1] +  ".PE"
            machoke[file_name] = line.split(',')[0]
    file_DB = {}
    file_DB[FLAG] = FindDiffX(machoke.keys(),list([FLAG]) , list([]))
    file_DB[VERS] = FindDiffX(machoke.keys(),list([VERS]) , list([]))
    file_DB[COMP] = FindDiffX(machoke.keys(),list([COMP]) , list([VERS]))
    file_DB[ARCH] = FindDiffX(machoke.keys(),list([ARCH]) , list([]))
    file_DB[PLAT] = FindDiffX(machoke.keys(),list([PLAT]), list([COMP,VERS,FLAG]))
    file_DB[NAME] = FindDiffX(machoke.keys(),list([]), list([ARCH,COMP,VERS,FLAG,PLAT]))

    for i in range(6):
        file_write = open(OUT_PATH + '/' + DB[i], "w")
        for file_pair in file_DB[i]:
            similarity = jaccardDistance(splitMachoke(machoke[file_pair[0]]), splitMachoke(machoke[file_pair[1]]))
            output = "{:.2f}, {}, {}\n".format(similarity, file_pair[0], file_pair[1])
            # print  (output)
            file_write.write(output)
        file_write.close()

            

def FindDiffX(files, X, dontcare):
    file_pairs = []

    # file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT
    for file_pair in itertools.combinations(files , r=2):
        fileone = file_pair[0].split('-') 
        filetwo = file_pair[1].split('-')
        fileone.append(file_pair[0].split('.')[-1])
        filetwo.append(file_pair[1].split('.')[-1])
        append = 1
        for i in range(6):
            if i in dontcare:
                continue

            if i in X:
                if fileone[i] == filetwo[i]:
                    append = 0
            else:
                if fileone[i] != filetwo[i]:
                    append = 0          

        if append:
            file_pairs.append(file_pair)

    return file_pairs
def jaccardDistance(mach1, mach2):
    s1 = set(mach1)
    s2 = set(mach2)
    return 100*float(len(s1.intersection(s2))) / float(len(s1.union(s2)))


def splitMachoke(machocke):
    return [machocke[i:i+8] for i in range(0, len(machocke), 8)]

if  __name__ == "__main__":
    main(sys.argv)