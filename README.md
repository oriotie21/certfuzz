This project is modified version of certfuzz.

# If you are looking for runnable code, you should download the latest releases at: #

* BFF (linux, OSX) [https://vuls.cert.org/confluence/display/tools/CERT+BFF+-+Basic+Fuzzing+Framework](https://vuls.cert.org/confluence/display/tools/CERT+BFF+-+Basic+Fuzzing+Framework "BFF")



# What's changed? #

When inputs are different from command line argument (especially for directory based seedfile), this modified version of BFF can be used. 

## Example scenario ## 
```
C:\test\project1
    |- project.prj
    |- content.bin
    |- resource.png
```

Assume that project file structure looks like this,
When we want to load project by command line, project.prj file's location has to be speeicifed 
(example command line : "C:\bins\example.exe C:\test\project1\project.prj")

But we want to fuzz content file of the project, (content.bin in this case) 

then, set the 'target' category of bff.yaml like this..
```
target:
    program: C:\bins\example.exe
    name: project.prj
    mutate: content.bin
    cmdline_template: $PROGRAM $SEEDFILE

```
seedfile folder looks like...
```
<BFF installed location>\seedfiles
    |-project1
        |- project.prj
        |- content.bin
        |- resource.png
    |-project2
        |- project.prj
        |- content.bin
        |- resource.png
    |-project3
        |- project.prj
        |- content.bin
        |- resource.png
```
then, it will mutate content.bin, while using project.prj location as $SEEDFILE argument

# How to apply to original BFF? #
Currently, working only on windows. 

1. copy src\certfuzz directory to <'BFF installed location'>\certfuzz
2. go to <'BFF installed location'>\bff.yaml and set the value 'target' to...
```
target:
    program:
    name: ""
    mutate: ""
    cmdline_template:

```
3. put the seedfiles in and enjoy fuzz

# Using this code #

Depending on your preferred level of difficulty and experience points, choose from the options below.

## Easy ##

Most of the BFF code can be found in the certfuzz package `src/certfuzz`. To try out the certfuzz code in an existing installation of BFF, replace the `certfuzz` directory in your installation with the `certfuzz` directory found in this repository.

## Moderate ##

Some platform-specific stuff is in `src/windows` and `src/linux`. BFF for OSX uses `src/linux` too. See `src/linux/README` and `src/windows/README.txt` for platform-specific readmes, and `src/linux/INSTALL` if you are feeling extra adventurous.

## Hard ##

We actually use a continuous integration system with some platform-specific tools in conjunction with the code in the `build/` directory to build the releases found at the links above. However, at this time the build code is not expected to work anywhere other than that environment. In fact, the code in the master branch is svn-centric so it didn't even work when we switched to git. We've fixed that in our internal development system, but have not yet merged that in with the code posted here.

Furthermore, the build scripts modify some files and move things around to put together the release packages and build installers. The filenames (but not necessarily the locations) in the `src/` directories usually stay intact though so you should be able to figure out where things go if you are looking outside the `src/certfuzz` directory. (As mentioned in the *Easy* section above, `src/certfuzz` should just be a drop-in replacement.)

If all that seems more like a challenge than a warning, go for it.

## Experimental ##

See `src/experimental/README.md` for some dead ends that might be marginally useful.

# About BFF #

The CERT Basic Fuzzing Framework (BFF) is a software testing tool that finds defects in applications that run on Linux, Mac OS X and Windows.

BFF performs mutational fuzzing on software that consumes file input.  They automatically collect test cases that cause software to crash in unique ways, as well as debugging information associated with the crashes. The goal of BFF is to minimize the effort required for software vendors and security researchers to efficiently discover and analyze security vulnerabilities found via fuzzing.

## A brief history of BFF and FOE ##

BFF and FOE started out as two separate but related projects within the CERT/CC
Vulnerability Analysis team. Over time, they converged in their architecture to the point where BFF 2.7 and FOE 2.1 shared much of their code. As of BFF 2.8, this integration is complete and we have retired the name FOE in favor of BFF.

## For more information

Blog posts about BFF and FOE can be found in the [Vulnerability Discovery](https://insights.sei.cmu.edu/cert/vulnerability-discovery/) category on the [CERT/CC Blog](https://insights.sei.cmu.edu/cert/)
