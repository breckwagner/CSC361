
File: Readme.txt
Author: Richard B. Wagner
Date: 2016-01-XX
################################################################################

#REQUIREMENTS
################################################################################

This software requires a POSIX compliant environment. It is spacifically 
designed to run on Ubuntu GNU/Linux but parts of it have been tested on OS X (BSD) and 
FEDORA (Linux). 

# INSTALATION
################################################################################

From the terminal/console window in the working directory of the project, run 
the commands: 
$ make

# RUNNING
################################################################################

To start the server:
$ ./server 8080 ./

Then to run a test execute:
$ ./client http://localhost:8080/index.html

To sellect a non default server/host use: 
$ ./client <URI proto://host:port/path>

Note: to turn on verbos output to console, uncomment "#define DEBUG 3" in 'util.h'