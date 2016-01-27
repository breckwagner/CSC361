
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
$ ./server

Then to run a test execute:
$ ./client 

To sellect a non default server/host use: 
$ ./client <URI proto://host:port/path>


# TODO
################################################################################
- Seperate response body from response header using the newline char or 
  something simular
- 


# CHANGELOG
################################################################################





# DESIGN CONSIDERATIONS
################################################################################

Components                                         Weight    Progress
Make file                                          5         OK
Error handling in SimpClient                       10        Mostly
Correct output in SimpClient                       30        Mostly
status code 200 and correct content in SimpServer  20        x
status code 404 in SimpServer                      15        x
status code 501 in SimpServer                      10        x
Code style                                         5         OK
Readme.txt and change.txt(if any)                  5         OK
Total Weight                                       100       x