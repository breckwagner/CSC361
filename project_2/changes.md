# CSc 361: Computer Communications and Networks (Spring 2016)
## Assignment 2 - CHANGES

During the presentation, I did not have working code because I was still facing
issues porting the c code I had written to c++11. The changes to the file were immense after the presentation so listing them may be somewhat impractical.
After the assignment is due, I will push my changes to github under the url
https://github.com/breckwagner/CSC361 and make the repository public. If it is super necessary to look at changes, the diffs will show them.

### MAJOR CHANGES
- Switched from using the "got_packet" callback function for procedural logic
to an object oriented approach that is more robust and lass error prone

- Changed the initial code for the Connections class to copy the packets/headers
and used getter methods to return values pointing to the packets.

- Added avg, min, and max functions which ultimately were not used consistently
due to the nature of the statistics reporting. Changed to using
std::min_element and std::max_element.

- changed my printOutput and other code to use streams from the c++ std library
instead of printf statements.

- Lots of tweaking to the "Connection" class code.
