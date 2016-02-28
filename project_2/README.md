# CSc 361: Computer Communications and Networks (Spring 2016)
## Assignment 2 - README

https://courses1.csc.uvic.ca/courses/2016/spring/csc/361

### Requirements
pcap library: libpcap, libpcap-dev

### Compiling
```bash
$ make
```

### Running
```bash
$ ./run <pcap>
```

# Explanations / Design Decisions

The duration was calculated using the GNU code for "timeval_subtract" and
 derivations of that method:

```c++
int timeval_subtract(struct timeval *result, struct timeval *x,
                     struct timeval *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}
```

Additionally, because no output format was specified for times, I have been outputting them using the method from the example Berkley code:

const char *timestamp_string(struct timeval ts);

I was not sure what was meant by the term data bytes in the assignment spec so I made the assumption that it includes the size of the header because wiresharks implementation does it that way but i implemented a method that gets the size of the payload without the header called "get_payload_size" in the util.cxx file.
