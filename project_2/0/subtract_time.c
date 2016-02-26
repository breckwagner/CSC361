/* Subtract the ‘struct timeval’ values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0. */

int
timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
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


printf("%s src_port=%d dst_port=%d length=%d\n",
  timestamp_string(tmp_time),
  ntohs(tcp->th_sport),
  ntohs(tcp->th_dport),
capture_length);// ntohs(tcp->uh_ulen)



/*
Connection::Connection(const Connection &copy_from) {
  this->sourceAddress = copy_from.sourceAddress;
  this->destinationAddress = copy_from.destinationAddress;
  this->sourcePort = copy_from.sourcePort;
  this->destinationPort = copy_from.destinationPort;
  this->endTime = copy_from.endTime;
  this->duration = copy_from.duration;

  this->numberPacketsSourceToDestination =
copy_from.numberPacketsSourceToDestination;
  this->numberPacketsDestinationToSource =
copy_from.numberPacketsDestinationToSource;

  this->numberBytesSourceToDestination =
copy_from.numberBytesSourceToDestination;
  this->numberBytesDestinationToSource =
copy_from.numberBytesDestinationToSource;
}*/
/*
Connection &Connection::operator=(const Connection &copy_from) {
  sourceAddress = copy_from.sourceAddress;
  destinationAddress = copy_from.destinationAddress;
  sourcePort = copy_from.sourcePort;
  destinationPort = copy_from.destinationPort;
  endTime = copy_from.endTime;
  duration = copy_from.duration;

  numberPacketsSourceToDestination = copy_from.numberPacketsSourceToDestination;
  numberPacketsDestinationToSource = copy_from.numberPacketsDestinationToSource;

  numberBytesSourceToDestination = copy_from.numberBytesSourceToDestination;
  numberBytesDestinationToSource = copy_from.numberBytesDestinationToSource;
  return *this;
}
*/
