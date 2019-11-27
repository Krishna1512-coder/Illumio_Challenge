# Illumio_Challenge

# Testing the solution
To test the implementation, I've used 'unittest' module of python. I've created different unit tests to check and test edge conditions

To run unit tests, run following command
```
python3 testing.py
```
# Design/Implementation
Time complexity of creating a firewall object is O(n logn), where n = number of rules

Time complexity of 'accept_packet' method is O(logn) in worst case, where n = number of rules

I am storing information in multilayer-hashmap. For example, firewall_rules["inbound"] will contain all the rules which has "inbound" direction.

Similarly, firewall_rules["inbound"]["tcp"][80] contains all rules which has "inbound" direction, "tcp" protocol and 80 as port

For rule like "outbound,tcp,10000-20000,192.168.10.11", I will store ip addess 192.168.10.11 for all ports between 10000-20000

There can be multiple ip address ranges for specific (direction, protocol, port) combination. I am assuming that this ip ranges can be overlapping. I am merging overlapping ranges and storing these ranges in sorted order which will help in lookup time(I am using binary search) while executing "accept_packet" method

To represnt ipaddress, I am converting ipaddress into int datatype.

**Tradeoff between space vs time complexity**
In my implementation, **accept_packet** method have O(logn). If we maintain hashmap for all ipaddresses instead storing ipaddress range directly, **accept_packet** will have O(1) time complexity. But in this case, memory requirement will be too high. Because for each (direction, protocol, port) combination, there can be 255^4 = 4294967296 possible ip addresses and there are 2*2*65535=262140 (direction, protocol, port) combinations. So overall,  it's not advisanle to store all ip addresses seperately in hashmap

# Assumptions
**1** all rules of csv file are well-defined

**2** csv file of rules can be very large

# Refinements or Optimizations
**1** I am using 'int' datatype of python to represent ipaddress and port. 'int' datatype using 32 bytes and 28 bytes respectively. I could have represent ipaddress and port in some compact manner to save some memory.
