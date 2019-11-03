/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

// ip4 filters
#define IP4_FILTER_MASK unsigned char

#define IP4_NONE    0x0
#define IP4_ACCEPT  0x1
#define IP4_DROP    0x2
#define IP4_ABORT   0x3
#define IP4_UNKNOWN 0x4
// TODO:
//#define IP4_FORWARD 0x4

// end of ip4 filters

#define MAX_IP4_FILTER_SIZE 10000

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};



#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
