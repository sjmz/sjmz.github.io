---
layout: post
title: "Non-SQL kernel querying: how ip lists your interfaces"
date: 2025-09-12
---

**ip** is one of the most useful tools when comes to managing network interfaces.<br/>
You can bring an interface up:
```text
$ sudo ip link set wlp1s0 up
```
Set it in promiscuous mode:
```text
$ sudo ip link set dev wlp1s0 promisc on
```
Show some of its information:
```text
$ sudo ip link show wlp1s0
```

That last command shows this:<br/>
```text
2: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether a4:c3:f0:82:e6:9b brd ff:ff:ff:ff:ff:ff
```

How does this work? Simple in theory: the kernel holds this information in some kind of data structure to be retrieved. How do you retrieve this? Two main paths can be followed:
* Old and deprecated: ioctl calls as **ifconfig** does
* New and standard: user-kernel socket communication as ip implements

We won't dive deep into that ifconfig approach, but instead we will see how ip uses **netlink sockets** to fetch information about network interfaces.

# **netlink nockets**

The netlink protocol is a socket-based IPC (Inter Process Communication) mechanism based on RFC 3549.
It provides bidirectional communication between two or multiple processes.
The usual communication model expects a user process to talk to a kernel subsystem through a socket following the netlink protocol rules.

Information about network interfaces is handled by the routing subsystem, called ``rtnetlink``.<br/>
To communicate with it we first need to create a socket, in this way:
```c
int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
```
Notice how the domain and protocol fields are set.
AF_NETLINK refers to the general protocol, in this case netlink.
NETLINK_ROUTE specifies the netlink subsystem to talk to.
Be aware that it is correct to define the protocol field as the identifier of a kernel-side listening/sending socket.
Let me explain what I mean.

To be clear, I am running Ubuntu 20.04.06 LTS with Linux 5.15.175.
Code snippets may be outdated with respect to newer version of Linux, but typically the logic remains intact.
Back to sockets.
The creation of a kernel-side netlink socket is primarly handled by the ``netlink_kernel_create()`` function.
This is actually a wrapper to the more low-level \_\_netlink_kernel_create() found in net/netlink/af_netlink.c
We can 'grep' for this function call and find the active kernel-side netlink sockets.

```text
$ grep -R --include=*.c "= netlink_kernel_create\("
lib/kobject_uevent.c:	ue_sk->sk = netlink_kernel_create(net, NETLINK_KOBJECT_UEVENT, &cfg);
net/xfrm/xfrm_user.c:	nlsk = netlink_kernel_create(net, NETLINK_XFRM, &cfg);
net/ipv4/fib_frontend.c:	sk = netlink_kernel_create(net, NETLINK_FIB_LOOKUP, &cfg);
net/netlink/genetlink.c:	net->genl_sock = netlink_kernel_create(net, NETLINK_GENERIC, &cfg);
net/core/sock_diag.c:	net->diag_nlsk = netlink_kernel_create(net, NETLINK_SOCK_DIAG, &cfg);
net/core/rtnetlink.c:	sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);
net/netfilter/nfnetlink.c:	nfnlnet->nfnl = netlink_kernel_create(net, NETLINK_NETFILTER, &cfg);
security/selinux/netlink.c:	selnl = netlink_kernel_create(&init_net, NETLINK_SELINUX, &cfg);
crypto/crypto_user_base.c:	net->crypto_nlsk = netlink_kernel_create(net, NETLINK_CRYPTO, &cfg);
drivers/scsi/scsi_netlink.c:	scsi_nl_sock = netlink_kernel_create(&init_net, NETLINK_SCSITRANSPORT,
drivers/scsi/scsi_transport_iscsi.c:	nls = netlink_kernel_create(&init_net, NETLINK_ISCSI, &cfg);
drivers/staging/gdm724x/netlink_k.c:	sock = netlink_kernel_create(&init_net, unit, &cfg);
drivers/connector/connector.c:	dev->nls = netlink_kernel_create(&init_net, NETLINK_CONNECTOR, &cfg);
drivers/infiniband/core/netlink.c:	nls = netlink_kernel_create(net, NETLINK_RDMA, &cfg);
kernel/audit.c:	aunet->sk = netlink_kernel_create(net, NETLINK_AUDIT, &cfg);
```
Notice how that ``sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);`` aligns with its userland counterpart we create before.
In our case, sent messages will be received by this 'rtnetlink' kernel socket.

Looking at `net/core/rtnetlink.c` reveals this:
```c
static int __net_init rtnetlink_net_init(struct net *net)
{                                                            
        struct sock *sk;                                     
        struct netlink_kernel_cfg cfg = {                    
                .groups         = RTNLGRP_MAX,               
                .input          = rtnetlink_rcv,             
                .cb_mutex       = &rtnl_mutex,               
                .flags          = NL_CFG_F_NONROOT_RECV,     
                .bind           = rtnetlink_bind,            
        };                                                   
                                                             
        sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);
        if (!sk)                                             
                return -ENOMEM;                              
        net->rtnl = sk;                                      
        return 0;                                            
}                                                            
```

Little is going on here, but that ``cfg`` is very important.
``struct netlink_kernel_cfg`` defines some properties of a kernel netlink socket.
Notably, the ``input`` function field specifies the handler of incoming packets on that socket.
In this case set to ``rtnetlink_rcv``.

# **netlink protocol(s)**

A typical netlink message is comprised of a header and a payload.
Linux describes a netlink header with ``struct nlmsgh_hdr``, defined in include/uapi/linux/netlink.h as:
```c
struct nlmsghdr {                                                               
        __u32      nlmsg_len;    /* Length of message including header */
        __u16      nlmsg_type;   /* Message content */                   
        __u16      nlmsg_flags;  /* Additional flags */                  
        __u32      nlmsg_seq;    /* Sequence number */                   
        __u32      nlmsg_pid;    /* Sending process port ID */           
};                                                                              
```

The nlmsg_type field can assume four standard values: NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE and NLMSG_OVERRUN (more on NLMSG_DONE later).
This field specifies the purpose/nature of the packet.
The traditional values are generic and taken alone don't provide much information and cannot fulfill the various needs of the different subsystems that exploit netlink sockets.
For this reason, there is the tendency to add and define more specific packet types.
rtnetlink defines: RTM_GETLINK, RTM_NEWROUTE, RTM_GETNEXTHOP and many others.
You can see all the routing specific packet types in `include/uapi/linux/rtnetlink.h`.
In our case, for retrieving information about network interfaces, we need to send a RTM_GETLINK packet to the routing subsystem.

Let's look at the other fields.

* nlmsg_seq is used as an identifier for the packet. It is used to associate request to response. A response packet must set its sequence number to the one of the request it answers for.
* nlmsg_pid identifies the sending process. Kernel messages are identified by 0, whereas user process usually use their pid.
* nlmsg_flags specifies some properties of the packet. Usually, a single bit of this field has a particular meaning. For example, the bit called NLM_F_REQUEST, specifies that the packet is a request message. NLM_F_MULTI says that the packet is part of a collection of responses that answer to the same request. This last flag is used in case a single response packet cannot provide all the necessary information , or simply for a more logical and structured communication. 
* nlmsg_len specifies the size of the whole packet: header length + payload length. More on this later.

# **nlmsghdr construction**

With this we can start constructing our packet starting from the header:
```c
char send_buffer[MAX_PAYLOAD];
memset(send_buffer, 0, MAX_PAYLOAD);

struct nlmsghdr * nh = (struct nlmsghdr *) send_buffer;

nh_req->nlmsg_type = RTM_GETLINK;
nh_req->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP
nh_req->nlmsg_len = NLMSG_SPACE(sizeof(struct ifinfomsg));
nh_req->nlmsg_pid = getpid();
nh_req->nlmsg_seq = 1999;
```

I do not use dynamic memory for storing the packet, but I simply use a stack array that is sufficiently large for the whole message.

The first thing to notice is the value for the nlmsg_flags field.
The NLM_F_REQUEST flag is set, as well as NLM_F_DUMP.
This last flag tells rtnetlink to 'dump' the information of all the interfaces.

The value for nlmsg_len might seem weird but it simply respects that header length + payload length rule.
The NLMSG_SPACE macro is defined in the following manner (include/uapi/linux/netlink.h):
```c
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))                  
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)                         
#define NLMSG_HDRLEN     ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))    
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_ALIGNTO   4U                                               
```

This is an important convention rule: each packet section must be padded such that its size is aligned to / is a multiple of a defined constant.
For our request packet all sections are already aligned to 4 bytes, but it is good practice to have the general case in mind.
Also, from the two snippets just shown, you can guess what our payload is.

# **ifinfomsg construction**

``struct ifinfomsg`` is defined in include/uapi/linux/netlink.h as:
```c
struct ifinfomsg {                                                     
        unsigned char   ifi_family;                                    
        unsigned char   __ifi_pad;                                     
        unsigned short  ifi_type;      /* ARPHRD_* */         
        int             ifi_index;     /* Link index   */     
        unsigned        ifi_flags;     /* IFF_* flags  */     
        unsigned        ifi_change;    /* IFF_* change mask */
};                                                                     
```

For our purpose we can simply zero-out the whole structure, but ifi_index, for example, is used to specify the particular interface to fetch (see 'ip a show' output).

# **sending our message**

We can send our message with:
```c
write_size = sendmsg(socket, &msg, 0);
```

but first we need to understand that `msg` argument.

There is an indirect procedure when comes to sending data over a socket with sendmsg.
The second argument to a sendmsg call is a pointer to a variable of type `struct msghdr`, which is defined as:
```c
struct msghdr {                                                   
    void         *msg_name;       /* Optional address */          
    socklen_t     msg_namelen;    /* Size of address */           
    struct iovec *msg_iov;        /* Scatter/gather array */      
    size_t        msg_iovlen;     /* # elements in msg_iov */     
    void         *msg_control;    /* Ancillary data, see below */ 
    size_t        msg_controllen; /* Ancillary data buffer len */ 
    int           msg_flags;      /* Flags (unused) */            
};                                                                
```
Where, for our purpose:
* msg_name, believe it or not, specifies some information about the receiving socket
* msg_namelen specifies the size of the aformentioned data structure that holds receiving socket information
* msg_iov points to a structure called 'iovec'. This data structure refers to the actual data to send and its size
* msg_iovlen is the number of these aformentioned 'iovecs'

We can prepare all this with:
```c
struct sockaddr_nl dst_addr;
struct msghdr msg;
struct iovec iov;

memset(&dst_addr, 0, sizeof(dst_addr));
dst_addr.nl_family = AF_NETLINK;

memset(&msg, 0, sizeof(msg));

iov.iov_base = send_buffer;
iov.iov_len = nh_req->nlmsg_len;

msg.msg_name = &dst_addr;
msg.msg_namelen = sizeof(dst_addr);
msg.msg_iov = &iov;
msg.msg_iovlen = 1;
```

`struct sockaddr_nl` contains a field called 'nl_pid', which in our case must be set to 0 since we are talking to the kernel, remember?

# **interpreting the response**

The response to a RTM_GETLINK dump request is a packet comprised of: nlmsghdr + ifinfomsg + several attributes.
The ifinfomsg inside provides some general information about the interface. Most notably, the ifi_flags field is set to a value that represents the state of that device.
Reconsider the ip output and notice the various flags set for your interfaces:
```text
wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

Now to the attributes.
Interface name, MAC address, MTU value and other characteristics are packed in a structure called Type-Length-Value (TLV).
A TLV structure is actually a standard way of encoding information.
Type refers to how the attribute payload is to be interpreted.
Whether is a string, an integer number or some other kind of data.
Length is how much space the payload occupies.
Be aware that a length field isn't always to be considered as 'the number of bytes'.
Value is the actual payload (raw bytes).

What happens in practice is that rtnetlink has its own set of specific attribute types.
If we were to extract the interface name, we would search for a IFLA_IFNAME type of attribute in the attributes section of the response.
Similar thing for the MAC address which is identified with the IFLA_ADDRESS type.
You can look at all the specific attribute types in include/uapi/linux/if_link.h.

Just for completeness, look at how the attributes are set when a response to a rtnetlink dump request is constructed in the kernel.
rtnl_fill_ifinfo implemented in net/core/rtnetlink.c shows this:
```c
static int rtnl_fill_ifinfo(struct sk_buff *skb,
			    struct net_device *dev, // fetched interface
			    int type, u32 pid, u32 seq,
			    unsigned int flags, ...)
{
   struct ifinfomsg *ifm;
   struct nlmsghdr *nlh;
   [...]

   nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ifm), flags);
     // make space for nlmsghdr + ifinfomsg

   [...]

   ifm = nlmsg_data(nlh);  // (unsigned char *) nlh + NLMSG_HDRLEN;
   ifm->ifi_family = AF_UNSPEC;
   ifm->__ifi_pad = 0;
   ifm->ifi_type = dev->type;
   ifm->ifi_index = dev->ifindex;  // 1, 2, 3 as ip shows
   ifm->ifi_flags = dev_get_flags(dev);  // UP, BROADCAST, LOOKUP, PROMISC etc.
   ifm->ifi_change = change;

   [...]

   if (nla_put_string(skb, IFLA_IFNAME, dev->name) ||  // if. name: lo, wlp1s0 etc.
      nla_put_u32(skb, IFLA_TXQLEN, dev->tx_queue_len) ||
      nla_put_u8(skb, IFLA_OPERSTATE,
	       netif_running(dev) ? dev->operstate : IF_OPER_DOWN) ||
      nla_put_u8(skb, IFLA_LINKMODE, dev->link_mode) ||
      nla_put_u32(skb, IFLA_MTU, dev->mtu) ||

```

A few calls down from any 'nla_put' function, there is the presence of \_\_nla_reserve which makes space for the attribute to append and sets the TLV type field to the one specified as argument: IFLA_IFNAME, IFLA_TXQLEN, IFLA_LINKMODE etc.

# **more in-depth: nlmsghdr response**

Let's put together a simple example.
We send a RTM_GETLINK message and print the header of the netlink message we receive as response:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/if.h>

#define MAX_PAYLOAD 8192

void print_hdr(struct nlmsghdr * nh){
	printf("  length: %d\n", nh->nlmsg_len);
	printf("  type: %d\n", nh->nlmsg_type);
	printf("  flags: %d\n", nh->nlmsg_flags);
	printf("  seq: %d\n", nh->nlmsg_seq);
	printf("  port: %d\n", nh->nlmsg_pid);
}

int main(int argc, char ** argv[]){

	int s;
	ssize_t read_size, write_size;
	struct sockaddr_nl src_addr, dst_addr;
	struct msghdr req_msg, rsp_msg;
	struct iovec req_iov, rsp_iov;
	struct nlmsghdr * nh_req;
	struct nlmsghdr * nh_rsp;

	char send_buffer[MAX_PAYLOAD];
	char recv_buffer[MAX_PAYLOAD];

	printf("[*] user pid: %d\n", getpid());

	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if(s < 0){
		printf("[-] can't create socket\n");
		exit(-1);
	}

	printf("[+] NETLINK_ROUTE socket created\n");

	memset(&src_addr, 0, sizeof(src_addr));
	memset(&dst_addr, 0, sizeof(dst_addr));
	src_addr.nl_family = AF_NETLINK;
	dst_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	
	if(bind(s, (struct sockaddr *) &src_addr, sizeof(src_addr)) < 0){
		perror("[-] Can't bind");
		exit(-1);
	}

	printf("[+] NETLINK_ROUTE socket bound\n");

	memset(send_buffer, 0, MAX_PAYLOAD);
	memset(recv_buffer, 0, MAX_PAYLOAD);

	nh_req = (struct nlmsghdr *) send_buffer;

	nh_req->nlmsg_type = RTM_GETLINK;
	nh_req->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nh_req->nlmsg_len = NLMSG_SPACE(sizeof(struct ifinfomsg));
	nh_req->nlmsg_pid = getpid();
	nh_req->nlmsg_seq = 1999;

	memset(&req_msg, 0, sizeof(struct msghdr));
	req_iov.iov_base = send_buffer;
	req_iov.iov_len = nh_req->nlmsg_len;
	req_msg.msg_name = &dst_addr;
	req_msg.msg_namelen = sizeof(dst_addr);
	req_msg.msg_iov = &req_iov;
	req_msg.msg_iovlen = 1;

	write_size = sendmsg(s, &req_msg, 0);
	if(write_size < 0){
		perror("[-] Can't send data");
		exit(-1);
	}

	printf("[+] %ld bytes sent\n\n", write_size);

	memset(&rsp_msg, 0, sizeof(struct msghdr));
	rsp_iov.iov_base = recv_buffer;
	rsp_iov.iov_len = MAX_PAYLOAD;
	rsp_msg.msg_name = &dst_addr;
	rsp_msg.msg_namelen = sizeof(dst_addr);
	rsp_msg.msg_iov = &rsp_iov;
	rsp_msg.msg_iovlen = 1;


	read_size = recvmsg(s, &rsp_msg, 0);
	if(read_size < 0){
		perror("[-] Can't receive data");
		exit(-1);
	}

	nh_rsp = (struct nlmsghdr *) recv_buffer;
	printf("[ NLMSGHDR RSP ]\n");
	print_hdr(nh_rsp);

	close(s);

	return 0;
}
```
Simply compile with ``gcc yourfilename.c -o yourprogramname``

The associated output:

```text
$ ./netlink_simple
[*] user pid: 502006
[+] NETLINK_ROUTE socket created
[+] NETLINK_ROUTE socket bound
[+] 32 bytes sent

[ NLMSGHDR RSP ]
  length: 1348
  type: 16
  flags: 2
  seq: 1999
  port: 502006
```

Let's start simple.
Look at how the response matches both the process id of the sender and the sequence number of the request we made.
Next, **type: 16**.
By looking at include/uapi/linux/rtnetlink.h we can see that this response is a RTM_NEWLINK packet.
**flags: 2** means that the second bit of the flags field is set.
In the same file we can see how that bit is called NLM_F_MULTI.
This means that, as response, we got multiple RTM_NEWLINK packets.
One for each individual interface.
Since this very first response contains legit information we can investigate even more.

# **more in-depth: ifinfomsg response**

To see the content of the ifinfomsg section we can simply do this:

```c
void print_ifinfo(struct ifinfomsg * info){
	printf("  ifi_family: %d\n", info->ifi_family);
	printf("  __ifi_pad: %d\n", info->__ifi_pad);
	printf("  ifi_type: %d\n", info->ifi_type);
	printf("  ifi_index: %d\n", info->ifi_index);
	printf("  ifi_flags: %d\n", info->ifi_flags);
	printf("  ifi_change: %d\n", info->ifi_change);
}

int main ...

	[...]

	nh_rsp = (struct nlmsghdr *) recv_buffer;
	printf("[ IFINFOMSG RSP ]\n");
	print_ifinfo(NLMSG_DATA(nh_rsp));
}

```

The **NLMSG_DATA** macro jumps at the section right next to nlmsghdr, which in this case is the ifinfomsg structure.

The output of our little example is now this one:
```text
[*] user pid: 507368
[+] NETLINK_ROUTE socket created
[+] NETLINK_ROUTE socket bound
[+] 32 bytes sent

[ NLMSGHDR RSP ]
  length: 1348
  type: 16
  flags: 2
  seq: 1999
  port: 507368
[ IFINFOMSG RSP ]
  ifi_family: 0
  __ifi_pad: 0
  ifi_type: 772
  ifi_index: 1
  ifi_flags: 65609
  ifi_change: 0
```

The ifi_index value is '1' and the output of ``ip link`` shows me this.
```text
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether a4:c3:f0:82:e6:9b brd ff:ff:ff:ff:ff:ff
```
The response is about the interface of index 1: 'lo' a.k.a. **the loopback interface**.
Let's compare the interface flags we received as response to the ones shown by ip.
``65609`` is ``10000000001001001`` in binary.
**include/uapi/linux/if.h** shows this:
```c
enum net_device_flags {
/* for compatibility with glibc net/if.h */
#if __UAPI_DEF_IF_NET_DEVICE_FLAGS
	IFF_UP				= 1<<0,  /* sysfs */
	IFF_BROADCAST			= 1<<1,  /* volatile */
	IFF_DEBUG			= 1<<2,  /* sysfs */
	IFF_LOOPBACK			= 1<<3,  /* volatile */
	IFF_POINTOPOINT			= 1<<4,  /* volatile */
	IFF_NOTRAILERS			= 1<<5,  /* sysfs */
	IFF_RUNNING			= 1<<6,  /* volatile */
	IFF_NOARP			= 1<<7,  /* sysfs */
	IFF_PROMISC			= 1<<8,  /* sysfs */
	IFF_ALLMULTI			= 1<<9,  /* sysfs */
	IFF_MASTER			= 1<<10, /* volatile */
	IFF_SLAVE			= 1<<11, /* volatile */
	IFF_MULTICAST			= 1<<12, /* sysfs */
	IFF_PORTSEL			= 1<<13, /* sysfs */
	IFF_AUTOMEDIA			= 1<<14, /* sysfs */
	IFF_DYNAMIC			= 1<<15, /* sysfs */
#endif /* __UAPI_DEF_IF_NET_DEVICE_FLAGS */
#if __UAPI_DEF_IF_NET_DEVICE_FLAGS_LOWER_UP_DORMANT_ECHO
	IFF_LOWER_UP			= 1<<16, /* volatile */
	IFF_DORMANT			= 1<<17, /* volatile */
	IFF_ECHO			= 1<<18, /* volatile */
#endif /* __UAPI_DEF_IF_NET_DEVICE_FLAGS_LOWER_UP_DORMANT_ECHO */
};
```

We can deduce that the following bits are set: **IFF_UP**, **IFF_LOOPBACK**, **IFF_RUNNING** and **IFF_LOWER_UP**.
This is coherent to what ip teels us about the loopback interface.
At least with the IFF_UP, IFF_LOOPBACK and IFF_LOWER_UP bits.

Let's now extract the interface name and its MAC address stored in the attributes section of the response packet.
