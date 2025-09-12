---
layout: post
title: "Non-SQL kernel querying: how ip lists your interfaces"
date: 2025-09-12
---

``ip`` is one of the most useful tools when comes to managing network interfaces.<br/>
You can bring an interface up:
```
$ sudo ip link set wlp1s0 up
```
Set it in promiscuous mode:
```
$ sudo ip link set dev wlp1s0 promisc on
```
Show some of its information:
```
$ sudo ip link show wlp1s0
```

That last command shows this:<br/>
```
2: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether a4:c3:f0:82:e6:9b brd ff:ff:ff:ff:ff:ff
```

How does this work? Simple in theory: the kernel holds this information in some kind of data structure to be retrieved. How do you retrieve this? Two main paths can be followed:
* Old and deprecated: ioctl calls as ``ifconfig`` does
* New and standard: user-kernel socket communication as ip implements

We won't dive deep into that ifconfig approach, but instead we will see how ip uses ``netlink sockets`` to fetch information about network interfaces.

# Netlink Sockets

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
Be aware that it is correct to define the protocol field as an identifier of a kernel-side listening/sending socket.
Let me explain what I mean.

To be clear, I am running Ubuntu 20.04.06 LTS with Linux 5.15.175.
Code snippets may be outdated with respect to newer version of Linux, but typically the logic remains intact.
Back to sockets.
The creation of a kernel-side netlink socket is primarly handled by the ``netlink_kernel_create()`` function.
This is actually a wrapper to the more low-level \_\_netlink_kernel_create() found in net/netlink/af_netlink.c
We can 'grep' for this function call and find the active kernel-side netlink sockets.

```
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

Looking at `net/core/rtnetlink` reveals this:
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

# Netlink protocol(s)

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

The nlmsg_type field can assume four standard values: NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN (more on these later).
This field specifies the purpose/nature of the packet.
These traditional values are generic and interpreted alone cannot fulfill the various needs of the different subsystems that use netlink sockets.
For this reason, there is the tendency to add and define more specific packet types.
rtnetlink defines additionally: RTM_GETLINK, RTM_NEWROUTE, RTM_GETNEXTHOP and many others.
You can see all the routing specific packet types in `include/uapi/linux/rtnetlink.h`.
In our case, for retrieving information about network interfaces, we need to send a RTM_GETLINK packet to the routing subsystem.

Let's look at the other fields.

* nlmsg_seq is used as an identifier for the packet. It is used to associate request to response. A response packet must set its sequence number to the one of the request it answers for.
* nlmsg_pid identifies the sending process. Kernel messages are identified by 0, whereas user process usually use their pid.
* nlmsg_flags specify some properties of the packet. Each bit of this field has a particular meaning. For example, the bit called NLM_F_REQUEST, specifies that the packet is a request message. NLM_F_MULTI says that the packet is part of a collection of responses that answer to the same request. This last flag is used in case a single response packet cannot provide all the necessary information , or simply for a more logical and structured communication.
* nlmsg_len specifies the size of the whole packet: header length + payload length. More on this later.

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
I set the NLM_F_REQUEST flag, but also NLM_F_DUMP.
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

For our purpose we can simply zero-out the whole structure, but for more refined requests ifi_index, for example, is used to specify the interface to fetch (see 'ip a show' output).

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
struct iov;

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
