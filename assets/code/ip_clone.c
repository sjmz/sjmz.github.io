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

void print_ifinfo(struct ifinfomsg * info){
	printf("     | ifi_family: %d\n", info->ifi_family);
	printf("     | __ifi_pad: %d\n", info->__ifi_pad);
	printf("     | ifi_type: %d\n", info->ifi_type);
	printf("     | ifi_index: %d\n", info->ifi_index);
	printf("     | ifi_flags: %d\n", info->ifi_flags);
	printf("     | ifi_change: %d\n", info->ifi_change);
}

void print_hdr(struct nlmsghdr * nh){
	printf("  | length: %d\n", nh->nlmsg_len);
	printf("  | type: %d\n", nh->nlmsg_type);
	printf("  | flags: %d\n", nh->nlmsg_flags);
	printf("  | seq: %d\n", nh->nlmsg_seq);
	printf("  | port: %d\n", nh->nlmsg_pid);
}

void print_nlattr(struct nlattr * attr){
	printf("  type: %d\n", attr->nla_type);
	printf("  len: %d\n", attr->nla_len);
}

void print_mac(struct nlattr * attr){
	unsigned char * mac;
	mac = ((char *) attr) + NLA_HDRLEN;
	printf("        | MAC address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ifname(struct nlattr * attr){
	printf("        | interface: %s\n", ((char *) attr) + NLA_HDRLEN);
}

void print_attr(struct nlmsghdr * nh){
	struct nlattr * attr;
	int asize;

	attr = (struct nlattr * )(((char *) nh) + NLMSG_ALIGN(NLMSG_HDRLEN + sizeof(struct ifinfomsg)));
	asize = nh->nlmsg_len - NLMSG_ALIGN(NLMSG_HDRLEN + sizeof(struct ifinfomsg));

	while(asize > 0){
		if(attr->nla_type == 1)
			print_mac(attr);
		if(attr->nla_type == 3)
			print_ifname(attr);

		asize = asize - NLA_ALIGN(attr->nla_len);
		attr = (struct nlattr *)(((char *) attr) + NLA_ALIGN(attr->nla_len));
	}
}

int main(int argc, char ** argv[]){

	int s;
	ssize_t read_size, write_size;
	struct sockaddr_nl src_addr, dst_addr;
	struct msghdr req_msg, rsp_msg;
	struct iovec req_iov, rsp_iov;
	struct nlmsghdr * nh_req;
	struct nlmsghdr * nh_rsp;
	struct nlattr * attr;
	
	int asize;
	int finish = 0;

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

	printf("[+] %ld bytes sent\n", write_size);

	memset(&rsp_msg, 0, sizeof(struct msghdr));
	rsp_iov.iov_base = recv_buffer;
	rsp_iov.iov_len = MAX_PAYLOAD;
	rsp_msg.msg_name = &dst_addr;
	rsp_msg.msg_namelen = sizeof(dst_addr);
	rsp_msg.msg_iov = &rsp_iov;
	rsp_msg.msg_iovlen = 1;

	while(!finish){
		nh_rsp = (struct nlmsghdr *) recv_buffer;

		read_size = recvmsg(s, &rsp_msg, 0);
		if(read_size < 0){
			perror("[-] Can't receive data");
			exit(-1);
		}
	
		while(nh_rsp->nlmsg_type != NLMSG_DONE && read_size > 0){
			printf("\n[ NLMSGHDR ]\n");
			print_hdr(nh_rsp);
			printf("  [ IFINFOMSG ]\n");
			print_ifinfo(NLMSG_DATA(nh_rsp));
			printf("     [ ATTR ]\n");
			print_attr(nh_rsp);	

			read_size = read_size - nh_rsp->nlmsg_len;
			nh_rsp = (struct nlmsghdr *)(((char *) nh_rsp) + nh_rsp->nlmsg_len);
		}

		finish = nh_rsp->nlmsg_type == NLMSG_DONE;
	}

	close(s);

	return 0;
}
