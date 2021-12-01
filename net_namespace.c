#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <asm-generic/fcntl.h>

#include <linux/sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/net_namespace.h>
#include <asm/types.h>

#define MAX_PAYLOAD 1024
#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) && \
                nla->nla_len >= sizeof(struct nlattr) && \
				                nla->nla_len <= len)
#define NLA_NEXT(nla, len) (len -= NLA_ALIGN(nla->nla_len), \
                (struct nlattr *)(((char *)nla) + NLA_ALIGN(nla->nla_len)))
#define NLA_DATA(nla) (void *)((char *)(nla) + NLA_HDRLEN)

static int seq;

void get_ns_id(void) {
	int fd = 0;
	int file;
	struct sockaddr_nl addr;
	struct nlmsghdr *nl_hdr;
	struct iovec iov;
	struct msghdr msghdr;
	struct nlattr *payload;
	int len;
	pid_t pid;

	pid = getpid();
	memset(&addr, 0, sizeof(struct sockaddr_nl));
	memset(&msghdr, 0, sizeof(struct msghdr));
	seq = 0;
	do {
		fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (fd < 0)
			break;
		addr.nl_family = AF_NETLINK;
		if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)))
			break;

		nl_hdr = malloc(NLMSG_LENGTH(MAX_PAYLOAD));
		if (!nl_hdr)
			break;
		nl_hdr->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct rtgenmsg));
		((struct rtgenmsg *)NLMSG_DATA(nl_hdr))->rtgen_family = PF_UNSPEC;
		nl_hdr->nlmsg_seq = ++seq;
		nl_hdr->nlmsg_type = RTM_GETNSID;
		nl_hdr->nlmsg_pid = pid;
		nl_hdr->nlmsg_flags |= NLM_F_DUMP | NLM_F_REQUEST;
		payload = NLMSG_DATA(nl_hdr) + NLMSG_ALIGN(sizeof(struct rtgenmsg));
		payload->nla_type = NETNSA_PID;
		payload->nla_len = NLA_HDRLEN + sizeof(uint32_t);
		*(uint32_t *)(payload + NLA_HDRLEN) = pid;
		nl_hdr->nlmsg_len += (NLA_HDRLEN + sizeof(uint32_t));
		
		memset(&iov, 0, sizeof(iov));
		iov.iov_base = nl_hdr;
		iov.iov_len = nl_hdr->nlmsg_len;

		msghdr.msg_name = &addr;
		msghdr.msg_namelen = sizeof(addr);
		msghdr.msg_iov = &iov;
		msghdr.msg_iovlen = 1;
		len = sendmsg(fd, &msghdr, 0);
		if (len < 0)
			break;
		printf("send %d bytes\n", len);
		memset(nl_hdr, 0, NLMSG_LENGTH(MAX_PAYLOAD));
		addr.nl_groups = NETLINK_ROUTE;
		len = recvmsg(fd, &msghdr, sizeof(struct msghdr));
		printf("recv %d bytes\n", len);
		
		if (len < 0)
			break;
		switch (nl_hdr->nlmsg_type) {
		case RTM_NEWNSID:
			if (((struct rtgenmsg *)NLMSG_DATA(nl_hdr))->rtgen_family != PF_UNSPEC) {
				printf("unknow protocol %d\n", ((struct rtgenmsg *)NLMSG_DATA(nl_hdr))->rtgen_family);
				break;
			}
			len -= NLMSG_LENGTH(sizeof(struct rtgenmsg));
			payload = NLMSG_DATA(nl_hdr) + NLMSG_ALIGN(sizeof(struct rtgenmsg));
			file = open("/tmp/test", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
			if (file < 0) {
				printf("error %s\n", strerror(errno));
				break;
			}
			char buffer[64];
			while (NLA_OK(payload, len)) {
				printf("%d, %d\n", payload->nla_type, *(uint32_t *)NLA_DATA(payload));
				sprintf(buffer, "%d, %d", payload->nla_type, *(uint32_t *)NLA_DATA(payload));
				write(file, buffer, strlen(buffer));
				payload = NLA_NEXT(payload, len);
			}
			close(file);
		break;
		default:
			printf("unknow nlmsg_type %d\n", nl_hdr->nlmsg_type);
		break;
		}
		free(nl_hdr);
		exit(EXIT_SUCCESS);

	} while(0);

	printf("exception : %s\n", strerror(errno));

}

int main(int argc, char **argv) {
	void *child_stack;

	child_stack = (void *)malloc(16384);
	if (clone(get_ns_id, child_stack+10000, CLONE_NEWNS) < 0)
		printf("clone error %s\n", strerror(errno));
	sleep(3);
	get_ns_id();
}
