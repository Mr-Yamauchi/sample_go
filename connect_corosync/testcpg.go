package main

/* 
#cgo LDFLAGS: -lcpg

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <limits.h>

#include <corosync/corotypes.h>
#include <corosync/cpg.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

static int quit = 0;
static int show_ip = 0;
static int restart = 0;
static uint32_t nodeidStart = 0;

static void print_localnodeid(cpg_handle_t handle);
static int runs();

static void print_cpgname (const struct cpg_name *name)
{
	unsigned int i;

	for (i = 0; i < name->length; i++) {
		printf ("%c", name->value[i]);
	}
}

static char * node_pid_format(unsigned int nodeid, unsigned int pid) {
	static char buffer[100];
	if (show_ip) {
		struct in_addr saddr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
		saddr.s_addr = swab32(nodeid);
#else
		saddr.s_addr = nodeid;
#endif
		sprintf(buffer, "node/pid %s/%d", inet_ntoa(saddr),pid);
	} 
	else {
		sprintf(buffer, "node/pid %d/%d", nodeid, pid);
	} 
	return buffer;
}

static void
print_time(void)
{
#define     MAXLEN (256)
	char buf[MAXLEN];
	char hostname[HOST_NAME_MAX];
	struct timeval tnow;
	time_t t;
	size_t len;
	char *s = buf;

	len = sizeof(hostname);
	if(gethostname(hostname, len) == 0) {
		char *longName;
		hostname[len-1] = '\0';
		longName = hostname;
		if( (longName = strstr( hostname, "." )) != NULL )
		*longName = '\0';
	}

	strcpy(s, hostname);
	s += strlen(hostname);
	s += snprintf(s, sizeof(buf)-(s-buf), ":%d", getpid());
	t = time(0);
	gettimeofday( &tnow, 0 );
	s += strftime(s, sizeof(buf)-(s-buf) , " %Y-%m-%d %T", localtime(&t));
	s += snprintf(s, sizeof(buf)-(s-buf), ".%03ld", tnow.tv_usec/1000);
	assert(s-buf < (int)sizeof(buf));
	printf("%s\n", buf);
}

void goDeliverCallback(uint32_t nodeid, uint32_t pid, size_t msg_len, char *msg);

static void DeliverCallback (
	cpg_handle_t handle,
	const struct cpg_name *groupName,
	uint32_t nodeid,
	uint32_t pid,
	void *msg,
	size_t msg_len)
{
#if 0
	print_time();
	printf("DeliverCallback: message (len=%lu)from %s: '%s'\n",
		       (unsigned long int) msg_len, node_pid_format(nodeid, pid),
		       (const char *)msg);

#endif
	goDeliverCallback(nodeid, pid, msg_len, (char *)msg);
}

static struct cpg_address *getMember(struct cpg_address *ptr, uint32_t idx);
static struct cpg_address *getMember(struct cpg_address *ptr, uint32_t idx) {
	return (ptr+idx);
}

void goConfchgCallback(
	struct cpg_address *member_list, 
	size_t member_list_entries,
	struct cpg_address *left_list, 
	size_t left_list_entries,
	struct cpg_address *joined_list, 
	size_t joined_list_entries);

static void ConfchgCallback (
	cpg_handle_t handle,
	const struct cpg_name *groupName,
	const struct cpg_address *member_list, size_t member_list_entries,
	const struct cpg_address *left_list, size_t left_list_entries,
	const struct cpg_address *joined_list, size_t joined_list_entries)
{
	unsigned int i;
	int result;
	uint32_t nodeid;
#if 0
	for (i=0; i<joined_list_entries; i++) {
		printf("joined %s reason: %d\n",
				node_pid_format(joined_list[i].nodeid, joined_list[i].pid),
				joined_list[i].reason);
	}

	for (i=0; i<left_list_entries; i++) {
		printf("left %s reason: %d\n",
				node_pid_format(left_list[i].nodeid, left_list[i].pid),
				left_list[i].reason);
	}

	printf("nodes in group now %lu\n",
	       (unsigned long int) member_list_entries);
	for (i=0; i<member_list_entries; i++) {
		printf("%s\n",
				node_pid_format(member_list[i].nodeid, member_list[i].pid));
	}
#endif
	result = cpg_local_get(handle, &nodeid);
	if(result != CS_OK) {
		printf("failed to get local nodeid %d\n", result);
		nodeid = 0;
	}
	if (left_list_entries && (pid_t)left_list[0].pid == getpid()) {
		printf("We might have left the building pid %d\n", left_list[0].pid);
		if(nodeidStart) {
			if(htonl((uint32_t)nodeid) == INADDR_LOOPBACK) {
				printf("We probably left the building switched identity? start nodeid %d nodeid %d current nodeid %d pid %d\n", nodeidStart, left_list[0].nodeid, nodeid, left_list[0].pid);
			} else if(htonl((uint32_t)left_list[0].nodeid) == INADDR_LOOPBACK) {
				printf("We probably left the building started alone? start nodeid %d nodeid %d current nodeid %d pid %d\n", nodeidStart, left_list[0].nodeid, nodeid, left_list[0].pid);
			}
			if(left_list[0].nodeid == nodeidStart) {
				printf("We have left the building direct match start nodeid %d nodeid %d local get current nodeid %d pid %d\n", nodeidStart, left_list[0].nodeid, nodeid, left_list[0].pid);
				// quit = 1;
				restart = 1;
			} else {
				printf("Probably another node with matching pid start nodeid %d nodeid %d current nodeid %d pid %d\n", nodeidStart, left_list[0].nodeid, nodeid, left_list[0].pid);
			}
		}
	}
	goConfchgCallback(
		(struct cpg_address *)member_list, member_list_entries,
		(struct cpg_address *)left_list, left_list_entries,
		(struct cpg_address *)joined_list, joined_list_entries);
}

static uint32_t *getMember2(uint32_t *ptr, uint32_t idx);
static uint32_t *getMember2(uint32_t *ptr, uint32_t idx) {
	return (ptr+idx);
}

void goTotemchgCallback(
        struct cpg_ring_id ring_id,
        uint32_t member_list_entries,
        uint32_t *member_list);

static void TotemConfchgCallback (
	cpg_handle_t handle,
        struct cpg_ring_id ring_id,
        uint32_t member_list_entries,
        const uint32_t *member_list)
{
#if 0
	unsigned int i;

	printf("\n");
	print_time();
	printf ("TotemConfchgCallback: ringid (%u.%"PRIu64")\n",
		ring_id.nodeid, ring_id.seq);

	printf("active processors %lu: ",
	       (unsigned long int) member_list_entries);
	for (i=0; i<member_list_entries; i++) {
		printf("%d ", member_list[i]);
	}
	printf ("\n");
#endif
	goTotemchgCallback(ring_id, member_list_entries, (uint32_t *)member_list);
	
}

static cpg_model_v1_data_t model_data = {
	.cpg_deliver_fn =            DeliverCallback,
	.cpg_confchg_fn =            ConfchgCallback,
	.cpg_totem_confchg_fn =      TotemConfchgCallback,
	.flags =                     CPG_MODEL_V1_DELIVER_INITIAL_TOTEM_CONF,
};

static void sigintr_handler (int signum) __attribute__((noreturn));
static void sigintr_handler (int signum) {
	exit (0);
}
static struct cpg_name group_name;

#define retrybackoff(counter) {    \
		counter++;                    \
		printf("Restart operation after %ds\n", counter); \
		sleep((unsigned int)counter);               \
		restart = 1;			\
		continue;			\
}

#define cs_repeat_init(counter, max, code) do {    \
	code;                                 \
	if (result == CS_ERR_TRY_AGAIN || result == CS_ERR_QUEUE_FULL || result == CS_ERR_LIBRARY) {  \
		counter++;                    \
		printf("Retrying operation after %ds\n", counter); \
		sleep((unsigned int)counter);               \
	} else {                              \
		break;                        \
	}                                     \
} while (counter < max)

#define cs_repeat(counter, max, code) do {    \
	code;                                 \
	if (result == CS_ERR_TRY_AGAIN || result == CS_ERR_QUEUE_FULL) {  \
		counter++;                    \
		printf("Retrying operation after %ds\n", counter); \
		sleep((unsigned int)counter);               \
	} else {                              \
		break;                        \
	}                                     \
} while (counter < max)

static void print_localnodeid(cpg_handle_t handle)
{
	char addrStr[128];
	unsigned int retries;
	unsigned int nodeid;
	struct sockaddr_storage addr;
	struct sockaddr_in *v4addr = (struct sockaddr_in *)&addr;
	int result;

	retries = 0;

	cs_repeat(retries, 30, result = cpg_local_get(handle, &nodeid));
	if (result != CS_OK) {
		printf ("Could not get local node id\n");
	} else {
	v4addr->sin_addr.s_addr = nodeid;
	if(inet_ntop(AF_INET, (const void *)&v4addr->sin_addr.s_addr,
                           addrStr, (socklen_t)sizeof(addrStr)) == NULL) {
		addrStr[0] = 0;
	}
	printf ("Local node id is %s/%x result %d\n", addrStr, nodeid, result);
	}
}

int runs () {
	cpg_handle_t handle;
	fd_set read_fds;
	int select_fd;
	int result;
	int retries;
	const char *options = "i";
	int opt;
	unsigned int nodeid;
	char *fgets_res;
	struct cpg_address member_list[64];
	int member_list_entries;
	int i;
	int recnt;
	int doexit;
	const char *exitStr = "EXIT";

	doexit = 0;

	strcpy(group_name.value, "GROUP");
	group_name.length = 6;

	recnt = 0;

	printf ("Type %s to finish\n", exitStr);
	restart = 1;

	do {
		if(restart) {
			restart = 0;
			retries = 0;
			cs_repeat_init(retries, 30, result = cpg_model_initialize (&handle, CPG_MODEL_V1, (cpg_model_data_t *)&model_data, NULL));
			if (result != CS_OK) {
				printf ("Could not initialize Cluster Process Group API instance error %d\n", result);
				retrybackoff(recnt);
			}
			retries = 0;
			cs_repeat(retries, 30, result = cpg_local_get(handle, &nodeid));
			if (result != CS_OK) {
				printf ("Could not get local node id\n");
				retrybackoff(recnt);
			}
			printf ("Local node id is %x\n", nodeid);
			nodeidStart = nodeid;

			retries = 0;
			cs_repeat(retries, 30, result = cpg_join(handle, &group_name));
			if (result != CS_OK) {
				printf ("Could not join process group, error %d\n", result);
				retrybackoff(recnt);
			}

			retries = 0;
			cs_repeat(retries, 30, result = cpg_membership_get (handle, &group_name,
				(struct cpg_address *)&member_list, &member_list_entries));
			if (result != CS_OK) {
				printf ("Could not get current membership list %d\n", result);
				retrybackoff(recnt);
			}
			recnt = 0;

			printf ("membership list\n");
			for (i = 0; i < member_list_entries; i++) {
				printf ("node id %d pid %d\n", member_list[i].nodeid,
					member_list[i].pid);
			}

			FD_ZERO (&read_fds);
			cpg_fd_get(handle, &select_fd);
		}
		FD_SET (select_fd, &read_fds);
		FD_SET (STDIN_FILENO, &read_fds);
		result = select (select_fd + 1, &read_fds, 0, 0, 0);
		if (result == -1) {
			perror ("select\n");
		}
		if (FD_ISSET (STDIN_FILENO, &read_fds)) {
			char inbuf[132];
			struct iovec iov;

			fgets_res = fgets(inbuf, (int)sizeof(inbuf), stdin);
			if (fgets_res == NULL) {
				doexit = 1;
				cpg_leave(handle, &group_name);
			}
			if (strncmp(inbuf, exitStr, strlen(exitStr)) == 0) {
				doexit = 1;
				cpg_leave(handle, &group_name);
			}
			else {
				iov.iov_base = inbuf;
				iov.iov_len = strlen(inbuf)+1;
				cpg_mcast_joined(handle, CPG_TYPE_AGREED, &iov, 1);
			}
		}
		if (FD_ISSET (select_fd, &read_fds)) {
			if (cpg_dispatch (handle, CS_DISPATCH_ALL) != CS_OK) {
				if(doexit) {
					exit(1);
				}
				restart = 1;
			}
		}
		if(restart) {
			if(!doexit) {
				result = cpg_finalize (handle);
				printf ("Finalize+restart result is %d (should be 1)\n", result);
				continue;
			}
		}
	} while (result && !quit && !doexit);

	result = cpg_finalize (handle);
	printf ("Finalize  result is %d (should be 1)\n", result);
	return (0);
}
*/
import "C"
import "runtime"
import "fmt"

//export goConfchgCallback 
func goConfchgCallback(member_list *C.struct_cpg_address, member_list_entries C.size_t,
        left_list *C.struct_cpg_address, left_list_entries C.size_t,
        join_list *C.struct_cpg_address, joined_list_entries C.size_t) {

	fmt.Println("------------golang:ConfChg------------")
	fmt.Println("--member_ent :", member_list_entries)
	for i:= 0; i<int(member_list_entries);i++ {
		p := (*C.struct_cpg_address)(C.getMember(member_list, C.uint32_t(i)))
		fmt.Printf("-- member(%d:%d)\n", p.nodeid, p.pid)
	}
	fmt.Println("--left_ent :", left_list_entries)
	for j:= 0; j<int(left_list_entries);j++ {
		p := (*C.struct_cpg_address)(C.getMember(left_list, C.uint32_t(j)))
		fmt.Printf("-- left  (%d:%d)\n", p.nodeid, p.pid)
	}
	fmt.Println("--join_ent :", joined_list_entries)
	for k:= 0; k<int(joined_list_entries);k++ {
		p := (*C.struct_cpg_address)(C.getMember(join_list, C.uint32_t(k)))
		fmt.Printf("-- joined(%d:%d)\n", p.nodeid, p.pid)
	}
}

//export goDeliverCallback
func goDeliverCallback(nodeid C.uint32_t, pid C.uint32_t, msg_len C.size_t, msg *C.char) {
	fmt.Println("------------golang:Deliver------------")
	fmt.Printf("DeliverCallback: message (len=%d)from %s: %d:%d\n",
		       msg_len, C.GoString(msg), nodeid, pid)
}
//export goTotemchgCallback
func goTotemchgCallback(ring_id C.struct_cpg_ring_id,
        member_list_entries C.uint32_t,
        member_list *C.uint32_t){

	fmt.Println("------------golang:TotemchgCallback------------")
	fmt.Printf("goTotemConfchgCallback: ringid (%d.%d)\n", ring_id.nodeid, ring_id.seq)
	fmt.Printf("active processors %d: \n", member_list_entries)

	for i:=0; i<int(member_list_entries); i++ {
		p := (*C.uint32_t)(C.getMember2(member_list, C.uint32_t(i)))
		fmt.Printf(" %d \n", *p)
	}
}
//
func init() {
	runtime.LockOSThread()
}
//
func main() {
	ech := make(chan int)
	go func() {
		C.runs()
		ech<-1		
	}()
	select {
		case <-ech : break
	}
}
