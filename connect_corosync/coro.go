package main

/*
#cgo LDFLAGS: -lcpg
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <corosync/corotypes.h>
#include <corosync/cpg.h>

int wrap(cpg_handle_t *handle,
		cpg_callbacks_t *callbacks) {
	cpg_initialize (
		handle,
		callbacks);
}

int wrap_join(cpg_handle_t handle) {
	struct cpg_name group={5,"GROUP"};

	return cpg_join(handle, &group);
}

int wrap_membership_get(cpg_handle_t handle) {
	struct cpg_name group_name={5,"GROUP"};
	int result, i;
	struct cpg_address member_list[64];
	int member_list_entries;
	int retries;
	

	retries = 0;
	while(1) {
		result = cpg_membership_get (handle, &group_name,
			(struct cpg_address *)&member_list, &member_list_entries);
		if (result == CS_OK) break;
		retries++;
		if (retries >30) {
			break;
		}
	}

	if (result != CS_OK) {
		printf ("Could not get current membership list %d\n", result);
	}

	printf ("membership list\n");
	for (i = 0; i < member_list_entries; i++) {
		printf ("node id %d pid %d\n", member_list[i].nodeid,
			member_list[i].pid);
	}
	return 0;
}
int wrap_fd_get(cpg_handle_t handle, int *fd) {
	return cpg_fd_get(handle, fd);
}
*/
import "C"
import "fmt"
import "unsafe"
import "syscall"
import "runtime"

const (
	MaxEpollEvents = 32
	KB             = 1024
)
type Deliver func(
	handle C.cpg_handle_t,
	group_name *C.struct_cpg_name,
	nodeid	C.uint,
	pid	C.uint,
	msg *unsafe.Pointer)

type Confch func(
	handle C.cpg_handle_t,
	group_name *C.struct_cpg_name,
	member_list *C.struct_cpg_address, member_list_entries C.size_t,
	left_list *C.struct_cpg_address, left_list_entries C.size_t,
	join_list *C.struct_cpg_address, joined_list_entries C.size_t)

func init() {
    runtime.LockOSThread()
}
func deliver(
	handle C.cpg_handle_t,
	group_name *C.struct_cpg_name,
	nodeid	C.uint,
	pid	C.uint,
	msg *unsafe.Pointer) {
	
	fmt.Println("deliver")
}	
func confch(
	handle C.cpg_handle_t,
	group_name *C.struct_cpg_name,
	member_list *C.struct_cpg_address, member_list_entries C.size_t,
	left_list *C.struct_cpg_address, left_list_entries C.size_t,
	join_list *C.struct_cpg_address, joined_list_entries C.size_t) {

	fmt.Println("confch")
}

func echo(in, out int) {

 

	var buf [KB]byte

	for {

		nbytes, e := syscall.Read(in, buf[:])

		if nbytes > 0 {

			syscall.Write(out, buf[:nbytes])

		}

		if e != nil {

			break

		}

	}

}

func main() {
	var h C.cpg_handle_t = 0
	var nodeid C.uint = 0
	var deli Deliver = deliver
	var conf Confch = confch
	var event syscall.EpollEvent
	var events [MaxEpollEvents]syscall.EpollEvent

	cb := &C.cpg_callbacks_t {
		cpg_deliver_fn : (C.cpg_deliver_fn_t)(unsafe.Pointer(&deli)),
		cpg_confchg_fn : (C.cpg_confchg_fn_t)(unsafe.Pointer(&conf)),
 	}
	
	v := unsafe.Pointer(&h)
	y := unsafe.Pointer(cb)
	rc := C.cpg_initialize((*C.cpg_handle_t)(v), (*C.cpg_callbacks_t)(y))
	fmt.Println("initalize", rc)

	rc = C.cpg_local_get((C.cpg_handle_t)(h), (*C.uint)(&nodeid))
	fmt.Println("local_get", rc)

	rc2 := C.wrap_join((C.cpg_handle_t)(h))
	fmt.Println("join", rc2)

	rc3 := C.wrap_membership_get((C.cpg_handle_t)(h))
	fmt.Println("membership_get", rc3)

	var fd C.int
	rc4 := C.wrap_fd_get((C.cpg_handle_t)(h), (*C.int)(&fd))
	fmt.Println("fd_get", rc4, fd)
	
	if e := syscall.SetNonblock((int)(fd), true); e != nil {
		fmt.Println("setnonblock1: ", e)
	}
 
	epfd, e := syscall.EpollCreate1(0)
	if e != nil {
		fmt.Println("epoll_create1: ", e)
	}
	defer syscall.Close(epfd)

	event.Events = syscall.EPOLLIN
	event.Fd = int32(fd)
	if e = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, (int)(fd), &event); e != nil {
		fmt.Println("epoll_ctl: ", e)
	}

	for {
		nevents, e := syscall.EpollWait(epfd, events[:], -1)
		if e != nil {
			fmt.Println("epoll_wait: ", e)
			break
		}
 
		for ev := 0; ev < nevents; ev++ {
			if (events[ev].Fd == (int32)(fd)) {
				go echo(int(events[ev].Fd), syscall.Stdout)
			}
		}
	}

	fmt.Println("TEST",h)
	select {}
}
