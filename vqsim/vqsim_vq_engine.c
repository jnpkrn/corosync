
/* This is the bit of VQSIM that runs in the forked process.
   It represents a single votequorum instance or, if you like,
   a 'node' in the cluster.
*/

#include <sys/types.h>
#include <qb/qblog.h>
#include <qb/qbloop.h>
#include <qb/qbipc_common.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <stdio.h>

#include "../exec/votequorum.h"
#include <corosync/logsys.h>
#include <corosync/coroapi.h>
#include "service.h"
#include "icmap.h"

#include "vqsim.h"

/* Static variables here are per-instance because we are forked */
static struct corosync_service_engine *engine;
static int parent_socket; /* Our end of the socket */
static char buffer[8192];
static int our_nodeid;
static char *private_data;
static qb_loop_t *poll_loop;
static qb_loop_timer_handle sync_timer;
static int we_are_quorate;

static void api_error_memory_failure() __attribute__((noreturn));
static void api_error_memory_failure()
{
	fprintf(stderr, "Out of memory error\n");
	exit(-1);
}
static void api_timer_delete(corosync_timer_handle_t th)
{
	qb_loop_timer_del(poll_loop, th);
}

extern int api_timer_add_duration (
        unsigned long long nanosec_duration,
        void *data,
        void (*timer_fn) (void *data),
        corosync_timer_handle_t *handle)
{
        return qb_loop_timer_add(poll_loop,
				 QB_LOOP_MED,
                                 nanosec_duration,
                                 data,
                                 timer_fn,
                                 handle);
}

static unsigned int api_totem_nodeid_get()
{
	return our_nodeid;
}

static int api_totem_mcast(const struct iovec *iov, unsigned int iovlen, unsigned int type)
{
	struct vqsim_msg_header header;
	struct iovec iovec[iovlen+1];
	int total = sizeof(header);
	int res;
	int i;

	header.type = VQMSG_EXEC;
	header.from_nodeid = our_nodeid;
	header.param = 0;

	iovec[0].iov_base = &header;
	iovec[0].iov_len = sizeof(header);
	for (i=0; i<iovlen; i++) {
		iovec[i+1].iov_base = iov[i].iov_base;
		iovec[i+1].iov_len = iov[i].iov_len;
		total += iov[i].iov_len;
	}

	res = writev(parent_socket, iovec, iovlen+1);
	if (res != total) {
		fprintf(stderr, "writev wrong only %d of %d bytes\n", res, total);
	}
	return 0;
}
static void *api_ipc_private_data_get(void *conn)
{
	return private_data;
}
static int api_ipc_response_send(void *conn, const void *msg, size_t len)
{
	/* We don't really need this to do anything here */
	return 0;
}

static struct corosync_api_v1 corosync_api = {
	.error_memory_failure = api_error_memory_failure,
	.timer_delete = api_timer_delete,
	.timer_add_duration = api_timer_add_duration,
	.totem_nodeid_get = api_totem_nodeid_get,
	.totem_mcast = api_totem_mcast,
	.ipc_private_data_get = api_ipc_private_data_get,
	.ipc_response_send = api_ipc_response_send,
};

/* -------------------- Above is all for providing the corosync_api support routines --------------------------------------------*/
// CC: maybe put those in their own file.
/* --------------------------------------------------------------------------------- */

static void start_sync_timer(void);

/* Callback from Votequorum to tell us about the quorum state */
static void quorum_fn(const unsigned int *view_list,
		      size_t view_list_entries,
		      int quorate, struct memb_ring_id *ring_id)
{
	char msgbuf[8192];
	int len;
	struct vqsim_quorum_msg *quorum_msg = (void*) msgbuf;

	we_are_quorate = quorate;

	/* Send back to parent */
	quorum_msg->header.type = VQMSG_QUORUM;
	quorum_msg->header.from_nodeid = our_nodeid;
	quorum_msg->header.param = 0;
	quorum_msg->quorate = quorate;
	memcpy(&quorum_msg->ring_id, ring_id, sizeof(*ring_id));
	quorum_msg->view_list_entries = view_list_entries;

	memcpy(quorum_msg->view_list, view_list, sizeof(unsigned int)*view_list_entries);

	if ( (len=write(parent_socket, msgbuf, sizeof(*quorum_msg) + sizeof(unsigned int)*view_list_entries)) <= 0) {
		perror("write (view list to parent) failed");
	}
//	fprintf(stderr, "%d: quorum callback %d write returned %d\n", our_nodeid, quorate, len);
}

char *corosync_service_link_and_init(struct corosync_api_v1 *api,
				     struct default_service *engine)
{
	/* dummy */
	return NULL;
}

char *get_run_dir()
{
	static char cwd_buffer[PATH_MAX];

	return getcwd(cwd_buffer, PATH_MAX);
}

static int load_quorum_instance(struct corosync_api_v1 *api)
{
	const char *error_string;

	error_string = votequorum_init(api, quorum_fn);
	if (error_string) {
		fprintf(stderr, "Votequorum init failed: %s\n", error_string);
		return -1;
	}

	engine = votequorum_get_service_engine_ver0();
	error_string = engine->exec_init_fn(api);
	if (error_string) {
		fprintf(stderr, "votequorum exec init failed: %s\n", error_string);
		return -1;
	}
	return 0;
}

static void sync_dispatch_fn(void *data)
{
	if (engine->sync_process()) {
//		fprintf(stderr, "%d: waiting for sync to finish\n", our_nodeid);
		start_sync_timer();
	}
	else {
		engine->sync_activate();
	}
}

static void start_sync_timer()
{
	qb_loop_timer_add(poll_loop,
			  QB_LOOP_MED,
			  10000000,
			  NULL,
			  sync_dispatch_fn,
			  &sync_timer);
}

static void send_sync(char *buffer, int len)
{
	struct vqsim_sync_msg *msg = (void*)buffer;

	/* Votequorum doesn't use the transitional node list :-) */
	engine->sync_init(NULL, 0,
			  msg->view_list, msg->view_list_entries,
			  &msg->ring_id);

	start_sync_timer();
}

static void send_exec_msg(char *buffer, int len)
{
	struct vqsim_exec_msg *execmsg = (void*)buffer;
	struct qb_ipc_request_header *qb_header = (void*)execmsg->execmsg;

//	fprintf(stderr, "%d: EXEC message %d received from %d\n", our_nodeid, qb_header->id & 0xFFFF, execmsg->header.from_nodeid);
	engine->exec_engine[qb_header->id & 0xFFFF].exec_handler_fn(execmsg->execmsg, execmsg->header.from_nodeid);
}


/* From controller */
static int parent_pipe_read_fn(int32_t fd, int32_t revents, void *data)
{
	struct vqsim_msg_header *header = (void*)buffer;
	int len;

	len = read(fd, buffer, sizeof(buffer));
	if (len > 0) {
		/* Check header and route */
//		fprintf(stderr, "%d: message %d from parent pipe\n", our_nodeid, header->type);
		switch (header->type) {
		case VQMSG_QUIT:
			exit(0);
			break;
		case VQMSG_EXEC: // For votequorum exec
			send_exec_msg(buffer, len);
			break;
		case VQMSG_SYNC:
			send_sync(buffer, len);
			break;
		case VQMSG_QUORUM:
			/* not used here */
			break;
		}
	}
	return 0;
}

static void initial_sync(int nodeid)
{
	unsigned int trans_list[1] = {nodeid};
	unsigned int member_list[1] = {nodeid};
	struct memb_ring_id ring_id;
	ring_id.rep.nodeid = our_nodeid;
	ring_id.seq = 1;

	/* cluster with just us in it */
	engine->sync_init(trans_list, 1,
			  member_list, 1,
			  &ring_id);
	start_sync_timer();
}

/* Return pipe FDs if sucessful */
int fork_new_instance(int nodeid, int *vq_sock)
{
	int pipes[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, pipes)) {
		return -1;
	}
	parent_socket = pipes[0];

	switch (fork()) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child process - continue below */
		break;
	default:
		/* parent process */
		*vq_sock = pipes[1];
		return 0;
	}


	our_nodeid = nodeid;
	poll_loop = qb_loop_create();

	load_quorum_instance(&corosync_api);

	private_data = malloc(engine->private_data_size);
	if (!private_data) {
		perror("Malloc in child failed");
		return -1;
	}

	qb_loop_poll_add(poll_loop,
			 QB_LOOP_MED,
			 parent_socket,
			 POLLIN,
			 NULL,
			 parent_pipe_read_fn);

	/* Start it up! */
	initial_sync(nodeid);
	qb_loop_run(poll_loop);

	return 0;
}
