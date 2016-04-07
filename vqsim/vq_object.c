/*
  This is a Votequorum object in the parent process. it's really just a conduit for the forked
  votequorum entity
*/

#include <qb/qblog.h>
#include <qb/qbloop.h>
#include <qb/qbipcc.h>
#include <netinet/in.h>

#include "../exec/votequorum.h"
#include "vqsim.h"
#include "../include/corosync/corotypes.h"
#include "../include/corosync/votequorum.h"
#include "../include/corosync/ipc_votequorum.h"

#define QDEVICE_NAME "VQsim_qdevice"
struct vq_instance
{
	int nodeid;
	int vq_socket;
	int qdevice_registered;
};

vq_object_t vq_create_instance(qb_loop_t *poll_loop, int nodeid)
{
	struct vq_instance *instance = malloc(sizeof(struct vq_instance));
	if (!instance) {
		return NULL;
	}

	instance->nodeid = nodeid;
	instance->qdevice_registered = 0;

	if (fork_new_instance(nodeid, &instance->vq_socket)) {
		free(instance);
		return NULL;
	}

	return instance;
}

void vq_quit(vq_object_t instance)
{
	struct vq_instance *vqi = instance;
	struct vqsim_msg_header msg;
	int res;

	msg.type = VQMSG_QUIT;
	msg.from_nodeid = 0;
	msg.param = 0;

	res = write(vqi->vq_socket, &msg, sizeof(msg));
	if (res <= 0) {
		perror("Quit write failed");
	}
}

int vq_set_nodelist(vq_object_t instance, struct memb_ring_id *ring_id, int *nodeids, int nodeids_entries)
{
	struct vq_instance *vqi = instance;
	char msgbuf[sizeof(int)*nodeids_entries + sizeof(struct vqsim_sync_msg)];
	struct vqsim_sync_msg *msg = (void*)msgbuf;
	int res;

//	fprintf(stderr, "vq_set_nodelist: %d nodes (ring_id.seq=%d)\n", nodeids_entries, ring_id->seq);
	msg->header.type = VQMSG_SYNC;
	msg->header.from_nodeid = 0;
	msg->header.param = 0;
	msg->view_list_entries = nodeids_entries;
	memcpy(&msg->view_list, nodeids, nodeids_entries*sizeof(int));
	memcpy(&msg->ring_id, ring_id, sizeof(struct memb_ring_id));

	res = write(vqi->vq_socket, msgbuf, sizeof(msgbuf));
	if (res <= 0) {
		perror("Sync write failed");
		return -1;
	}
	return 0;
}

int vq_set_qdevice(vq_object_t instance, struct memb_ring_id *ring_id, int onoff)
{
	struct vq_instance *vqi = instance;
	char msgbuf[sizeof(struct req_lib_votequorum_qdevice_poll) + sizeof(struct vqsim_lib_msg)];
	struct vqsim_lib_msg *msg = (void*)msgbuf;
	struct req_lib_votequorum_qdevice_register *regmsg = (void*)msgbuf+sizeof(struct vqsim_lib_msg);
	struct req_lib_votequorum_qdevice_poll *pollmsg = (void*)msgbuf+sizeof(struct vqsim_lib_msg);
	int res;

	msg->header.type = VQMSG_LIB;
	msg->header.from_nodeid = 0;
	msg->header.param = 0;

	// TODO: split this
	if (!vqi->qdevice_registered) {
		strcpy(regmsg->name, QDEVICE_NAME);
		regmsg->header.id = MESSAGE_REQ_VOTEQUORUM_QDEVICE_REGISTER;

		res = write(vqi->vq_socket, msgbuf, sizeof(msgbuf));
		if (res <= 0) {
			perror("qdevice register write failed");
			return -1;
		}
		vqi->qdevice_registered = 1;
		return 0;
	}
	else {
		strcpy(pollmsg->name, QDEVICE_NAME);
		pollmsg->header.id = MESSAGE_REQ_VOTEQUORUM_QDEVICE_POLL;
		pollmsg->cast_vote = onoff;
		pollmsg->ring_id.nodeid = ring_id->rep.nodeid;
		pollmsg->ring_id.seq = ring_id->seq;

		res = write(vqi->vq_socket, msgbuf, sizeof(msgbuf));
		if (res <= 0) {
			perror("qdevice poll write failed");
			return -1;
		}
	}
	return 0;
}

int vq_get_parent_fd(vq_object_t instance)
{
	struct vq_instance *vqi = instance;

	return vqi->vq_socket;
}
