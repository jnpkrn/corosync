#include <sys/types.h>
#include <wait.h>
#include <qb/qblog.h>
#include <qb/qbloop.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/queue.h>

#include "../exec/votequorum.h"
#include <corosync/logsys.h>
#include <corosync/coroapi.h>
#include "service.h"
#include "icmap.h"
#include "vqsim.h"

/* Easier than including the config file with a ton of conflicting dependencies */
extern int coroparse_configparse (icmap_map_t config_map, const char **error_string);
extern int corosync_log_config_read (const char **error_string);

#define MAX_NODES 1024
#define MAX_PARTITIONS 16

/* One of these per partition */
struct vq_partition {
	TAILQ_HEAD(, vq_node) nodelist;
	struct memb_ring_id ring_id;
	int num;
};

/* One of these per node */
struct vq_node {
	vq_object_t instance;
	unsigned int nodeid;
	int fd;
	struct vq_partition *partition;
	TAILQ_ENTRY(vq_node) entries;
};

static struct vq_partition partitions[MAX_PARTITIONS];
static qb_loop_t *poll_loop;
static int autofence;

static void print_qmsg(struct vqsim_quorum_msg *qmsg)
{
	int i;

	fprintf(stderr, "%d: quorate = %d ring = %d/%lld ", qmsg->header.from_nodeid, qmsg->quorate, qmsg->ring_id.rep.nodeid, qmsg->ring_id.seq);
	fprintf(stderr, "nodes = [");
	for (i = 0; i<qmsg->view_list_entries; i++) {
		if (i) {
			fprintf(stderr, " ");
		}
		fprintf(stderr, "%d", qmsg->view_list[i]);
	}
	fprintf(stderr, "]\n");
}

static void propogate_vq_message(struct vq_node *vqn, const char *msg, int len)
{
	struct vq_node *other_vqn;

	/* Send it to everyone in that node's partition (including itself) */
	// TODO: ordering?
	TAILQ_FOREACH(other_vqn, &vqn->partition->nodelist, entries) {
		write(other_vqn->fd, msg, len);
	}
}

static int vq_parent_read_fn(int32_t fd, int32_t revents, void *data)
{
	char msgbuf[8192];
	int msglen;
	struct vqsim_msg_header *msg;
	struct vqsim_quorum_msg *qmsg;
	struct vq_node *vqn = data;

	if (revents == POLLIN) {
		msglen = read(fd, msgbuf, sizeof(msgbuf));
//		fprintf(stderr, "c: message received from child %d (len=%d)\n", vqn->nodeid, msglen);
		if (msglen < 0) {
			perror("read failed");
		}

		if (msglen > 0) {
			msg = (void*)msgbuf;
			switch (msg->type) {
			case VQMSG_QUORUM:
				qmsg = (void*)msgbuf;
				print_qmsg(qmsg);
				break;
			case VQMSG_EXEC:
				/* Message from votequorum, pass around the partition */
				propogate_vq_message(vqn, msgbuf, msglen);
				break;
			case VQMSG_QUIT:
			case VQMSG_SYNC:
				/* not used here */
				break;
			}
		}
	}
	if (revents == POLLERR) {
		fprintf(stderr, "pollerr on %d\n", vqn->nodeid);
	}
	return 0;
}


static int read_corosync_conf()
{
	int res;
	const char *error_string;

	int err = icmap_init();
	if (!err) {
		fprintf(stderr, "icmap_init failed\n");
	}

	/* Load corosync.conf */
	res = coroparse_configparse(icmap_get_global_map(), &error_string);
	if (res == -1) {
		log_printf (LOGSYS_LEVEL_INFO, "Error loading corosyc.conf %s", error_string);
		return -1;
	}
	else {
		res = corosync_log_config_read (&error_string);
		if (res < 0) {
			log_printf (LOGSYS_LEVEL_INFO, "error reading log config %s", error_string);
			syslog (LOGSYS_LEVEL_INFO, "error reading log config %s", error_string);
		}
		else {
			logsys_config_apply();
		}
	}
	if (logsys_thread_start() != 0) {
	        log_printf (LOGSYS_LEVEL_ERROR, "Can't initialize log thread");
		return -1;
	}
	return 0;

}

static int32_t sigchld_handler(int32_t signal, void *data)
{
	pid_t pid;
	int status;

	pid = wait(&status);
	if (WIFEXITED(status)) {
		fprintf(stderr, "child %d exited with status %d\n", pid, WEXITSTATUS(status));
	}
	if (WIFSIGNALED(status)) {
		fprintf(stderr, "child %d exited with status %d%s\n", pid, WTERMSIG(status), WCOREDUMP(status)?" (core dumped)":"");
	}
	return 0;
}

static void send_partition_to_nodes(struct vq_partition *partition)
{
	struct vq_node *vqn;
	int nodelist[MAX_NODES];
	int nodes = 0;
	int first = 1;

	/* Simulate corosync incrementing the seq by 4 for added authenticity */
	partition->ring_id.seq += 4;

	/* Build the node list */
	TAILQ_FOREACH(vqn, &partition->nodelist, entries) {
		nodelist[nodes++] = vqn->nodeid;
		if (first) {
			partition->ring_id.rep.nodeid = vqn->nodeid;
			first = 0;
		}
	}

	TAILQ_FOREACH(vqn, &partition->nodelist, entries) {
		vq_set_nodelist(vqn->instance, &partition->ring_id, nodelist, nodes);
	}
}

static void init_partitions()
{
	int i;

	for (i=0; i<MAX_PARTITIONS; i++) {
		TAILQ_INIT(&partitions[i].nodelist);
		partitions[i].ring_id.rep.nodeid = 1000+i;
		partitions[i].ring_id.seq = 0;
		partitions[i].num = i;
	}
}

static int create_node(int nodeid, int partno)
{
	struct vq_node *newvq;

	newvq = malloc(sizeof(struct vq_node));
	if (newvq) {
		newvq->instance = vq_create_instance(poll_loop, nodeid);
		newvq->partition = &partitions[partno];
		newvq->nodeid = nodeid;
		newvq->fd = vq_get_parent_fd(newvq->instance);
		TAILQ_INSERT_TAIL(&partitions[partno].nodelist, newvq, entries);

		if (qb_loop_poll_add(poll_loop,
				     QB_LOOP_MED,
				     newvq->fd,
				     POLLIN | POLLERR,
				     newvq,
				     vq_parent_read_fn)) {
			perror("qb_loop_poll_add returned error");
			return -1;
		}

		/* Send sync with all the nodes so far in it. */
		send_partition_to_nodes(&partitions[partno]);
	}
	return 0;
}

static void create_nodes_from_config(qb_loop_t *poll_loop)
{
	icmap_iter_t iter;
	char tmp_key[ICMAP_KEYNAME_MAXLEN];
	uint32_t node_pos;
	uint32_t nodeid;
	const char *iter_key;
	int res;

	init_partitions();

	iter = icmap_iter_init("nodelist.node.");
	while ((iter_key = icmap_iter_next(iter, NULL, NULL)) != NULL) {
		res = sscanf(iter_key, "nodelist.node.%u.%s", &node_pos, tmp_key);
		if (res != 2) {
			continue;
		}

		if (strcmp(tmp_key, "ring0_addr") != 0) {
			continue;
		}

		snprintf(tmp_key, ICMAP_KEYNAME_MAXLEN, "nodelist.node.%u.nodeid", node_pos);
		if (icmap_get_uint32(tmp_key, &nodeid) == CS_OK) {
			create_node(nodeid, 0);
		}

	}
	icmap_iter_finalize(iter);
}

static struct vq_node *find_node(int nodeid)
{
	int i;
	struct vq_node *vqn;

	for (i=0; i<MAX_PARTITIONS; i++) {
		TAILQ_FOREACH(vqn, &partitions[i].nodelist, entries) {
			if (vqn->nodeid == nodeid) {
				return vqn;
			}
		}
	}
	return NULL;
}

/* Routines called from the parser */
void cmd_start_new_node(int nodeid, int partition)
{
	struct vq_node *node;

	node = find_node(nodeid);
	if (node) {
		fprintf(stderr, "ERR: nodeid %d already exists in partition %d\n", nodeid, node->partition->num);
	}
	create_node(nodeid, partition);
}

void cmd_stop_node(int nodeid, int partition)
{
	struct vq_node *node;
	struct vq_partition *part;

	node = find_node(nodeid);
	if (!node) {
		fprintf(stderr, "ERR: nodeid %d is not up\n", nodeid);
		return;
	}

	if (partition != 0 && partition != node->partition->num) {
		fprintf(stderr, "ERR: nodeid %d is in partition %d\n", nodeid, node->partition->num);
		return;
	}
	part = node->partition;

	/* Remove processor */
	vq_quit(node->instance);

	/* Remove from partition list */
	TAILQ_REMOVE(&part->nodelist, node, entries);
	free(node);

	/* Rebuild quorum */
	send_partition_to_nodes(part);
}

void cmd_set_autofence(int onoff)
{
	autofence = onoff;
}

/* ---------------------------------- */

static int stdin_read_fn(int32_t fd, int32_t revents, void *data)
{
	char buffer[8192];
	int len;

	len = read(fd, buffer, sizeof(buffer));
	if (len) {
		if (buffer[len-1] == '\n') {
			buffer[len-1] = '\0';
		}
		else {
			buffer[len] = '\0';
		}
		parse_input_command(buffer, len);
	}
	else {
		exit(0);
	}

	return 0;
}

static void start_kb_input(qb_loop_t *poll_loop)
{
	if (qb_loop_poll_add(poll_loop,
			     QB_LOOP_MED,
			     STDIN_FILENO,
			     POLLIN | POLLERR,
			     NULL,
			     stdin_read_fn)) {
		perror("qb_loop_poll_add returned error");
	}
}

int main(int argc, char **argv)
{
	qb_loop_signal_handle sigchld_qb_handle;

	qb_log_filter_ctl(QB_LOG_SYSLOG, QB_LOG_FILTER_ADD,
			  QB_LOG_FILTER_FUNCTION, "*", LOG_DEBUG);

	qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_TRUE);
	qb_log_filter_ctl(QB_LOG_STDERR, QB_LOG_FILTER_ADD,
			  QB_LOG_FILTER_FUNCTION, "*", LOG_DEBUG);

	poll_loop = qb_loop_create();

	/* SIGCHLD handler to reap sub-processes */
	qb_loop_signal_add(poll_loop,
			   QB_LOOP_MED,
			   SIGCHLD,
			   NULL,
			   sigchld_handler,
			   &sigchld_qb_handle);

	/* Create a full cluster of nodes from corosync.conf */
	read_corosync_conf();
	create_nodes_from_config(poll_loop);

	start_kb_input(poll_loop);

	qb_loop_run(poll_loop);
	return 0;
}

