
typedef enum {VQMSG_QUIT=1,
	      VQMSG_SYNC,   /* set nodelist */
	      VQMSG_QUORUM, /* quorum state of this 'node' */
	      VQMSG_EXEC,   /* message for exec_handler */
} vqsim_msg_type_t;

typedef struct vq_instance *vq_object_t;

struct vqsim_msg_header
{
	vqsim_msg_type_t type;
	int from_nodeid;
	int param;
};

/* This is the sync sent from the controller process */
struct vqsim_sync_msg
{
	struct vqsim_msg_header header;
	struct memb_ring_id ring_id;
	size_t view_list_entries;
	unsigned int view_list[];
};

/* This is just info sent from each VQ instance */
struct vqsim_quorum_msg
{
	struct vqsim_msg_header header;
	int quorate;
	struct memb_ring_id ring_id;
	size_t view_list_entries;
	unsigned int view_list[];
};

struct vqsim_exec_msg
{
	struct vqsim_msg_header header;
	char execmsg[];
};



vq_object_t vq_create_instance(qb_loop_t *poll_loop, int nodeid);
void vq_quit(vq_object_t instance);
int vq_set_nodelist(vq_object_t instance, struct memb_ring_id *ring_id, int *nodeids, int nodeids_entries);
int vq_get_parent_fd(vq_object_t instance);

int fork_new_instance(int nodeid, int *vq_sock);
