# A *very* basic Makefile For the moment
# You will need to have build corosync first before this will work
#

CFLAGS=-Wall -I ../exec -I ../include -I ../include/corosync 
DEBUG=-O0 -g
CC=gcc

vqsim: vqmain.o vq_object.o vqsim_vq_engine.o parser.o \
	../exec/corosync-votequorum.o ../exec/corosync-icmap.o ../exec/corosync-logsys.o ../exec/corosync-coroparse.o ../exec/corosync-logconfig.o
	$(CC) -ovqsim $^ -lqb -L../common_lib/ -lcorosync_common -lreadline

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEBUG) $< -o $@

clean:
	rm -f vqsim *.o *~