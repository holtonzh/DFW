
ifneq ($(KERNELRELEASE),)

# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

obj-m := nf_match.o
nf_match-objs := match_rule.o match_nfhook.o netlink_kernel.o

else
CURBASE:=$(shell pwd)
KERNEL_SRC = $(firstword $(wildcard /lib/modules/$(shell uname -r)/build /usr/src/linux))
ifeq ($(KERNEL_SRC),)
$(error You need to define KERNEL_SRC)
endif

CC = gcc
EXTRA_CFLAGS = -O3 -Wall

all: 
	$(MAKE) -C $(KERNEL_SRC) SUBDIRS=$(CURBASE) modules


agentlog: log.c config.h runlog.h sqlite3.h ConnToServer.h
	gcc -Wall log.c sqlite3.c cJSON.c -I/usr/include/libxml2 -lxml2 -lcurl -g -o agentlog

parsexml: parse_xml.c cJSON.c  sqlite3.h ConnToServer.h config.h runlog.h cJSON.h
	gcc -g -Wall parse_xml.c sqlite3.c cJSON.c -I/usr/include/libxml2 -L/usr/lib -lxml2 -lcurl -lm -g -o parsexml

clean:
	-rm -f *.o *.so *.ko .*.cmd *.mod.c *.symvers *.unsigned *.order agentlog parsexml
endif
