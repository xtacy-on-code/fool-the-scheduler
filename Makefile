CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: usched job

usched: src/usched.c
	$(CC) $(CFLAGS) -o $@ $<

job: src/job.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f usched job
