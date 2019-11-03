/* SPDX-License-Identifier: GPL-2.0 */
static const char __doc__[] = "XDP stats program\n"
	" - Finding xdp_stats_map via --dev name info\n";

static char prog_name[] = "xdp_firewall_stats";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <argp.h>

#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_user_bpf_xdp.h"
#include "../common/xdp_stats_kern_user.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */

bool verbose = true;

struct config {
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int ifindex;
};


static struct argp_option options[] = {
    {"dev", 'd', "DEVICE", 0, "Use device DEVICE"},
	{"quiet", 'q', 0, 0, "Quiet mode (no output)"},
    {0}
};

static error_t parse_opt(int key, char* optarg, struct argp_state *state)
{
	struct config *cfg = state->input;

	switch (key)
	{
	case 'd':
		if (strlen(optarg) >= IF_NAMESIZE) {
			fprintf(stderr, "ERR: --dev name too long\n");
			return ARGP_ERR_UNKNOWN;
		}
		cfg->ifname = (char *)&cfg->ifname_buf;
		strncpy(cfg->ifname, optarg, IF_NAMESIZE);
		cfg->ifindex = if_nametoindex(cfg->ifname);
		if (cfg->ifindex == 0) {
			fprintf(stderr,
				"ERR: --dev name unknown err(%d):%s\n",
				errno, strerror(errno));
			return ARGP_ERR_UNKNOWN;
		}
		break;
	
	case 'q':
        verbose = false;

	default:
		ARGP_ERR_UNKNOWN;
	}
	
	return 0;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(-1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[XDP_ACTION_MAX];
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print_header()
{
	/* Print stats "header" */
	printf("%-12s\n", "XDP-action");
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i;

	stats_print_header(); /* Print stats "header" */

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps     = packets / period;

		bytes   = rec->total.rx_bytes   - prev->total.rx_bytes;
		bps     = (bytes * 8)/ period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1000 , bps,
		       period);
	}
	printf("\n");
}


/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
	}
}

static int stats_poll(const char *pin_dir, int map_fd, __u32 id,
		      __u32 map_type, int interval)
{
	struct bpf_map_info info = {};
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */

		map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
		if (map_fd < 0) {
			return -1;
		} else if (id != info.id) {
			printf("BPF map xdp_stats_map changed its ID, restarting\n");
			return 0;
		}

		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

static struct argp argp = { options, parse_opt, 0, __doc__ };

int main(int argc, char **argv)
{
	const struct bpf_map_info map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct datarec),
		.max_entries = XDP_ACTION_MAX,
	};
	struct bpf_map_info info = { 0 };
	char pin_dir[PATH_MAX];
	int stats_map_fd;
	int interval = 2;
	int len, err;

	struct config cfg = {
		.ifindex   = -1,
	};

	/* Cmdline options can change progsec */
    argp_parse(&argp, argc, argv, 0, 0, &cfg);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		argp_help(&argp, stdout, ARGP_HELP_USAGE, prog_name);
		return -1;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return -1;
	}

	for ( ;; ) {
		stats_map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
		if (stats_map_fd < 0) {
			return -1;
		}

		/* check map info, e.g. datarec is expected size */
		err = check_map_fd_info(&info, &map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			return err;
		}
		if (verbose) {
			printf("\nCollecting stats from BPF map\n");
			printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			       " key_size:%d value_size:%d max_entries:%d\n",
			       info.type, info.id, info.name,
			       info.key_size, info.value_size, info.max_entries
			       );
		}

		err = stats_poll(pin_dir, stats_map_fd, info.id, info.type, interval);
		if (err < 0)
			return err;
	}

	return 0;
}
