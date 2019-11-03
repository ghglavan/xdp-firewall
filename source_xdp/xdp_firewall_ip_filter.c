const char* argp_program_version = "1.0.0.0";

static char prog_name[] = "xdp_firewall_ip_filter";

static const char __doc__[] = "XDP ip filter program\n"
	" - Block an --ip ip for a --dev device\n";

#include <arpa/inet.h>

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

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "common_kern_user.h"
#include "../common/common_user_bpf_xdp.h"

#include "bpf_util.h" /* bpf_num_possible_cpus */

static bool verbose = true;

struct config {
    char *ifname;
	char ifname_buf[IF_NAMESIZE];
    int ifindex;
    __u32 ip;
    const char* ip_str;
    const char* verdict_str;
    IP4_FILTER_MASK mask;
};



IP4_FILTER_MASK str_to_rule(const char* rule) {
    if (0 == strcmp(rule, "NONE"))
        return IP4_NONE;
    if (0 == strcmp(rule, "ACCEPT"))
        return IP4_ACCEPT;
    if (0 == strcmp(rule, "DROP"))
        return IP4_DROP;
    
    printf("Unknown rule %s.\n", rule);
    return IP4_UNKNOWN;
}

static struct argp_option options[] = {
    {"dev", 'd', "DEVICE", 0, "Use device DEVICE"},
    {"ip", 'i', "IP", 0, "Filter this ip"},
    {"vedict", 'v', "VERDICT", 0, "Verdict for this ip: {DROP, ACCEPT, NONE}"},
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
    
    case 'i':
        if (1 != inet_pton(AF_INET, optarg, &cfg->ip)) {
            fprintf(stderr, "inet_pton failed for %s\n\n", optarg);
            return ARGP_ERR_UNKNOWN;
        }
        cfg->ip_str = optarg;
        break;

    case 'v':
        cfg->verdict_str = optarg;

        IP4_FILTER_MASK verdict = str_to_rule(optarg);
        cfg->mask |= verdict;

        if (IP4_UNKNOWN != verdict)
            break;

        return ARGP_ERR_UNKNOWN;

    case 'q':
        verbose = false;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

void iterate_map(int filter_map_fd) {
    printf("iterating the map\n");
    __u32 prev_key = -1, key1;
    IP4_FILTER_MASK value;
    int res;
    while(bpf_map_get_next_key(filter_map_fd, &prev_key, &key1) == 0) {
        printf("Got key %lld ", key1);
        res = bpf_map_lookup_elem(filter_map_fd, &key1, &value);
        if(res < 0) {
            printf("No value??\n");
        } else {
            printf("%lld\n", value);
        }
        prev_key=key1;
    }

}

static struct argp argp = { options, parse_opt, 0, __doc__ };


int main(int argc, char **argv)
{
	const struct bpf_map_info map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(IP4_FILTER_MASK),
		.max_entries = MAX_IP4_FILTER_SIZE,
	};
	struct bpf_map_info info = { 0 };
	char pin_dir[PATH_MAX];
	int filter_map_fd;
	int len, err;

	struct config cfg = {
		.ifindex   = -1,
        .ip = 0,
        .ip_str = NULL,
        .mask = 0
	};

    argp_parse(&argp, argc, argv, 0, 0, &cfg);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		argp_help(&argp, stdout, ARGP_HELP_USAGE, prog_name);
		return -1;
	}

    if (NULL == cfg.ip_str) {
        fprintf(stderr, "ERR: required option --ip missing\n\n");
        argp_help(&argp, stdout, ARGP_HELP_USAGE, prog_name);
		return -1;
    }

    if (0 == cfg.mask) {
        fprintf(stderr, "ERR: required option --ip missing\n\n");
        argp_help(&argp, stdout, ARGP_HELP_USAGE, prog_name);
		return -1;
    }

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return -1;
	}

    filter_map_fd = open_bpf_map_file(pin_dir, "xdp_filter_ipv4", &info);
    if (filter_map_fd < 0) {
        printf("ERR: Could not find map xdp_filter_ipv4 in path %s\n", pin_dir);
		return -1;
    }

    err = check_map_fd_info(&info, &map_expect);
    if (err) {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return err;
    }

    printf("Checking for previous map values for %s (%d)\n", cfg.ip_str, cfg.ip);

    IP4_FILTER_MASK *v = NULL;
    if (bpf_map_lookup_elem(filter_map_fd, &cfg.ip, v)) {
        printf("No previous value \n");
    } else {
        printf("Previos verdict for %s (%d) : %d\n", cfg.ip_str, cfg.ip, *v);
    }

    if (verbose) {
        printf("\n Setting verdict %s to ip: %s (%d)\n", cfg.verdict_str, cfg.ip_str, cfg.ip);
    }

    iterate_map(filter_map_fd);

    if (bpf_map_update_elem(filter_map_fd, &cfg.ip, &cfg.mask, BPF_ANY)) {
        fprintf(stderr, "error updating map element: %s\n\n", strerror(errno));
        return -1;
    }

    iterate_map(filter_map_fd);

	return 0;
}
