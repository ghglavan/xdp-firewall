const char* argp_program_version = "1.0.0.0";

static char prog_name[] = "xdp_firewall_user";

static const char __doc__[] = "XDP firewall user\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

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
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */


#define XDP_COPY	(1 << 1) /* Force copy-mode */
#define XDP_ZEROCOPY	(1 << 2) /* Force zero-copy mode */

static bool verbose = true;

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	__u16 xsk_bind_flags;

};

#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const char *default_filename = "xdp_firewall_kernel.o";

static struct argp_option options[] = {
	{"dev", 'd', "DEVICE", 0, "Use device DEVICE"},
	{"skb-mode", 'S', 0, 0, "Install XDP program in SKB (AKA generic) mode"},
	{"native-mode", 'N', 0, 0, "Install XDP program in native mode"},
	{"auto-mode", 'A', 0, 0, "Auto-detect SDK or native mode"},
	{"force", 'F', 0, 0, "Force install, replacing existing program on interface"},
	{"unload", 'U', 0, 0, "Unload XDP program instead of loading"},
	{"reuse-maps", 'M', 0, 0, "Reuse pinned maps"},
	{"quiet", 'q', 0, 0, "Quiet mode (no output)"},
	{"filename", 'f', "FILENAME", 0, "Load a program from FILENAME"},
	{"progsec", 'p', "SEC", 0, "Load a program in SEC of the ELF file"},
	{0}
};

static error_t parse_opt(int key, char* optarg, struct argp_state *state)
{
	struct config *cfg = state->input;
	char* dest;

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

	case 'A':
		cfg->xdp_flags &= ~XDP_FLAGS_MODES;
		break;

	case 'S':
		cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
		cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
		cfg->xsk_bind_flags &= XDP_ZEROCOPY;
		cfg->xsk_bind_flags |= XDP_COPY;
		break;

	case 'N':
		cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
		cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
		break;

	case 'F':
		cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
		break;

	case 'U':
		cfg->do_unload = true;
		break;

	case 'M':
		cfg->reuse_maps = true;
		break;

	case 'q':
		verbose = false;
		break;

	case 'f':
		dest  = (char *)&cfg->filename;
		strncpy(dest, optarg, sizeof(cfg->filename));
		break;

	case 'p':
		dest  = (char *)&cfg->progsec;
		strncpy(dest, optarg, sizeof(cfg->progsec));
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;


	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, cfg->ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return -1;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return -2;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err)
		return -2;

	return 0;
}

static struct argp argp = { options, parse_opt, 0, __doc__ };


int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	int err, len;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progsec */

	argp_parse(&argp, argc, argv, 0, 0, &cfg);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		argp_help(&argp, stdout, ARGP_HELP_USAGE, prog_name);
		return -1;
	}
	if (cfg.do_unload) {
		if (!cfg.reuse_maps) {
		/* TODO: Miss unpin of maps on unload */
		}
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0, verbose);
	}

	len = snprintf(cfg.pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return -1;
	}


	bpf_obj = load_bpf_and_xdp_attach(cfg.xdp_flags, cfg.ifindex, cfg.reuse_maps, cfg.filename, cfg.progsec, cfg.pin_dir);
	if (!bpf_obj)
		return -2;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg.reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	return 0;
}
