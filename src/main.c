#include "sniffer.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-i IFACE] [-n COUNT] [-f text|csv|json] [--no-promisc]\n"
        "       %s --help\n"
        "Defaults: auto-pick iface, COUNT=-1 (infinite), format=text, promisc=on\n",
        prog, prog);
}

int main(int argc, char **argv) {
    char iface[64] = {0};
    int count = -1;
    int promisc = 1;
    const char *format = "text";

    static struct option longopts[] = {
        {"iface",      required_argument, 0, 'i'},
        {"count",      required_argument, 0, 'n'},
        {"format",     required_argument, 0, 'f'},
        {"no-promisc", no_argument,       0, 'P'},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:n:f:Ph", longopts, NULL)) != -1) {
        switch (opt) {
            case 'i': snprintf(iface, sizeof(iface), "%s", optarg); break;
            case 'n': count = atoi(optarg); break;
            case 'f': format = optarg; break;
            case 'P': promisc = 0; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (iface[0] == '\0') {
        if (pick_default_iface(iface, sizeof(iface)) != 0) {
            fprintf(stderr, "Could not auto-pick interface. Use -i IFACE.\n");
            return 1;
        }
    }

    printf("Listening on %s (promisc=%d, count=%d, format=%s)...\n",
           iface, promisc, count, format);

    return start_sniffer(iface, promisc, count, format);
}
