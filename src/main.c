#include "sniffer.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	const char *ifname = (argc > 1) ? argv[1] : "enp1s0"; // use your iface
	printf("Listening on %s (promisc=1)...\n", ifname);
	return start_sniffer(ifname, /*promisc=*/1, /*count=*/-1);
}
