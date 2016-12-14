#include <stdio.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"
//Inclure la structure pour bootp
#include "../../bootp.h"

void bootp(const u_char *appHeader){
	if (coloration) {
		printT(1, 8, KYEL"BOOTP\n");
	} else {
		printT(1, 8, "BOOTP\n");
	}

	const struct bootp *bootp = (const struct bootp *) appHeader;
  printT(0, 10, "|-Opcode                   : %d\n", bootp->bp_op);
	if (bootp->bp_htype == 1) {
		printT(0, 10, "|-Hardware type            : %s (0x%02x)\n", "Ethernet", bootp->bp_htype);
	} else {
		printT(0, 10, "|-Hardware type            : %s (0x%02x)\n", "Unknown", bootp->bp_htype);
	}
	printT(0, 10, "|-Hardware adress length   : %d\n", bootp->bp_hlen);
	printT(0, 10, "|-Hop count                : %d\n", bootp->bp_hops);
	printT(0, 10, "|-Transaction ID           : 0x%08x\n", ntohl(bootp->bp_xid)); //ntohl and not noths
	printT(0, 10, "|-Seconds since start      : %d\n", bootp->bp_secs);
	printT(0, 10, "|-Flags                    : 0x%04x %s\n", bootp->bp_flags, "(0x8000 is broadcast)");
	printT(0, 10, "|-Client IP Address        : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printT(0, 10, "|-\"Your\" IP Address        : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printT(0, 10, "|-Server IP Address        : %s\n", inet_ntoa(bootp->bp_siaddr));
	printT(0, 10, "|-Gateway IP Address       : %s\n", inet_ntoa(bootp->bp_giaddr));
	printT(0, 10, "|-Client MAC Address       : %s\n", ether_ntoa((const struct ether_addr*)&bootp->bp_chaddr));
	printT(0, 10, "|-Server host name         : %s\n", bootp->bp_sname);
	printT(0, 10, "|-Boot filename            : %s\n", bootp->bp_file);

	//------------Vendor specific (DHCP : 63 82 53 63)-----------------------
	if (testMagicCookie(bootp->bp_vend)) {
		const u_int8_t *dhcp = bootp->bp_vend + 4;
		printT(0, 14, "|-DHCP");
		printDhcp(dhcp);
		printT(1, 10, "");

	}
	if (coloration) {
		printf(KNRM);
	}
}

int testMagicCookie(const u_int8_t *bp_vend){
	int magicCookie[4] = {99, 130, 83, 99};
	int testDhcp = 1; //Par défaut DHCP
	printT(0, 10, "|-Vendor specific          : 0x");
	size_t i;
	for (i = 0; i < 4; i++) {
		printT(0, 0, "%02x", bp_vend[i]);
		if (magicCookie[i] != bp_vend[i]) {
			testDhcp = 0;
		}
	}
	if (testDhcp) {
		printT(0, 0, " (DHCP)");
	}
	printT(1, 0, "");
	return testDhcp;
}

void printDhcp(const u_int8_t *dhcp){
	size_t i = 0;
	int opt;
	for (i = 0; i < 60; i++) {
		if (opt != TAG_END) {
			printT(1, 14, "|-Option : ");
			opt = option(dhcp, &i);
			if (opt == TAG_END) {
				printT(1, 14, "|-Padding (%d) : ", 60 - i);
			}
		} else {
				printT(0, 0, "%d", dhcp[i]);
		}
	}
}

int option(const u_int8_t *dhcp, size_t *i){
	size_t length = 0;
	size_t len = 0;
	int tag = -1;

	switch (dhcp[*i]) {
		case TAG_DHCP_MESSAGE:
			printT(0, 0, "%s (%d)\n", "DHCP Message Type", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			printT(0, 16, "|-Length : %d", length);
			*i = *i + length;
			typeDhcp(dhcp[*i]);
			 return TAG_DHCP_MESSAGE;
			break;
		case TAG_CLIENT_ID:
			printT(0, 0, "%s (%d)\n", "CLIENT_ID", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_CLIENT_ID;
			break;
		case TAG_HOSTNAME:
			printT(0, 0, "%s (%d)\n", "HOSTNAME", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_HOSTNAME;
			break;
		case TAG_PARM_REQUEST:
			printT(0, 0, "%s (%d)\n", "PARM_REQUEST", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_PARM_REQUEST;
			break;
		case TAG_GATEWAY:
			printT(0, 0, "%s (%d)\n", "GATEWAY", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_GATEWAY;
			break;
		case TAG_DOMAIN_SERVER:
			printT(0, 0, "%s (%d)\n", "DOMAIN_SERVER", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_DOMAIN_SERVER;
			break;
		case TAG_SUBNET_MASK:
			printT(0, 0, "%s (%d)\n", "SUBNET_MASK", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SUBNET_MASK;
			break;
		case TAG_DOMAINNAME:
			printT(0, 0, "%s (%d)\n", "DOMAINNAME", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_DOMAINNAME;
			break;
		case TAG_SERVER_ID:
			printT(0, 0, "%s (%d)\n", "SERVER_ID", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SERVER_ID;
			break;
		case TAG_IP_LEASE:
			printT(0, 0, "%s (%d)\n", "IP_LEASE", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SERVER_ID;
			break;
		case TAG_REBIND_TIME:
			printT(0, 0, "%s (%d)\n", "REBIND_TIME", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SERVER_ID;
			break;
		case TAG_END:
			printT(0, 0, "%s (%d)\n", "END", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			printT(0, 16, "|-Length : %d", length);

			if (len < length) {
				printT(1, 16, "|-Data   : ");

				while (len < length && *i < 60) {
					*i = *i + 1;
					len++;
					printT(0, 0, "%02x (%d) ", dhcp[*i], dhcp[*i]);
				}
			}
			return TAG_END;
			break;
		default:
			printT(0, 0, "%s (%d)\n", "Unknown", dhcp[*i]);
			*i = *i + 1;
			tag = -1;
			break;
	}
	length = dhcp[*i];
	printT(0, 16, "|-Length : %d", length);

	if (len < length) {
		printT(1, 16, "|-Data   : ");

		while (len < length && *i < 60) {
			*i = *i + 1;
			len++;
			printT(0, 0, "%02x (%d) ", dhcp[*i], dhcp[*i]);
		}
	}

	return tag;
}

void typeDhcp(const u_int8_t val){
	printT(1, 16, "|-Message type : ");
	switch (val) {
		case DHCPDISCOVER:
			printT(0, 0, "DHCPDISCOVER");
			break;
		case DHCPOFFER:
			printT(0, 0, "DHCPOFFER");
			break;
		case DHCPREQUEST:
			printT(0, 0, "DHCPREQUEST");
			break;
		case DHCPDECLINE:
			printT(0, 0, "DHCPDECLINE");
			break;
		case DHCPACK:
			printT(0, 0, "DHCPACK");
			break;
		case DHCPNAK:
			printT(0, 0, "DHCPNAK");
			break;
		case DHCPRELEASE:
			printT(0, 0, "DHCPRELEASE");
			break;
		case DHCPINFORM:
			printT(0, 0, "DHCPINFORM");
			break;
		default:
			printT(0, 0, "Unknown");
			break;
	}
	printT(0, 1, "");
}
