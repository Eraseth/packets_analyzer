#include <stdio.h>
#include <netinet/ether.h>
#include "../../inc/analyseur.h"
//Inclure la structure pour bootp
#include "../../bootp.h"

/* Affichage de BOOTP (et DHCP si nécéssaire) */
void bootp(const u_char *appHeader){
	const struct bootp *bootp = (const struct bootp *) appHeader;

	/*
	---------------Verbose 1------------------
	*/
	if (verbose == 1) {
		if (coloration) {
			printT(0, 0, "-"KYEL"BOOTP");
		} else {
			printT(0, 0, "-BOOTP");
		}
		testMagicCookieVerbose(bootp->bp_vend);
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ;
	}

	if (coloration) {
		printT(1, BOOTPSPACE-TITLESPACE, KYEL"BOOTP");
	} else {
		printT(1, BOOTPSPACE-TITLESPACE, "BOOTP");
	}
	testMagicCookieVerbose(bootp->bp_vend);

	/*
	---------------Verbose 2------------------
	*/
	if (verbose == 2) {
		printT(0, 0, "|-Opcode : %d ", bootp->bp_op);
		printT(0, 0, "|-Client IP Address : %s ", inet_ntoa(bootp->bp_ciaddr));
		printT(0, 0, "|-Server IP Address : %s ", inet_ntoa(bootp->bp_siaddr));
		printT(0, 0, "|-Gateway IP Address : %s", inet_ntoa(bootp->bp_giaddr));
		if (coloration) {
			printT(0, 0, KNRM);
		}
		return ;
	}

	/*
	---------------Verbose 3------------------
	*/
  printT(1, BOOTPSPACE, "|-Opcode                   : %d\n", bootp->bp_op);
	if (bootp->bp_htype == 1) {
		printT(0, BOOTPSPACE, "|-Hardware type            : %s (0x%02x)\n", "Ethernet", bootp->bp_htype);
	} else {
		printT(0, BOOTPSPACE, "|-Hardware type            : %s (0x%02x)\n", "Unknown", bootp->bp_htype);
	}
	printT(0, BOOTPSPACE, "|-Hardware adress length   : %d\n", bootp->bp_hlen);
	printT(0, BOOTPSPACE, "|-Hop count                : %d\n", bootp->bp_hops);
	printT(0, BOOTPSPACE, "|-Transaction ID           : 0x%08x\n", ntohl(bootp->bp_xid)); //ntohl and not noths
	printT(0, BOOTPSPACE, "|-Seconds since start      : %d\n", bootp->bp_secs);
	printT(0, BOOTPSPACE, "|-Flags                    : 0x%04x %s\n", bootp->bp_flags, "(0x8000 is broadcast)");
	printT(0, BOOTPSPACE, "|-Client IP Address        : %s\n", inet_ntoa(bootp->bp_ciaddr));
	printT(0, BOOTPSPACE, "|-\"Your\" IP Address        : %s\n", inet_ntoa(bootp->bp_yiaddr));
	printT(0, BOOTPSPACE, "|-Server IP Address        : %s\n", inet_ntoa(bootp->bp_siaddr));
	printT(0, BOOTPSPACE, "|-Gateway IP Address       : %s\n", inet_ntoa(bootp->bp_giaddr));
	printT(0, BOOTPSPACE, "|-Client MAC Address       : %s\n", ether_ntoa((const struct ether_addr*)&bootp->bp_chaddr));
	printT(0, BOOTPSPACE, "|-Server host name         : %s\n", bootp->bp_sname);
	printT(0, BOOTPSPACE, "|-Boot filename            : %s\n", bootp->bp_file);

	//------------Vendor specific (DHCP : 63 82 53 63)-----------------------
	if (testMagicCookie(bootp->bp_vend)) {
		const u_int8_t *dhcp = bootp->bp_vend + 4;
		printT(0, DHCPSPACE, "|-DHCP");
		printDhcp(dhcp);
		printT(1, BOOTPSPACE, "");
	}

	if (coloration) {
		printT(0, 0, KNRM);
	}
}

/* Test la partie Vendor specific pour vérifier si DHCP.
Affiche également les valeurs du vendor specific */
int testMagicCookie(const u_int8_t *bp_vend){
	int magicCookie[4] = {99, 130, 83, 99};
	int testDhcp = 1; //Par défaut DHCP
	printT(0, BOOTPSPACE, "|-Vendor specific          : 0x");
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

/* Identique à la fonction ci-dessus mais sans affichage pour les niveau de
verbose < 3 */
int testMagicCookieVerbose(const u_int8_t *bp_vend){
	int magicCookie[4] = {99, 130, 83, 99};
	int testDhcp = 1; //Par défaut DHCP
	size_t i;
	for (i = 0; i < 4; i++) {
		if (magicCookie[i] != bp_vend[i]) {
			testDhcp = 0;
		}
	}
	if (testDhcp) {
		printT(0, 0, "(DHCP)");
	}
	return testDhcp;
}

/* Affiche les valeurs dans la partie DHCP */
void printDhcp(const u_int8_t *dhcp){
	size_t i = 0;
	int opt;
	// 60 = Vendor specific - Magic Cookie (64 - 4)
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

/* Verifie les options DHCP et affiche en conséquence */
int option(const u_int8_t *dhcp, size_t *i){
	size_t length = 0;
	size_t len = 0;
	int tag = -1;

	switch (dhcp[*i]) {
		case TAG_DHCP_MESSAGE:
			printT(0, 0, "%s (%d)\n", "DHCP Message Type", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			printT(0, DHCPSPACE+UNDERSPACE, "|-Length : %d", length);
			*i = *i + length;
			typeDhcp(dhcp[*i]);
			 return TAG_DHCP_MESSAGE;
			break;
		case TAG_CLIENT_ID:
			printT(0, 0, "%s (%d)\n", "Client-identifier", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_CLIENT_ID;
			break;
		case TAG_HOSTNAME:
			printT(0, 0, "%s (%d)\n", "Host Name", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_HOSTNAME;
			break;
		case TAG_PARM_REQUEST:
			printT(0, 0, "%s (%d)\n", "Parameter Request List", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_PARM_REQUEST;
			break;
		case TAG_GATEWAY:
			printT(0, 0, "%s (%d)\n", "Router", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_GATEWAY;
			break;
		case TAG_DOMAIN_SERVER:
			printT(0, 0, "%s (%d)\n", "Domain Name Server", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_DOMAIN_SERVER;
			break;
		case TAG_SUBNET_MASK:
			printT(0, 0, "%s (%d)\n", "Subnet Mask", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SUBNET_MASK;
			break;
		case TAG_DOMAINNAME:
			printT(0, 0, "%s (%d)\n", "Domain Name", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_DOMAINNAME;
			break;
		case TAG_SERVER_ID:
			printT(0, 0, "%s (%d)\n", "Server Identifier", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SERVER_ID;
			break;
		case TAG_IP_LEASE:
			printT(0, 0, "%s (%d)\n", "IP address Lease Time", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SERVER_ID;
			break;
		case TAG_REBIND_TIME:
			printT(0, 0, "%s (%d)\n", "Rebinding (T2) Time Value", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			tag = TAG_SERVER_ID;
			break;
		case TAG_END:
			printT(0, 0, "%s (%d)\n", "END", dhcp[*i]);
			*i = *i + 1;
			length = dhcp[*i];
			printT(0, DHCPSPACE+UNDERSPACE, "|-Length : %d", length);

			if (len < length) {
				printT(1, DHCPSPACE+UNDERSPACE, "|-Data   : ");

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
	printT(0, DHCPSPACE+UNDERSPACE, "|-Length : %d", length);

	if (len < length) {
		printT(1, DHCPSPACE+UNDERSPACE, "|-Data   : ");

		while (len < length && *i < 60) {
			*i = *i + 1;
			len++;
			printT(0, 0, "%02x (%d) ", dhcp[*i], dhcp[*i]);
		}
	}

	return tag;
}

/* Verifi le type DHCP et affiche la valeur en conséquence */
void typeDhcp(const u_int8_t val){
	printT(1, DHCPSPACE+UNDERSPACE, "|-Message type : ");
	switch (val) {
		case DHCPDISCOVER:
			printT(0, 0, "DHCP Discovery");
			break;
		case DHCPOFFER:
			printT(0, 0, "DHCP Offer");
			break;
		case DHCPREQUEST:
			printT(0, 0, "DHCP Request");
			break;
		case DHCPDECLINE:
			printT(0, 0, "DHCPDECLINE");
			break;
		case DHCPACK:
			printT(0, 0, "DHCP Acknowledgement");
			break;
		case DHCPNAK:
			printT(0, 0, "DHCP NAK");
			break;
		case DHCPRELEASE:
			printT(0, 0, "DHCP Releasing");
			break;
		case DHCPINFORM:
			printT(0, 0, "DHCP Information");
			break;
		default:
			printT(0, 0, "Unknown");
			break;
	}
	printT(0, 1, "");
}
