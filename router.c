#include "queue.h"
#include "skel.h"
#include <stdio.h>

#define PLEN_SIZE 4

int rtable_length = 0;
struct route_table_entry *rtable;

int arp_table_length = 0;
struct arp_entry *arp_table;

// cautare liniara - din laboratorul 4
struct route_table_entry* get_best_route(__u32 ip) {
	struct route_table_entry *entry = NULL;
	for (int i = 0; i < rtable_length; ++i) {
		if ((rtable[i].mask & ip) == rtable[i].prefix) {
			 if (entry == NULL) {
				entry = &rtable[i];
			 } else if (ntohl(rtable[i].mask) > ntohl(entry->mask)) {
				entry = &rtable[i];
			 }
		}
	}
	return entry;
}
// returnez entry-ul dorit
struct arp_entry* get_arp_entry(__u32 ip) {
	for (int i = 0; i < arp_table_length; ++i) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
    return NULL;
}

// implementat dupa informatiile din document
void bonus_checksum(struct iphdr* ip_hdr) {
	// old value
	uint16_t old = ip_hdr->ttl;
	// new value
	uint16_t new = ip_hdr->ttl - 1;
	// decrementez
	ip_hdr->ttl--;
	uint16_t sum = ip_hdr->check;
	// reactualizez suma
	sum = sum - (~old + 1);
	sum = sum - new;
	ip_hdr->check = sum;
}

int main(int argc, char *argv[]) {
	packet m;
	int rc;
	
	init(argc - 2, argv + 2);
	// initializez rtable-ul si length-ul acestuia
	rtable = (struct route_table_entry *) malloc (100000 * sizeof(struct route_table_entry));
	rtable_length = read_rtable(argv[1], rtable);
	// initializez arp_table-ul
	arp_table = (struct arp_entry *) malloc (1000 * sizeof(struct arp_entry));
	// imi creez coada
	queue q = queue_create();
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		// extrag headerele ether, ip si arp
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr*) (m.payload + sizeof(struct ether_header));

		struct arp_header *arp_hdr = NULL;
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));
		}
		// am primit un header arp => verific daca este de tip REQUEST / REPLY
		if (arp_hdr != NULL) {
			// verific daca este de tip REQUEST
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				// modific headerul ethernet
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// imi iau un arp header
				struct arp_header* arp_head = malloc (sizeof(struct arp_header));
				// il completez cu informatiile necesare
				arp_head->htype = htons(ARPHRD_ETHER);
				arp_head->ptype = htons(1 << 11);
				arp_head->op = htons(ARPOP_REPLY);
				arp_head->hlen = ETH_ALEN;
				arp_head->plen = PLEN_SIZE;
				
				// imi iau un nou pachet sa lucrez cu el
				packet pkg;
				// copiez informatia in arp_head
				memcpy(arp_head->sha, eth_hdr->ether_shost, ETH_ALEN);
				memcpy(arp_head->tha, eth_hdr->ether_dhost, ETH_ALEN);
				arp_head->spa = arp_hdr->tpa;
				arp_head->tpa = arp_hdr->spa;
				// adaug in payload-ul pachetului
				memset(pkg.payload, 0, sizeof(pkg.payload));
				memcpy(pkg.payload, eth_hdr, sizeof(struct ethhdr));
				memcpy(pkg.payload + sizeof(struct ethhdr), arp_head, sizeof(struct arp_header));
				pkg.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
				// adaug interfata
				pkg.interface = m.interface;
				// trimit pachetul meu
				send_packet(&pkg);
				// este de tip REPLY
			} else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				// imi iau un nou entry
				struct arp_entry new_entry;

				// practic adresa ip este sursa de unde vine request-ul
				new_entry.ip = arp_hdr->spa;
				memcpy(new_entry.mac, arp_hdr->sha, sizeof(arp_hdr->sha));

				// adaug entry-ul in arp table si cresc size-ul
				arp_table[arp_table_length++] = new_entry;

				// coada folosita pentru salvarea pachetelor care nu au destinatia data de reply
				queue aux_q = queue_create();

				// fac asta cat timp coada nu este vida
				while (!queue_empty(q)) { 
					packet *pack = queue_front(q);
					// extrag headerele ether si ip din pachet
					struct ether_header *eth_hdr = pack->payload;
					struct iphdr *ip_hdr = (pack->payload + sizeof(struct ether_header));
					// calculez ruta cea mai buna
					// struct route_table_entry *entry = get_binary_route(ip_hdr->daddr, rtable, rtable_length);
					struct route_table_entry *entry = get_best_route(ip_hdr->daddr);
					// struct route_table_entry *entry = get_binary_route(ip_hdr->daddr);

					// schimb pachetul in tip ip
					eth_hdr->ether_type = htons(ETHERTYPE_IP);

					// adaug adresa mac a eth_hdr este acum adresa primita de la reply
					eth_hdr->ether_dhost[0] = new_entry.mac[0];
					eth_hdr->ether_dhost[1] = new_entry.mac[1];
					eth_hdr->ether_dhost[2] = new_entry.mac[2];
					eth_hdr->ether_dhost[3] = new_entry.mac[3];
					eth_hdr->ether_dhost[4] = new_entry.mac[4];
					eth_hdr->ether_dhost[5] = new_entry.mac[5];
					// iau adresa mac
					get_interface_mac(entry->interface, eth_hdr->ether_shost);
					// iau interfata dorita
					pack->interface = entry->interface;
					// trimit pachetul
					send_packet(pack);
					// scot din coada
					queue_deq(q);
				}
				// schimb valorile cozilor
				q = aux_q;
			}
			// arunc pachetul
			continue;
		}

		// iau ruta cea mai buna pentru ip-ul destinatiei mele unde trebuie sa ajung
		struct route_table_entry *route_entry = get_best_route(ip_hdr->daddr);

		// iau adresa mac potrivita rutei
		struct arp_entry *arp_entr = get_arp_entry(route_entry->next_hop);

		// daca checksum-ul este gresit, arunc pachetul
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			 continue;
		}
		// reactualizez suma
		bonus_checksum(ip_hdr);
		
		// daca entry-ul meu este null => trebuie sa fac un request pentru a afla adresa mac
		if (arp_entr == NULL) {
			packet *pack = malloc (sizeof(packet));
			// copiez pachetul nou creat
			memcpy(pack, &m, sizeof(packet));

			// bag pachetul in coada pentru al folosi mai tarziu
			queue_enq(q, pack);

			// creez un ether header si ii adaug ce imi trebuie
			struct ether_header *ether_hdr = malloc (sizeof(struct ether_header));
			ether_hdr->ether_type = htons(ETHERTYPE_ARP);
			get_interface_mac(route_entry->interface, ether_hdr->ether_shost);

			// iau in considerare orice parte din reteaua mea de internet
			uint8_t broadcast[6];
			memset(broadcast, 0xFF, ETH_ALEN);
			memcpy(ether_hdr->ether_dhost, &broadcast, 6);
			
			// imi iau un arp header
			struct arp_header* arp_head = malloc (sizeof(struct arp_header));
			// il completez cu informatiile necesare
			arp_head->htype = htons(ARPHRD_ETHER);
			arp_head->ptype = htons(1 << 11);
			arp_head->op = htons(ARPOP_REQUEST);
			arp_head->hlen = ETH_ALEN;
			arp_head->plen = PLEN_SIZE;

			// imi iau un nou pachet sa lucrez cu el
			packet pkg;
			memcpy(arp_head->sha, ether_hdr->ether_shost, ETH_ALEN);
			memcpy(arp_head->tha, ether_hdr->ether_dhost, ETH_ALEN);
			arp_head->spa = inet_addr(get_interface_ip(route_entry->interface));
			arp_head->tpa = route_entry->next_hop;

			// adaug in payload-ul packetului meu
			memset(pkg.payload, 0, 1600);
			memcpy(pkg.payload, ether_hdr, sizeof(struct ethhdr));
			memcpy(pkg.payload + sizeof(struct ethhdr), arp_head, sizeof(struct arp_header));
			pkg.len = sizeof(struct arp_header) + sizeof(struct ethhdr);

			// adaug interfata
			pkg.interface = route_entry->interface;
			// trimit pachetul
			send_packet(&pkg);
			continue;
		}
		// schimb adresa destinatie cu adresa mac gasita a next hop-ului
		get_interface_mac(route_entry->interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, arp_entr->mac, sizeof(arp_entr->mac));
		m.interface = route_entry->interface;
		// trimit pachetul mai departe
		send_packet(&m);
	}
	return 0;
}
