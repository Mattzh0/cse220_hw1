#include "hw1.h"

void print_packet_sf(unsigned char packet[])
{
    unsigned int src_add = (packet[0] << 20) | (packet[1] << 12) | (packet[2] << 4) | ((packet[3] & 0xF0) >> 4);
    printf("Source Address: %u\n", src_add);

    unsigned int des_add = ((packet[3] & 0x0F) << 24) | (packet[4] << 16) | (packet[5] << 8) | (packet[6]);
    printf("Destination Address: %u\n", des_add);

    unsigned int sp = (packet[7] & 0xF0) >> 4;
    printf("Source Port: %u\n", sp);

    unsigned int dp = (packet[7] & 0x0F);
    printf("Destination Port: %u\n", dp);

    unsigned int f_offset = (packet[8] << 6) | ((packet[9] & 0xFC) >> 2);
    printf("Fragment Offset: %u\n", f_offset);

    unsigned int packet_length = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | ((packet[11] & 0xF0) >> 4);
    printf("Packet Length: %u\n", packet_length);

    unsigned int mh = ((packet[11] & 0x0F) << 1) | ((packet[12] & 0x80) >> 7);
    printf("Maximum Hop Count: %u\n", mh);

    unsigned int checksum = ((packet[12] & 0x7F) << 16) | (packet[13] << 8) | (packet[14]);
    printf("Checksum: %u\n", checksum);

    unsigned int compression_scheme = ((packet[15] & 0xC0) >> 6);
    printf("Compression Scheme: %u\n", compression_scheme);

    unsigned int tc = ((packet[15] & 0x3F));
    printf("Traffic Class: %u\n", tc);

    printf("Payload: ");
    for (int i = 16; i <= packet_length - 4; i += 4) {
        signed int payload_int = (packet[i] << 24) | (packet[i+1] << 16) | (packet[i+2] << 8) | (packet[i+3]);
        if (i == (packet_length - 4)) { 
            printf("%d\n", payload_int);
        }
        else {
            printf("%d ", payload_int);
        }
    }

}

unsigned int compute_checksum_sf(unsigned char packet[])
{
    unsigned int dividend;
    unsigned int src_add = (packet[0] << 20) | (packet[1] << 12) | (packet[2] << 4) | ((packet[3] & 0xF0) >> 4);
    unsigned int des_add = ((packet[3] & 0x0F) << 24) | (packet[4] << 16) | (packet[5] << 8) | (packet[6]);
    unsigned int sp = (packet[7] & 0xF0) >> 4;
    unsigned int dp = (packet[7] & 0x0F);
    unsigned int f_offset = (packet[8] << 6) | ((packet[9] & 0xFC) >> 2);
    unsigned int packet_length = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | ((packet[11] & 0xF0) >> 4);
    unsigned int mh = ((packet[11] & 0x0F) << 1) | ((packet[12] & 0x80) >> 7);
    unsigned int compression_scheme = ((packet[15] & 0xC0) >> 6);
    unsigned int tc = ((packet[15] & 0x3F));

    dividend = src_add + des_add + sp + dp + f_offset + packet_length + mh + compression_scheme + tc;

    for (int i = 16; i <= packet_length - 4; i += 4) {
        signed int payload_int = (packet[i] << 24) | (packet[i+1] << 16) | (packet[i+2] << 8) | (packet[i+3]);
        dividend += abs(payload_int);
    }

    unsigned int res = dividend % ((1 << 23) - 1);

    return res;
}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    unsigned int count = 0;
    for (int i = 0; i < packets_len; i++) {
        unsigned int checksum_one = ((packets[i][12] & 0x7F) << 16) | (packets[i][13] << 8) | (packets[i][14]);
        unsigned int checksum_two = compute_checksum_sf(packets[i]);

        if (checksum_one != checksum_two) {
            continue;
        }

        unsigned int packet_i_length = ((packets[i][9] & 0x03) << 12) | (packets[i][10] << 4) | ((packets[i][11] & 0xF0) >> 4);
        unsigned int f_offset = (packets[i][8] << 6) | ((packets[i][9] & 0xFC) >> 2);
        unsigned int index = (f_offset / 4);
        for (unsigned int j = 16; j <= packet_i_length - 4; j += 4) {
            signed int payload_int = (packets[i][j] << 24) | (packets[i][j+1] << 16) | (packets[i][j+2] << 8) | (packets[i][j+3]);
            if (index >= array_len) {
                break; 
            }
            else {
                array[index] = payload_int;
                index += 1;
                count += 1;
            }
        }
    }
    return count;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    unsigned int num_packets = 0;
    unsigned int i = 0;
    unsigned int array_index= 0;
    unsigned int fragment_offset = 0;

    while ((i < packets_len) && (array_index < array_len)) {
        packets[i] = malloc(16 + max_payload);
            
        packets[i][0] = (src_addr >> 20) & 0xFF;
        packets[i][1] = (src_addr >> 12) & 0xFF;
        packets[i][2] = (src_addr >> 4) & 0xFF;
        packets[i][3] = ((src_addr & 0x0F) << 4) | ((dest_addr >> 24) & 0x0F);
        packets[i][4] = (dest_addr >> 16) & 0xFF;
        packets[i][5] = (dest_addr >> 8) & 0xFF;
        packets[i][6] = (dest_addr) & 0xFF;
        packets[i][7] = (src_port << 4) | dest_port;
        packets[i][8] = (fragment_offset >> 6) & 0xFF;
        packets[i][9] = ((fragment_offset & 0x3F) << 2);
        packets[i][11] = (maximum_hop_count >> 1) & 0x0F;
        packets[i][12] = (maximum_hop_count & 0x01) << 7;
        packets[i][15] = (compression_scheme << 6) | (traffic_class);

        unsigned int payload_length = 0;
        for (unsigned int j=0; j < max_payload / 4 && array_index < array_len; j++) {
            packets[i][16 + j * 4] = (array[array_index] >> 24) & 0xFF; 
            packets[i][17 + j * 4] = (array[array_index] >> 16) & 0xFF; 
            packets[i][18 + j * 4] = (array[array_index] >> 8) & 0xFF; 
            packets[i][19 + j * 4] = (array[array_index]) & 0xFF; 
            payload_length += 4;
            array_index += 1;

            if (array_index >= array_len) {
                break;
            }
        }

        unsigned int packet_length = 16 + payload_length;

        packets[i][9] |= ((packet_length >> 12) & 0x03);
        packets[i][10] = (packet_length >> 4) & 0xFF;
        packets[i][11] |= ((packet_length & 0x0F) << 4);

        unsigned int checksum = compute_checksum_sf(packets[i]);

        packets[i][12] |= ((checksum >> 16) & 0x7F);
        packets[i][13] = (checksum >> 8) & 0xFF;
        packets[i][14] = checksum & 0xFF; 

        fragment_offset += payload_length;
        num_packets += 1;
        i += 1;
    }

    return num_packets;
}
