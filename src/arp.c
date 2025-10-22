#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
//调用 buf_init() 函数对 txbuf 进行初始化。
buf_init(&txbuf, sizeof(arp_pkt_t));
//调用 buf_add_header() 函数为 txbuf 添加 ARP 报头空间。
buf_add_header(&txbuf, sizeof(arp_pkt_t));
//将 arp_init_pkt 复制到 txbuf 中，作为 ARP 报文的初始内容。
arp_pkt_t *arpHeader = (arp_pkt_t *)txbuf.data;
memcpy(arpHeader, &arp_init_pkt, sizeof(arp_pkt_t));
//按照 ARP 协议规范，准确填写 ARP 报头信息。
arpHeader->opcode16 = swap16(ARP_REQUEST);
memcpy(arpHeader->target_ip, target_ip, NET_IP_LEN);
//调用 ethernet_out 函数将 ARP 报文发送出去。需要注意的是，ARP announcement 或 ARP 请求报文均为广播报文，其目标 MAC 地址应设置为广播地址：FF - FF - FF - FF - FF - FF。
ethernet_out(&txbuf, (uint8_t *)ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    //Step1. 初始化缓冲区：调用 buf_init() 函数初始化 txbuf。
    buf_init(&txbuf, sizeof(arp_pkt_t));
    //Step1.5. 添加 ARP 报头空间：调用 buf_add_header() 函数为 txbuf 添加 ARP 报头空间。
    buf_add_header(&txbuf, sizeof(arp_pkt_t));
    //Step1.75. 复制初始内容：将 arp_init_pkt 复制到 txbuf 中，作为 ARP 报文的初始内容。
    arp_pkt_t *arpHeader = (arp_pkt_t *)txbuf.data;
    memcpy(arpHeader, &arp_init_pkt, sizeof(arp_pkt_t));
    //Step2. 填写 ARP 报头首部：按照 ARP 协议规范，准确填写 ARP 报头首部信息。
    arpHeader->opcode16 = swap16(ARP_REPLY);
    memcpy(arpHeader->target_ip, target_ip, NET_IP_LEN);
    memcpy(arpHeader->target_mac, target_mac, NET_MAC_LEN);
    //Step3. 发送 ARP 报文：调用 ethernet_out() 函数将填充好的 ARP 报文发送出去。
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    //Step1. 检查数据长度：首先判断数据长度，若数据长度小于 ARP 头部长度，则认为数据包不完整，将其丢弃，不予处理。
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }
    //Step2. 报头检查：对报头进行详细检查，查看报文是否完整。检测内容包括 ARP 报头的硬件类型、上层协议类型、MAC 硬件地址长度、IP 协议地址长度、操作类型，确保该报头符合协议规定。
    arp_pkt_t *arpHeader = (arp_pkt_t *)buf->data;
    if (swap16(arpHeader->hw_type16) != ARP_HW_ETHER ||
        swap16(arpHeader->pro_type16) != NET_PROTOCOL_IP ||
        arpHeader->hw_len != NET_MAC_LEN ||
        arpHeader->pro_len != NET_IP_LEN ||
        (swap16(arpHeader->opcode16) != ARP_REQUEST && swap16(arpHeader->opcode16) != ARP_REPLY)) {
        return;
    }
    //Step2.5. 提取关键信息：从 ARP 报文中提取发送方的 IP 地址（sender_ip）、发送方的 MAC 地址（sender_mac）、目标 IP 地址（target_ip）等关键信息，后续处理会用到这些信息。
    uint8_t sender_ip[NET_IP_LEN];
    uint8_t sender_mac[NET_MAC_LEN];
    uint8_t target_ip[NET_IP_LEN];
    memcpy(sender_ip, arpHeader->sender_ip, NET_IP_LEN);
    memcpy(sender_mac, arpHeader->sender_mac, NET_MAC_LEN);
    memcpy(target_ip, arpHeader->target_ip, NET_IP_LEN);
    //Step3. 更新 ARP 表项：调用 map_set() 函数更新 ARP 表项，使 ARP 表中的信息保持最新。
    map_set(&arp_table, sender_ip, sender_mac);
    //Step4. 查看缓存情况：调用 map_get() 函数查看该接收报文的 IP 地址是否有对应的 arp_buf 缓存。
    //有缓存情况：若有缓存，说明 ARP 分组队列里面有待发送的数据包。即上一次调用 arp_out() 函数发送来自 IP 层的数据包时，由于没有找到对应的 MAC 地址而先发送了 ARP request 报文，此时收到了该 request 的应答报文。此时，将缓存的数据包 arp_buf 发送给以太网层，即调用 ethernet_out() 函数将其发出，接着调用 map_delete() 函数将这个缓存的数据包删除。
    //无缓存情况：若该接收报文的 IP 地址没有对应的 arp_buf 缓存，还需要判断接收到的报文是否为 ARP_REQUEST 请求报文，并且该请求报文的 target_ip 是本机的 IP。若是，则认为是请求本主机 MAC 地址的 ARP 请求报文，调用 arp_resp() 函数回应一个响应报文。
    buf_t *cached_buf = map_get(&arp_buf, sender_ip);
    if (cached_buf != NULL) {
        ethernet_out(cached_buf, sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, sender_ip);
    } else {
        if (swap16(arpHeader->opcode16) == ARP_REQUEST &&
            memcmp(target_ip, net_if_ip, NET_IP_LEN) == 0) {
            arp_resp(sender_ip, sender_mac);
            }
        }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    //Step1. 查找 ARP 表：调用 map_get() 函数，依据 IP 地址在 ARP 表（arp_table）中进行查找。
    uint8_t mac[NET_MAC_LEN];
    /* Avoid dereferencing NULL: first get pointer from map_get, then copy if non-NULL */
    uint8_t *mac_ptr = map_get(&arp_table, ip);
    if (mac_ptr != NULL) {
        memcpy(mac, mac_ptr, NET_MAC_LEN);
        //Step2. 找到对应 MAC 地址：若能找到该 IP 地址对应的 MAC 地址，则将数据包直接发送给以太网层，即调用 ethernet_out 函数将数据包发出。
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
        return;
    }
    //Step3. 未找到对应 MAC 地址：若未找到对应的 MAC 地址，需进一步判断 arp_buf 中是否已经有包。若有包，说明正在等待该 IP 回应 ARP 请求，此时不能再发送 ARP 请求；若没有包，则调用 map_set() 函数将来自 IP 层的数据包缓存到 arp_buf 中，然后调用 arp_req() 函数，发送一个请求目标 IP 地址对应的 MAC 地址的 ARP request 报文。
    if(map_get(&arp_buf,ip)==NULL){
        map_set(&arp_buf,ip,buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}