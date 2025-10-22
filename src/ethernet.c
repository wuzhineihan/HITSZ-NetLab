#include "ethernet.h"
#include "net.h"
#include <string.h>
#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    //首先判断数据长度，若数据长度小于以太网头部长度，表明数据包不完整，应将其丢弃，不予处理。
    size_t original_len = buf->len;
    if(original_len < sizeof(ether_hdr_t)) {
        return;
    }
    //获取相关信息并存储
    ether_hdr_t *ethernetHeader = (ether_hdr_t *)buf->data;
    static uint8_t src_mac[NET_MAC_LEN];
    memcpy(src_mac, ethernetHeader->src, NET_MAC_LEN);
    uint16_t protocol = swap16(ethernetHeader->protocol16);
    //调用buf_remove_header()函数移除加以太网包头。
    buf_remove_header(buf, sizeof(ether_hdr_t));
    //调用net_in()函数向上层传递数据包。
    net_in(buf, protocol, src_mac);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // Step1: 数据长度检查与填充，若不足最小传输单元则填充0
    size_t dataLength = buf->len;
    if (dataLength < ETHERNET_MIN_TRANSPORT_UNIT)
        buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT - dataLength);

    /* Step2: 添加以太网包头 */
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *ethernetHeader = (ether_hdr_t *)buf->data;

    /* Step3: 填写目的MAC地址 */
    memcpy(ethernetHeader->dst, mac, NET_MAC_LEN);

    /* Step4: 填写源MAC地址（本机MAC） */
    memcpy(ethernetHeader->src, net_if_mac, NET_MAC_LEN);

    /* Step5: 填写协议类型 */
    ethernetHeader->protocol16 = swap16((uint16_t)protocol);

    /* Step6: 发送数据帧 */
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
