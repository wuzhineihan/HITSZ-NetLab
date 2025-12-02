#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    /* Step1: 检查数据包长度 */
    if (buf->len < sizeof(ip_hdr_t)) {
        // 数据包长度小于IP头部长度，丢弃
        return;
    }
    
    /* Step2: 进行报头检测 */
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    
    // 检查IP版本号是否为IPv4
    if (hdr->version != IP_VERSION_4) {
        return;
    }
    
    // 检查总长度字段是否小于或等于收到的数据包长度
    uint16_t total_len = swap16(hdr->total_len16);
    if (total_len > buf->len) {
        return;
    }
    
    /* Step3: 校验头部校验和 */
    uint16_t received_checksum = hdr->hdr_checksum16;  // 保存原校验和
    hdr->hdr_checksum16 = 0;  // 将校验和字段置0
    
    uint16_t calculated_checksum = swap16(checksum16((uint16_t *)hdr, sizeof(ip_hdr_t)));
    
    if (received_checksum != calculated_checksum) {
        // 校验和不一致，丢弃数据包
        return;
    }
    
    hdr->hdr_checksum16 = received_checksum;  // 恢复原校验和
    
    /* Step4: 对比目的IP地址 */
    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        // 目的IP地址不是本机IP，丢弃
        return;
    }
    
    /* Step5: 去除填充字段 */
    if (buf->len > total_len) {
        // 存在填充字段，去除
        buf_remove_padding(buf, buf->len - total_len);
    }
    
    /* Step6: 去掉IP报头 */
    buf_remove_header(buf, sizeof(ip_hdr_t));
    
    /* Step7: 向上层传递数据包 */
    if (net_in(buf, hdr->protocol, hdr->src_ip) == -1) {
        // 遇到不能识别的协议类型
        // 重新加入IP报头
        buf_add_header(buf, sizeof(ip_hdr_t));
        
        // 发送ICMP协议不可达信息
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    /* Step1: 增加头部缓存空间 */
    buf_add_header(buf, sizeof(ip_hdr_t));
    
    /* Step2: 填写头部字段 */
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    hdr->version = IP_VERSION_4;
    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;  // 首部长度，以4字节为单位
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);  // 总长度（网络字节序）
    hdr->id16 = swap16(id);
    
    // 设置标志位和分片偏移量
    uint16_t flags_fragment = (offset / IP_HDR_OFFSET_PER_BYTE);  // offset以8字节为单位
    if (mf) {
        flags_fragment |= IP_MORE_FRAGMENT;  // 设置MF标志位
    }
    hdr->flags_fragment16 = swap16(flags_fragment);
    
    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    
    /* Step3: 计算并填写校验和 */
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = swap16(checksum16((uint16_t *)hdr, sizeof(ip_hdr_t)));
    
    /* Step4: 发送数据 */
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    /* Step1: 检查数据报包长 */
    // IP协议最大负载包长 = MTU - IP首部长度
    size_t max_payload = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    
    /* Step2: 分片处理 */
    if (buf->len > max_payload) {
        // 需要分片发送
        static int packet_id = 0;  // 数据包ID（每个数据包递增）
        int id = packet_id++;
        
        size_t offset = 0;  // 当前分片偏移量
        uint8_t *data_ptr = buf->data;  // 指向当前要发送的数据
        size_t remaining = buf->len;  // 剩余数据长度
        
        while (remaining > max_payload) {
            // 初始化一个分片buf
            buf_t ip_buf;
            buf_init(&ip_buf, max_payload);
            
            // 复制数据到分片buf
            memcpy(ip_buf.data, data_ptr, max_payload);
            
            // 发送分片（MF=1，表示后面还有分片）
            ip_fragment_out(&ip_buf, ip, protocol, id, offset, 1);
            
            // 更新偏移量和剩余数据
            offset += max_payload;
            data_ptr += max_payload;
            remaining -= max_payload;
        }
        
        // 发送最后一个分片
        buf_t ip_buf;
        buf_init(&ip_buf, remaining);
        memcpy(ip_buf.data, data_ptr, remaining);
        
        // 最后一个分片，MF=0
        ip_fragment_out(&ip_buf, ip, protocol, id, offset, 0);
    }
    /* Step3: 直接发送 */
    else {
        // 不需要分片，直接发送
        static int packet_id = 0;
        ip_fragment_out(buf, ip, protocol, packet_id++, 0, 0);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}