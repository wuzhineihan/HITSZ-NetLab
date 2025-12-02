#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    /* Step1: 初始化并封装数据 */
    // 初始化txbuf
    buf_init(&txbuf, req_buf->len);
    
    // 复制ICMP头部
    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    icmp_hdr_t *resp_hdr = (icmp_hdr_t *)txbuf.data;
    
    // 填写ICMP回显应答头部
    resp_hdr->type = ICMP_TYPE_ECHO_REPLY;  // 回显应答类型
    resp_hdr->code = 0;
    resp_hdr->checksum16 = 0;  // 先置0，后面计算
    resp_hdr->id16 = req_hdr->id16;    // 复制标识符
    resp_hdr->seq16 = req_hdr->seq16;  // 复制序号
    
    // 复制数据部分（ICMP头部之后的数据）
    size_t data_len = req_buf->len - sizeof(icmp_hdr_t);
    if (data_len > 0) {
        memcpy(txbuf.data + sizeof(icmp_hdr_t), 
               req_buf->data + sizeof(icmp_hdr_t), 
               data_len);
    }
    
    /* Step2: 填写校验和 */
    resp_hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, txbuf.len));
    
    /* Step3: 发送数据报 */
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    /* Step1: 报头检测 */
    if (buf->len < sizeof(icmp_hdr_t)) {
        // 数据包长度小于ICMP头部长度，丢弃
        return;
    }
    
    /* Step2: 查看ICMP类型 */
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    
    /* Step3: 回送回显应答 */
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // 如果是回显请求，调用icmp_resp回送回显应答
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    /* Step1: 初始化并填写报头 */
    // ICMP不可达报文包含：ICMP头部(8字节) + IP头部(20字节) + IP数据报前8字节
    size_t icmp_data_len = sizeof(ip_hdr_t) + 8;  // IP头部 + 前8字节数据
    if (recv_buf->len < icmp_data_len) {
        icmp_data_len = recv_buf->len;  // 如果数据不足，就用实际长度
    }
    
    // 初始化txbuf: ICMP头部 + ICMP数据部分
    buf_init(&txbuf, sizeof(icmp_hdr_t) + icmp_data_len);
    
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    hdr->type = ICMP_TYPE_UNREACH;  // 目的不可达类型
    hdr->code = code;               // 协议不可达或端口不可达
    hdr->checksum16 = 0;            // 先置0，后面计算
    hdr->id16 = 0;                  // 不可达报文中这两个字段未使用
    hdr->seq16 = 0;
    
    /* Step2: 填写数据与校验和 */
    // 复制IP数据报首部和前8字节数据
    memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data, icmp_data_len);
    
    // 计算校验和
    hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, txbuf.len));
    
    /* Step3: 发送数据报 */
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}