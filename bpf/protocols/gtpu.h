#ifndef PROTOCOLS_GTPU_H
#define PROTOCOLS_GTPU_H

#define GTP_UDP_PORT 2152

#define GTPU_F_E  0x04
#define GTPU_F_S  0x02
#define GTPU_F_PN 0x01

struct gtpu_fixed {
    __u8   flags;
    __u8   msg_type;
    __be16 msg_len;
    __be32 teid;
} __attribute__((packed));

struct gtpu_opt {
    __be16 seq;
    __u8   npdu;
    __u8   next_ext;
} __attribute__((packed));

#define GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain)                 \
    do {                                                                  \
        if ((next) != 0) {                                                \
            if ((p) + 1 > (end)) return -1;                               \
            __u8 __len4 = *(p);                                           \
            if (__len4 == 0) return -1;                                   \
            __u32 __ext_total = (__u32)__len4 * 4;                        \
            if (__ext_total < 4) return -1;                               \
            if ((p) + __ext_total > (end)) return -1;                     \
            if ((remain) < __ext_total) return -1;                        \
            (next) = *((p) + __ext_total - 1);                            \
            (p) += __ext_total;                                           \
            (remain) -= __ext_total;                                      \
        }                                                                 \
    } while (0)

static __always_inline int gtpu_locate_inner_l3(const void *g0,
                                                const void *data_end,
                                                const void **inner_out,
                                                __u16 *gtp_msg_len_out,
                                                const struct gtpu_fixed **gtpu_hdr_out)
{
    const __u8 *p   = (const __u8 *)g0;
    const __u8 *end = (const __u8 *)data_end;

    if (p + sizeof(struct gtpu_fixed) > end) return -1;
    const struct gtpu_fixed *g = (const struct gtpu_fixed *)p;
    
    if (gtpu_hdr_out) *gtpu_hdr_out = g;
    
    p += sizeof(*g);

    __u16 remain = __builtin_bswap16(g->msg_len);
    if (gtp_msg_len_out) *gtp_msg_len_out = remain;

    if (g->flags & (GTPU_F_E | GTPU_F_S | GTPU_F_PN)) {
        if (remain < sizeof(struct gtpu_opt)) return -1;
        if (p + sizeof(struct gtpu_opt) > end) return -1;
        
        const struct gtpu_opt *opt = (const struct gtpu_opt *)p;
        p += sizeof(*opt);
        remain -= sizeof(*opt);

        if (g->flags & GTPU_F_E) {
            __u8 next = opt->next_ext;

            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);
            
            if (next) return -1;
        }
    }

    *inner_out = (const void *)p;
    return 0;
}

#endif
