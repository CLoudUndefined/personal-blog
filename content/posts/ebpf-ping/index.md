+++
date = '2025-03-04T16:54:29+02:00'
draft = false
title = 'Ломаем пинг с помощью eBPF/XDP'
+++
Оригинал: [Alexey Novikov](https://x3lfy.space/blog/ping/)

*(возможно, это и так всем известно, но я новичок в подобных делах. Решил покопаться в программировании eBPF и случайно наткнулся на это)*

**TL;DR:** Очень просто злоупотребить странной логикой расчёта времени в ping и добиться такого результата:

```bash
$ ping pingme.x3lfy.space
PING pingme.x3lfy.space (91.239.23.176) 56(84) bytes of data.
64 bytes from 91.239.23.176: icmp_seq=1 ttl=206 time=3200828 ms
64 bytes from 91.239.23.176: icmp_seq=2 ttl=184 time=3719749 ms
64 bytes from 91.239.23.176: icmp_seq=3 ttl=87 time=1705390 ms
64 bytes from 91.239.23.176: icmp_seq=4 ttl=190 time=952669 ms
64 bytes from 91.239.23.176: icmp_seq=5 ttl=52 time=1225036 ms
64 bytes from 91.239.23.176: icmp_seq=6 ttl=192 time=3620882 ms
64 bytes from 91.239.23.176: icmp_seq=7 ttl=167 time=2060680 ms
64 bytes from 91.239.23.176: icmp_seq=8 ttl=163 time=406768 ms
```

***мой код обманывает только реализацию ping из iputils. Но, думаю, технически можно реализовать то же самое и для busybox. А вот Windows ping к этой фишке неуязвим — он считает время совсем иначе***

## Как работает ping?

ping шлёт так называемый ICMP *Echo Request* — это пакет с IP-заголовком, где номер протокола 1 (то есть ICMP), плюс заголовок ICMP и немного данных в нагрузке. Вот как выглядит структура ICMP-заголовка:

```bash
+--------+--------+--------+--------+
|   0    |   1    |   2    |   3    |
|01234567|01234567|01234567|01234567|
+--------+--------+--------+--------+
|  Type  |  Code  |    Checksum     |
+--------+--------+--------+--------+
|   Identifier    | Sequence number |
+--------+--------+--------+--------+
|              Payload...           |
```

Хост, который пингует, заполняет поля так:

- `Type` ставит 8, `Code` — 0 — это значит, что пакет — echo request.
- `Identifier` — просто какое-то число, чтобы отличать ICMP-пакеты от разных процессов ping (обычно это PID или что-то в этом духе).
- `Sequence Number` — нарастающий номер, который виден в поле `icmp_seq` в выводе ping.

Целевой хост получает этот пакет, и его ядро делает своё дело:

- меняет `Type` на 0 (теперь это *Echo Reply*),
- пересчитывает контрольную сумму,
- отправляет обновлённый пакет обратно тому, кто пинговал.

## Как ping считает время?

Если вы ковырялись в трафике через Wireshark, то могли заметить странное поле в запросах ping:

![wireshark](/posts/ebpf-ping/images/wireshark.png)

"*Timestamp from icmp data*"... Откуда в запросе эхо взялась метка времени?

Заглянем в [исходники iputils-ping](https://github.com/iputils/iputils/blob/master/ping/ping.c#L1594) (это самая популярная имплементация ping), и всё станет ясно:

```c
icp = (struct icmphdr *)packet;
icp->type = ICMP_ECHO;
icp->code = 0;
icp->checksum = 0;
icp->un.echo.sequence = htons(rts->ntransmitted + 1);
icp->un.echo.id = rts->ident;

rcvd_clear(rts, rts->ntransmitted + 1);

if (rts->timing) {
    if (rts->opt_latency) {
        struct timeval tmp_tv;
        gettimeofday(&tmp_tv, NULL);
        memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv)); // вот оно!
    } else {
        memset(icp + 1, 0, sizeof(struct timeval));
    }
}
```

ping записывает текущую метку времени прямо после заголовка ICMP в пакете. Но зачем?

А затем, что когда ping ловит ответ (*Echo Reply*), он вычисляет время в пути, используя эту метку:

```c
uint8_t *ptr = icmph + icmplen; // icmph — указатель на заголовок ICMP

++rts->nreceived;
if (!csfailed)
    acknowledge(rts, seq);

if (rts->timing && cc >= (int)(8 + sizeof(struct timeval))) {
    struct timeval tmp_tv;
    memcpy(&tmp_tv, ptr, sizeof(tmp_tv)); // читаем метку из пакета

restamp:
    tvsub(tv, &tmp_tv); // tv — это текущая метка (момент получения), определена выше
    triptime = tv->tv_sec * 1000000 + tv->tv_usec;
```

Так что ping просто берёт время получения ответа и вычитает из него время отправки, записанное в пакете — вот тебе и время в пути!

## Злоупотребляем этим

А что, если наш сервер подкрутит метку времени в запросе эхо? Допустим, вычтем из неё какое-то число — и ping решит, что пакет был отправлен оооооочень давно. Идея проста до гениальности, но как это провернуть? ICMP-пакеты обрабатываются в ядре, и из пользовательского пространства туда не залезть. Да и навыков ковырять ядро у меня нет.

И тут на сцену выходит eBPF! О нём болтают много, но если коротко — это технология в ядре Linux, которая позволяет закинуть код в kernel space и запускать его на определённых событиях. А подсистема XDP пускает eBPF-программы прямо после того, как данные пакета считываются с сетевой карты — даже до того, как ядро разберёт их в свои структуры.

Кроме самой eBPF-программы, нужен ещё userspace-инструмент, чтобы закинуть её в ядро и прицепить к интерфейсу. Я взял библиотеку [ebpf-go](https://ebpf-go.dev/).

### Пишем обработчик ping на eBPF

Сначала проверяем, что пакет — это IP с ICMP внутри, и что это именно *Echo Request*. Если нет — пропускаем:

```c
void *data_end = (void*)(long)ctx->data_end;
void *data     = (void*)(long)ctx->data;

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end) { // проверяем, есть ли заголовок Ethernet
    return XDP_PASS;
}

// ntohs нужен, потому что порядок байтов в пакете может отличаться
if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { // ETH_P_IP — константа для IP
    return XDP_PASS;
}

struct iphdr *iph = (void*)(eth + 1);
if ((void*)(iph + 1) > data_end) { // есть ли IP-заголовок?
    return XDP_PASS;
}

if (iph->protocol != IPPROTO_ICMP) { // ICMP ли это?
    return XDP_PASS;
}

struct icmphdr* icmphdr = (void*)(iph + 1); // есть ли заголовок ICMP?
if ((void*)(icmphdr + 1) > data_end) {
    return XDP_PASS;
}

if (icmphdr->type != 8) { // это *Echo Request*?
    return XDP_PASS;
}
```

Теперь надо:
1. Поменять местами MAC-адреса источника и назначения в заголовке Ethernet.
2. Поменять местами IP-адреса в IP-заголовке.
3. Поменять тип ICMP-пакета.

Хорошая новость: замена байтов не ломает контрольную сумму, так что пункты 1 и 2 — просты в реализации.
Плохая новость: смена типа в пункте 3 ломает контрольную сумму ICMP, и её надо пересчитать.

Лучшего способа в XDP я не нашёл, кроме как взять код из [этого проекта](https://github.com/AirVantage/sbulb/blob/master/sbulb/bpf/checksum.c#L21) (спасибо [@sbernard31](https://github.com/sbernard31) за код и подсказку в [этой теме](https://github.com/iovisor/bcc/issues/2463#issuecomment-512812898)). Там используется метод из [RFC 1624](https://tools.ietf.org/html/rfc1624) для инкрементального пересчёта контрольной суммы.

Хотя в исходном проекте эта функция используется только для пересчёта контрольной суммы при замене IP-адресов, на самом деле она способна корректировать контрольную сумму для любого изменённого байта. Вот она, а также небольшие вспомогательные функции для ICMP и IP:

```c
__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum) {
  int i;
#pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

// https://github.com/AirVantage/sbulb/blob/master/sbulb/bpf/checksum.c#L21
__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    *csum += new_addr;
    *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void recalc_icmp_csum(struct icmphdr* hdr, __be32 old_value, __be32 new_value) {
    __u64 csum = hdr->checksum;
    update_csum(&csum, old_value, new_value);
    hdr->checksum = csum;
}

__attribute__((__always_inline__))
static inline void recalc_ip_csum(struct iphdr* hdr, __be32 old_value, __be32 new_value) {
    __u64 csum = hdr->check;
    update_csum(&csum, old_value, new_value);
    hdr->check = csum;
}
```

Теперь меняем адреса и тип пакета:

```c
// Меняем MAC-адреса
__u8 tmp_mac[ETH_ALEN]; // ETH_ALEN — число октетов в MAC из linux/if_ether.h
bpf_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
bpf_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
bpf_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

// Меняем IP-адреса
__u32 tmp_ip = iph->daddr;
iph->daddr = iph->saddr;
iph->saddr = tmp_ip;

icmphdr->type = 0; // Меняем тип ICMP на *Echo Reply*
recalc_icmp_csum(icmphdr, 8, icmphdr->type);
```

И отправляем пакет обратно:

> ### Итоговый код
> ```c
> #include <linux/if_ether.h>
> #include <linux/ip.h>
> #include <linux/bpf.h>
> #include <linux/icmp.h>
> #include <bpf/bpf_helpers.h>
> #include <linux/in.h>
> #include <bpf/bpf_endian.h>
>
> #define bpf_memcpy __builtin_memcpy
>
> __attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
>     __u64 csum) {
>   int i;
> #pragma unroll
>   for (i = 0; i < 4; i++) {
>     if (csum >> 16)
>       csum = (csum & 0xffff) + (csum >> 16);
>   }
>   return ~csum;
> }
>
> __attribute__((__always_inline__))
> static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
>     *csum = ~*csum;
>     *csum = *csum & 0xffff;
>     __u32 tmp;
>     tmp = ~old_addr;
>     *csum += tmp;
>     *csum += new_addr;
>     *csum = csum_fold_helper(*csum);
> }
>
> __attribute__((__always_inline__))
> static inline void recalc_icmp_csum(struct icmphdr* hdr, __be32 old_value, __be32 new_value) {
>     __u64 csum = hdr->checksum;
>     update_csum(&csum, old_value, new_value);
>     hdr->checksum = csum;
> }
>
> __attribute__((__always_inline__))
> static inline void recalc_ip_csum(struct iphdr* hdr, __be32 old_value, __be32 new_value) {
>     __u64 csum = hdr->check;
>     update_csum(&csum, old_value, new_value);
>     hdr->check = csum;
> }
>
> SEC("xdp")
> int pinger(struct xdp_md* ctx) {
>     void *data_end = (void *)(long)ctx->data_end;
>     void *data     = (void *)(long)ctx->data;
>
>     struct ethhdr *eth = data;
>     if ((void *)(eth + 1) > data_end) {
>         return XDP_PASS;
>     }
>
>     if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
>         return XDP_PASS;
>     }
>
>     struct iphdr *iph = (void*)(eth + 1);
>     if ((void*)(iph + 1) > data_end) {
>         return XDP_PASS;
>     }
>
>     if (iph->protocol != IPPROTO_ICMP) {
>         return XDP_PASS;
>     }
>
>     struct icmphdr* icmphdr = (void*)(iph + 1);
>     if ((void*)(icmphdr + 1) > data_end) {
>         return XDP_PASS;
>     }
>
>     if (icmphdr->type != 8) {
>         return XDP_PASS;
>     }
>
>     __u8 tmp_mac[ETH_ALEN];
>     bpf_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
>     bpf_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
>     bpf_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
>
>     __u32 tmp_ip = iph->daddr;
>     iph->daddr = iph->saddr;
>     iph->saddr = tmp_ip;
>
>     icmphdr->type = 0;
>     recalc_icmp_csum(icmphdr, 8, icmphdr->type);
>
>     return XDP_TX;
> }
>
> char LICENSE[] SEC("license") = "GPL";
> ```

Теперь, если загрузить и подключить эту программу, интерфейс будет отвечать на пинги как обычно. Однако в Wireshark вы не увидите пакетов ICMP echo, поскольку они обрабатываются до того, как ядро успевает их перехватить.

### Ломаем его полностью!

К сожалению, это не сработает с ping из Busybox (он использует немного другой формат метки времени, [источник](https://github.com/mirror/busybox/blob/master/networking/ping.c#L576))), а также с Windows ping (в нём метка времени в пакете вообще не сохраняется).

По данным Wireshark и кода iputils, метка времени лежит сразу за заголовком ICMP. Вот указатели на её части (`ts_secs` — целые секунды с эпохи, `ts_nsecs` — наносекунды; смотри [struct timespec](https://en.cppreference.com/w/c/chrono/timespec)):

```c
__u64* ts_secs = (void*)(icmphdr + 1);
__u64* ts_nsecs = (void*)(icmphdr + 1) + sizeof(__u64);
```

Проверяем, есть ли метка в пакете, сохраняем старые значения для пересчёта контрольной суммы и отнимаем рандомные числа:

```c
if ((void*)ts_nsecs + sizeof(__u64) <= data_end) {
    __u64 old_secs = *ts_secs;
    __u64 old_nsecs = *ts_nsecs;

    *ts_secs -= bpf_get_prandom_u32() % 500;
    *ts_nsecs -= bpf_get_prandom_u32();

    recalc_icmp_csum(icmphdr, old_secs, *ts_secs);
    recalc_icmp_csum(icmphdr, old_nsecs, *ts_nsecs);
}
```

А ещё можно рандомизировать TTL и порядковый номер ICMP:

```c
__u8 old_ttl = iph->ttl;
iph->ttl = bpf_get_prandom_u32() % 200 + 40;
recalc_ip_csum(iph, old_ttl, iph->ttl);

__be16 old_seq = icmphdr->un.echo.sequence;
icmphdr->un.echo.sequence = bpf_htons(bpf_get_prandom_u32() % 1000);
recalc_icmp_csum(icmphdr, old_seq, icmphdr->un.echo.sequence);
```

*Кстати, у меня в регионе ICMP-ответы со случайным порядковым номером почему-то блокируются, так что на `pingme.x3lfy.space` они не случайные.*

> ### Финальный код с ломалкой
> ```c
> #include <linux/if_ether.h>
> #include <linux/ip.h>
> #include <linux/bpf.h>
> #include <linux/icmp.h>
> #include <bpf/bpf_helpers.h>
> #include <linux/in.h>
> #include <bpf/bpf_endian.h>
>
> #define bpf_memcpy __builtin_memcpy
>
> __attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
>     __u64 csum) {
>   int i;
> #pragma unroll
>   for (i = 0; i < 4; i++) {
>     if (csum >> 16)
>       csum = (csum & 0xffff) + (csum >> 16);
>   }
>   return ~csum;
> }
>
> __attribute__((__always_inline__))
> static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
>     *csum = ~*csum;
>     *csum = *csum & 0xffff;
>     __u32 tmp;
>     tmp = ~old_addr;
>     *csum += tmp;
>     *csum += new_addr;
>     *csum = csum_fold_helper(*csum);
> }
>
> __attribute__((__always_inline__))
> static inline void recalc_icmp_csum(struct icmphdr* hdr, __be32 old_value, __be32 new_value) {
>     __u64 csum = hdr->checksum;
>     update_csum(&csum, old_value, new_value);
>     hdr->checksum = csum;
> }
>
> __attribute__((__always_inline__))
> static inline void recalc_ip_csum(struct iphdr* hdr, __be32 old_value, __be32 new_value) {
>     __u64 csum = hdr->check;
>     update_csum(&csum, old_value, new_value);
>     hdr->check = csum;
> }
>
> SEC("xdp")
> int pinger(struct xdp_md* ctx) {
>     void *data_end = (void *)(long)ctx->data_end;
>     void *data     = (void *)(long)ctx->data;
>
>     struct ethhdr *eth = data;
>     if ((void *)(eth + 1) > data_end) {
>         return XDP_PASS;
>     }
>
>     if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
>         return XDP_PASS;
>     }
>
>     struct iphdr *iph = (void*)(eth + 1);
>     if ((void*)(iph + 1) > data_end) {
>         return XDP_PASS;
>     }
>
>     if (iph->protocol != IPPROTO_ICMP) {
>         return XDP_PASS;
>     }
>
>     struct icmphdr* icmphdr = (void*)(iph + 1);
>     if ((void*)(icmphdr + 1) > data_end) {
>         return XDP_PASS;
>     }
>
>     if (icmphdr->type != 8) {
>         return XDP_PASS;
>     }
>
>     __u8 tmp_mac[ETH_ALEN];
>     bpf_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
>     bpf_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
>     bpf_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
>
>     __u32 tmp_ip = iph->daddr;
>     iph->daddr = iph->saddr;
>     iph->saddr = tmp_ip;
>
>     icmphdr->type = 0;
>     recalc_icmp_csum(icmphdr, 8, icmphdr->type);
>
>     __u64* ts_secs = (void*)(icmphdr + 1);
>     __u64* ts_nsecs = (void*)(icmphdr + 1) + sizeof(__u64);
>
>     if ((void*)ts_nsecs + sizeof(__u64) <= data_end) {
>         __u64 old_secs = *ts_secs;
>         __u64 old_nsecs = *ts_nsecs;
>
>         *ts_secs -= bpf_get_prandom_u32() % 500;
>         *ts_nsecs -= bpf_get_prandom_u32();
>
>         recalc_icmp_csum(icmphdr, old_secs, *ts_secs);
>         recalc_icmp_csum(icmphdr, old_nsecs, *ts_nsecs);
>     }
>
>     __u8 old_ttl = iph->ttl;
>     iph->ttl = bpf_get_prandom_u32() % 200 + 40;
>     recalc_ip_csum(iph, old_ttl, iph->ttl);
>
>     __be16 old_seq = icmphdr->un.echo.sequence;
>     icmphdr->un.echo.sequence = bpf_htons(bpf_get_prandom_u32() % 1000);
>     recalc_icmp_csum(icmphdr, old_seq, icmphdr->un.echo.sequence);
>
>     return XDP_TX;
> }
>
> char LICENSE[] SEC("license") = "GPL";
> ```

### И вот что из этого выходит

```bash
$ ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=789 ttl=180 time=1257520 ms
64 bytes from 127.0.0.1: icmp_seq=965 ttl=73 time=3875372 ms
64 bytes from 127.0.0.1: icmp_seq=701 ttl=183 time=434820 ms
64 bytes from 127.0.0.1: icmp_seq=689 ttl=95 time=771651 ms
64 bytes from 127.0.0.1: icmp_seq=777 ttl=55 time=2024511 ms
64 bytes from 127.0.0.1: icmp_seq=906 ttl=66 time=211697 ms
64 bytes from 127.0.0.1: icmp_seq=674 ttl=163 time=2369164 ms
```

Код лежит на [GitHub](https://github.com/x3lfyn/cursed-ping).

Проверь сам! — `ping pingme.x3lfy.space`
