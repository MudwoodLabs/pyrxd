/*
 * sha256d_grind.c -- a native SHA256d nonce grinder for pyrxd dMint contracts.
 *
 * Speaks pyrxd's external-miner protocol (protocol 1): one JSON request on
 * stdin, one JSON response on stdout, optional progress frames on stderr.
 * See docs/concepts/parallel-mining.md for the protocol and
 * src/pyrxd/contrib/miner/native/README.md for how to build and use it.
 *
 * What it computes, and nothing else: for each nonce n in the requested range,
 *
 *     digest = SHA256(SHA256(preimage || LE(n, nonce_width)))
 *
 * and n is a hit iff digest[0:4] is all zero AND digest[4:12], read
 * big-endian as an unsigned 64-bit integer, is below min(target, 2**63 - 1).
 * That is pyrxd's `verify_sha256d_solution`, and pyrxd re-checks every nonce
 * this program returns with that function before it is used.
 *
 * Why it is faster than the Python miners: the 64-byte preimage is exactly
 * one SHA-256 block, so its compression is done once per request (the
 * "midstate") and each attempt costs two compressions instead of three; the
 * padding of both remaining blocks is fixed and precomputed; there is no
 * per-attempt allocation; and on x86-64 CPUs with the SHA extensions the
 * compression function uses them (chosen at run time with CPUID). Every other
 * CPU uses the portable C compression function below. Threads take
 * fixed-size chunks of the nonce range from one shared counter, so fast and
 * slow cores both stay busy until the range is done.
 *
 * Portability: C11 with POSIX threads and `unsigned __int128`, so a 64-bit
 * target and GCC or Clang. Built and tested on Linux x86-64 only. Build with,
 * for example:
 *
 *     cc -O2 -pthread -o sha256d-grind sha256d_grind.c
 *
 * or `python -m pyrxd.contrib.miner.native --out sha256d-grind`, which
 * compiles with the same flags into a temporary directory, runs --selftest,
 * and moves the binary to --out only if it passes.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#endif

#if defined(__x86_64__)
#include <cpuid.h>
#include <immintrin.h>
#define GRIND_HAVE_X86_SHANI 1
#else
#define GRIND_HAVE_X86_SHANI 0
#endif

#if !defined(__SIZEOF_INT128__)
#error "sha256d_grind.c needs unsigned __int128 (a 64-bit target with GCC or Clang)"
#endif

__extension__ typedef unsigned __int128 u128;

#define PROTOCOL_VERSION 1
#define MAX_REQUEST_BYTES 4096
/* The covenant's target ceiling: pyrxd's MAX_SHA256D_TARGET. */
#define MAX_SHA256D_TARGET 0x7FFFFFFFFFFFFFFFULL
/* Nonces per unit of work a thread takes from the shared counter. */
#define CHUNK_NONCES 65536u
/* --enumerate lists every hit, so its range is bounded to keep memory flat. */
#define MAX_ENUMERATE_NONCES (1u << 20)
#define MAX_THREADS 1024
#define PROGRESS_INTERVAL_S 0.5
#define POLL_INTERVAL_NS 50000000L

#define EXIT_FOUND 0
#define EXIT_USAGE 1
#define EXIT_EXHAUSTED 2
/* A solution was found but could not be written to stdout (a full disk, for example). Not 0,
 * so the caller cannot take the missing or partial output for an answer. */
#define EXIT_WRITE_FAILED 3

/* ------------------------------------------------------------------ SHA-256 */

static const uint32_t SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }

/* One SHA-256 compression of a 64-byte block into `state` (FIPS 180-4, 6.2.2). */
static void sha256_transform_portable(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = load_be32(block + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

#if GRIND_HAVE_X86_SHANI
/*
 * The same compression with the x86 SHA extensions. SHA256RNDS2 runs two
 * rounds on a state held as (A,B,E,F) / (C,D,G,H); SHA256MSG1/MSG2 compute the
 * message schedule four words at a time. Each loop iteration is four rounds.
 * Only called when CPUID reports SHA, SSSE3 and SSE4.1 (see cpu_has_shani).
 */
__attribute__((target("sha,ssse3,sse4.1"))) static void sha256_transform_shani(uint32_t state[8],
                                                                              const uint8_t block[64]) {
    const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    __m128i tmp = _mm_loadu_si128((const __m128i *)&state[0]);    /* D C B A */
    __m128i state1 = _mm_loadu_si128((const __m128i *)&state[4]); /* H G F E */
    tmp = _mm_shuffle_epi32(tmp, 0xB1);                            /* C D A B */
    state1 = _mm_shuffle_epi32(state1, 0x1B);                      /* E F G H */
    __m128i state0 = _mm_alignr_epi8(tmp, state1, 8);              /* A B E F */
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);                   /* C D G H */
    const __m128i abef_save = state0;
    const __m128i cdgh_save = state1;

    __m128i w[4];
    for (int i = 0; i < 4; i++) w[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 16 * i)), bswap);

#if defined(__clang__)
#pragma clang loop unroll(full)
#elif defined(__GNUC__)
#pragma GCC unroll 16
#endif
    for (int g = 0; g < 16; g++) {
        __m128i msg = _mm_add_epi32(w[g & 3], _mm_loadu_si128((const __m128i *)&SHA256_K[4 * g]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        if (g < 12) {
            /* W[4(g+4) .. 4(g+4)+3] replaces W[4g .. 4g+3] in the ring. */
            __m128i t = _mm_sha256msg1_epu32(w[g & 3], w[(g + 1) & 3]);
            t = _mm_add_epi32(t, _mm_alignr_epi8(w[(g + 3) & 3], w[(g + 2) & 3], 4));
            w[g & 3] = _mm_sha256msg2_epu32(t, w[(g + 3) & 3]);
        }
    }

    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);
    tmp = _mm_shuffle_epi32(state0, 0x1B);        /* F E B A */
    state1 = _mm_shuffle_epi32(state1, 0xB1);     /* D C H G */
    state0 = _mm_blend_epi16(tmp, state1, 0xF0);  /* D C B A */
    state1 = _mm_alignr_epi8(state1, tmp, 8);     /* H G F E */
    _mm_storeu_si128((__m128i *)&state[0], state0);
    _mm_storeu_si128((__m128i *)&state[4], state1);
}

static int cpu_has_shani(void) {
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    const int ssse3 = (c >> 9) & 1, sse41 = (c >> 19) & 1;
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 0;
    const int sha = (b >> 29) & 1;
    return ssse3 && sse41 && sha;
}
#else
static int cpu_has_shani(void) { return 0; }
#endif

typedef void (*transform_fn)(uint32_t state[8], const uint8_t block[64]);

/* ------------------------------------------------------------ one attempt */

/*
 * The per-request constants every attempt shares. Built once by job_init and
 * read-only afterwards, so threads share it without locking.
 */
typedef struct {
    transform_fn transform;
    uint32_t midstate[8]; /* state after compressing the 64-byte preimage */
    unsigned nonce_width; /* 4 (V1) or 8 (V2) */
    u128 target96;        /* hit iff the digest's first 12 bytes, big-endian, are below this */
    uint64_t start;       /* first nonce of the range */
    u128 end;             /* one past the last nonce; at most 2**(8 * nonce_width) */
} job_t;

/*
 * The second block of the inner hash: the nonce (little-endian) at offset 0,
 * then the 0x80 terminator, zeros, and the 64-bit big-endian bit length of the
 * whole 64 + nonce_width byte message. Only the nonce bytes change per attempt.
 */
static void inner_tail_init(uint8_t block[64], unsigned nonce_width) {
    memset(block, 0, 64);
    block[nonce_width] = 0x80;
    const uint64_t bits = (uint64_t)(64u + nonce_width) * 8u;
    for (int i = 0; i < 8; i++) block[63 - i] = (uint8_t)(bits >> (8 * i));
}

/* The outer hash's only block: 32 digest bytes, 0x80, zeros, bit length 256. */
static void outer_block_init(uint8_t block[64]) {
    memset(block, 0, 64);
    block[32] = 0x80;
    block[62] = 0x01; /* 256 = 0x0100 */
}

/*
 * SHA256d(preimage || LE(nonce)) into `digest_words` (the final state: word i
 * is digest bytes 4i..4i+3, big-endian). `inner` and `outer` must have been
 * set up by inner_tail_init / outer_block_init; this writes only the nonce
 * bytes of `inner` and the first 32 bytes of `outer`.
 */
static inline void sha256d_attempt(const job_t *job, uint64_t nonce, uint8_t inner[64], uint8_t outer[64],
                                   uint32_t digest_words[8]) {
    for (unsigned i = 0; i < job->nonce_width; i++) inner[i] = (uint8_t)(nonce >> (8 * i));
    uint32_t s[8];
    memcpy(s, job->midstate, sizeof s);
    job->transform(s, inner);
    for (int i = 0; i < 8; i++) store_be32(outer + 4 * i, s[i]);
    memcpy(digest_words, SHA256_IV, sizeof SHA256_IV);
    job->transform(digest_words, outer);
}

/* The hit rule, on the final state words. The only place it is written. */
static inline int is_hit(const uint32_t digest_words[8], u128 target96) {
    const u128 prefix96 = ((u128)digest_words[0] << 64) | ((u128)digest_words[1] << 32) | (u128)digest_words[2];
    return prefix96 < target96;
}

/* ------------------------------------------------------------ the sweep */

typedef struct {
    uint64_t nonce;
    uint32_t digest_words[8];
} hit_t;

typedef struct {
    const job_t *job;
    int enumerate;             /* 0: stop at the first hit; 1: record every hit */
    _Atomic uint64_t next_chunk;
    _Atomic int stop;          /* set on the first hit when not enumerating */
    _Atomic uint64_t attempts; /* hashes done, published once per chunk */
    _Atomic int threads_done;
    pthread_mutex_t hit_mu;    /* guards everything below */
    int found;
    uint64_t found_nonce;
    hit_t *hits;
    size_t n_hits, cap_hits;
    int hits_overflow;
} sweep_t;

static void record_hit(sweep_t *sw, uint64_t nonce, const uint32_t digest_words[8]) {
    pthread_mutex_lock(&sw->hit_mu);
    if (sw->enumerate) {
        if (sw->n_hits < sw->cap_hits) {
            sw->hits[sw->n_hits].nonce = nonce;
            memcpy(sw->hits[sw->n_hits].digest_words, digest_words, 32);
            sw->n_hits++;
        } else {
            sw->hits_overflow = 1;
        }
    } else if (!sw->found) {
        sw->found = 1;
        sw->found_nonce = nonce;
        atomic_store(&sw->stop, 1);
    }
    pthread_mutex_unlock(&sw->hit_mu);
}

static void *sweep_thread(void *arg) {
    sweep_t *sw = (sweep_t *)arg;
    const job_t *job = sw->job;
    uint8_t inner[64], outer[64];
    uint32_t digest_words[8];
    inner_tail_init(inner, job->nonce_width);
    outer_block_init(outer);

    for (;;) {
        if (atomic_load(&sw->stop)) break;
        const uint64_t chunk = atomic_fetch_add(&sw->next_chunk, 1);
        const u128 lo = (u128)job->start + (u128)chunk * CHUNK_NONCES;
        if (lo >= job->end) break;
        const u128 hi = (lo + CHUNK_NONCES < job->end) ? lo + CHUNK_NONCES : job->end;
        /* Count, not an end nonce: `hi` can be 2**64, which a uint64_t cannot hold. */
        const uint64_t count = (uint64_t)(hi - lo);
        const uint64_t first = (uint64_t)lo;
        uint64_t done = 0;
        for (; done < count; done++) {
            const uint64_t nonce = first + done;
            sha256d_attempt(job, nonce, inner, outer, digest_words);
            if (is_hit(digest_words, job->target96)) {
                record_hit(sw, nonce, digest_words);
                if (!sw->enumerate) {
                    done++;
                    break;
                }
            }
        }
        atomic_fetch_add(&sw->attempts, done);
    }
    atomic_fetch_add(&sw->threads_done, 1);
    return NULL;
}

/* ------------------------------------------------------------ utilities */

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int default_threads(void) {
#if defined(__linux__)
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set) == 0) {
        int n = CPU_COUNT(&set);
        if (n > 0) return n > MAX_THREADS ? MAX_THREADS : n;
    }
#endif
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) return 1;
    return n > MAX_THREADS ? MAX_THREADS : (int)n;
}

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * n] = '\0';
}

/* Parse an unsigned integer: decimal, or hex with a 0x prefix. Whole string, no sign, no spaces. */
static int parse_u64_arg(const char *s, uint64_t *out) {
    if (s == NULL || *s == '\0') return 0;
    int base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
        if (*s == '\0') return 0;
    }
    uint64_t v = 0;
    for (; *s; s++) {
        int d = hexval((unsigned char)*s);
        if (d < 0 || d >= base) return 0;
        if (v > (UINT64_MAX - (uint64_t)d) / (uint64_t)base) return 0;
        v = v * (uint64_t)base + (uint64_t)d;
    }
    *out = v;
    return 1;
}

/* ------------------------------------------------------------ the request */

/*
 * A deliberately small JSON reader for the one flat object the protocol sends:
 * {"preimage_hex": str, "target_hex": str, "nonce_width": int, "protocol": int}.
 * Unknown keys are ignored when their value is a string, number, true, false or
 * null. It refuses, with exit code 1, some requests pyrxd's Python parser
 * (MineRequest.from_json) accepts: a nested object or array, a string with a
 * backslash escape, NaN, Infinity or -Infinity (Python's json module reads them
 * as numbers) in an unknown field, any byte outside ASCII, a repeated key whose
 * first value is invalid, and the hex that Python's int(x, 16) and bytes.fromhex
 * allow and this reader does not: a leading '+', underscores or surrounding
 * whitespace in target_hex, and whitespace in preimage_hex. pyrxd's request
 * (json.dumps of two lowercase hex strings and an integer) never contains any of
 * those. tests/contrib/test_native_grinder.py pins both lists.
 */
typedef struct {
    const char *p, *end;
} cursor_t;

static void skip_ws(cursor_t *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++;
}

static int take_char(cursor_t *c, char ch) {
    skip_ws(c);
    if (c->p < c->end && *c->p == ch) {
        c->p++;
        return 1;
    }
    return 0;
}

static int read_string(cursor_t *c, const char **s, size_t *n) {
    skip_ws(c);
    if (c->p >= c->end || *c->p != '"') return 0;
    c->p++;
    const char *start = c->p;
    while (c->p < c->end && *c->p != '"') {
        const unsigned char ch = (unsigned char)*c->p;
        if (ch == '\\' || ch < 0x20) return 0;
        c->p++;
    }
    if (c->p >= c->end) return 0;
    *s = start;
    *n = (size_t)(c->p - start);
    c->p++;
    return 1;
}

static int is_digit(char ch) { return ch >= '0' && ch <= '9'; }

/*
 * One JSON number (RFC 8259: -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?). Sets *is_uint and
 * *value when it is a non-negative integer that fits in 64 bits, as the protocol's integer
 * fields must be. Anything else that is not a number returns 0.
 */
static int read_number(cursor_t *c, int *is_uint, uint64_t *value) {
    skip_ws(c);
    const char *p = c->p, *const end = c->end;
    int plain = 1;
    uint64_t v = 0;
    if (p < end && *p == '-') {
        plain = 0;
        p++;
    }
    if (p >= end || !is_digit(*p)) return 0;
    if (*p == '0') {
        p++;
    } else {
        for (; p < end && is_digit(*p); p++) {
            if (v > (UINT64_MAX - 9) / 10) plain = 0;
            v = v * 10 + (uint64_t)(*p - '0');
        }
    }
    if (p < end && *p == '.') {
        plain = 0;
        p++;
        if (p >= end || !is_digit(*p)) return 0;
        while (p < end && is_digit(*p)) p++;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        plain = 0;
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        if (p >= end || !is_digit(*p)) return 0;
        while (p < end && is_digit(*p)) p++;
    }
    c->p = p;
    *is_uint = plain;
    *value = v;
    return 1;
}

static int read_literal(cursor_t *c, const char *lit) {
    skip_ws(c);
    const size_t n = strlen(lit);
    if ((size_t)(c->end - c->p) >= n && memcmp(c->p, lit, n) == 0) {
        c->p += n;
        return 1;
    }
    return 0;
}

static int key_is(const char *s, size_t n, const char *key) { return strlen(key) == n && memcmp(s, key, n) == 0; }

typedef struct {
    uint8_t preimage[64];
    uint64_t target; /* already clamped to MAX_SHA256D_TARGET */
    unsigned nonce_width;
} request_t;

static int parse_request(const char *buf, size_t len, request_t *req, const char **why) {
    cursor_t c = {buf, buf + len};
    int have_pre = 0, have_target = 0, have_width = 0;
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)buf[i] >= 0x80) {
            *why = "request contains a byte outside ASCII";
            return 0;
        }
    }
    if (!take_char(&c, '{')) {
        *why = "request must be a JSON object";
        return 0;
    }
    if (!take_char(&c, '}')) {
        for (;;) {
            const char *key;
            size_t klen;
            if (!read_string(&c, &key, &klen) || !take_char(&c, ':')) {
                *why = "request is not a flat JSON object of plain keys";
                return 0;
            }
            skip_ws(&c);
            if (key_is(key, klen, "preimage_hex")) {
                const char *s;
                size_t n;
                if (!read_string(&c, &s, &n)) {
                    *why = "'preimage_hex' must be a string";
                    return 0;
                }
                if (n != 128) {
                    *why = "preimage must be 64 bytes (128 hex characters)";
                    return 0;
                }
                for (size_t i = 0; i < 64; i++) {
                    const int hi = hexval((unsigned char)s[2 * i]), lo = hexval((unsigned char)s[2 * i + 1]);
                    if (hi < 0 || lo < 0) {
                        *why = "'preimage_hex' is not valid hex";
                        return 0;
                    }
                    req->preimage[i] = (uint8_t)(hi << 4 | lo);
                }
                have_pre = 1;
            } else if (key_is(key, klen, "target_hex")) {
                const char *s;
                size_t n;
                if (!read_string(&c, &s, &n)) {
                    *why = "'target_hex' must be a string";
                    return 0;
                }
                if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
                    s += 2;
                    n -= 2;
                }
                if (n == 0) {
                    *why = "'target_hex' is not valid hex";
                    return 0;
                }
                /* Any value at or above the ceiling is used as the ceiling, as pyrxd does. */
                uint64_t v = 0;
                int saturated = 0;
                for (size_t i = 0; i < n; i++) {
                    const int d = hexval((unsigned char)s[i]);
                    if (d < 0) {
                        *why = "'target_hex' is not valid hex";
                        return 0;
                    }
                    if (!saturated) {
                        if (v > (MAX_SHA256D_TARGET >> 4)) {
                            saturated = 1;
                        } else {
                            v = (v << 4) | (uint64_t)d;
                        }
                    }
                }
                if (!saturated && v == 0) {
                    *why = "target must be positive";
                    return 0;
                }
                req->target = (saturated || v > MAX_SHA256D_TARGET) ? MAX_SHA256D_TARGET : v;
                have_target = 1;
            } else if (key_is(key, klen, "nonce_width") || key_is(key, klen, "protocol")) {
                int is_uint;
                uint64_t v;
                if (!read_number(&c, &is_uint, &v) || !is_uint) {
                    *why = key_is(key, klen, "protocol") ? "'protocol' must be an integer"
                                                         : "'nonce_width' must be an integer";
                    return 0;
                }
                if (key_is(key, klen, "protocol")) {
                    if (v != PROTOCOL_VERSION) {
                        *why = "unsupported protocol version (this miner speaks 1)";
                        return 0;
                    }
                } else {
                    if (v != 4 && v != 8) {
                        *why = "'nonce_width' must be 4 or 8";
                        return 0;
                    }
                    req->nonce_width = (unsigned)v;
                    have_width = 1;
                }
            } else {
                const char *s;
                size_t n;
                int is_uint;
                uint64_t v;
                if (c.p < c.end && *c.p == '"') {
                    if (!read_string(&c, &s, &n)) {
                        *why = "unsupported string in an unknown field";
                        return 0;
                    }
                } else if (!(read_literal(&c, "true") || read_literal(&c, "false") || read_literal(&c, "null") ||
                             read_number(&c, &is_uint, &v))) {
                    *why = "unsupported value in an unknown field";
                    return 0;
                }
            }
            if (take_char(&c, ',')) continue;
            if (take_char(&c, '}')) break;
            *why = "request is not valid JSON";
            return 0;
        }
    }
    skip_ws(&c);
    if (c.p != c.end) {
        *why = "trailing data after the request object";
        return 0;
    }
    if (!have_pre || !have_target || !have_width) {
        *why = !have_pre ? "request missing required field: 'preimage_hex'"
               : !have_target ? "request missing required field: 'target_hex'"
                              : "request missing required field: 'nonce_width'";
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------ self-test */

/* Plain one-shot SHA-256 of an arbitrary message, for the known-answer tests. */
static void sha256_oneshot(transform_fn tf, const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t s[8];
    memcpy(s, SHA256_IV, sizeof s);
    size_t off = 0;
    for (; off + 64 <= len; off += 64) tf(s, msg + off);
    uint8_t tail[128];
    const size_t rem = len - off;
    memset(tail, 0, sizeof tail);
    memcpy(tail, msg + off, rem);
    tail[rem] = 0x80;
    const size_t tail_len = (rem + 1 + 8 <= 64) ? 64 : 128;
    const uint64_t bits = (uint64_t)len * 8u;
    for (int i = 0; i < 8; i++) tail[tail_len - 1 - i] = (uint8_t)(bits >> (8 * i));
    tf(s, tail);
    if (tail_len == 128) tf(s, tail + 64);
    for (int i = 0; i < 8; i++) store_be32(out + 4 * i, s[i]);
}

static int selftest_impl(const char *name, transform_fn tf) {
    /* FIPS 180-2 appendix B vectors, plus the empty string. */
    static const struct {
        const char *msg;
        const char *digest;
    } vectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    };
    int ok = 1;
    for (size_t v = 0; v < sizeof vectors / sizeof vectors[0]; v++) {
        uint8_t d[32];
        char hex[65];
        sha256_oneshot(tf, (const uint8_t *)vectors[v].msg, strlen(vectors[v].msg), d);
        hex_encode(d, 32, hex);
        if (strcmp(hex, vectors[v].digest) != 0) {
            fprintf(stderr, "selftest %s: SHA-256(\"%s\") = %s, expected %s\n", name, vectors[v].msg, hex,
                    vectors[v].digest);
            ok = 0;
        }
    }
    /* The midstate path must equal a one-shot SHA256d of the same 68/72 bytes. */
    for (unsigned width = 4; width <= 8; width += 4) {
        uint8_t msg[72];
        for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7 + 3);
        const uint64_t nonce = 0x0123456789abcdefULL;
        for (unsigned i = 0; i < width; i++) msg[64 + i] = (uint8_t)(nonce >> (8 * i));
        uint8_t first[32], want[32];
        sha256_oneshot(tf, msg, 64 + width, first);
        sha256_oneshot(tf, first, 32, want);

        job_t job;
        memset(&job, 0, sizeof job);
        job.transform = tf;
        job.nonce_width = width;
        memcpy(job.midstate, SHA256_IV, sizeof job.midstate);
        tf(job.midstate, msg);
        uint8_t inner[64], outer[64];
        uint32_t w[8];
        inner_tail_init(inner, width);
        outer_block_init(outer);
        sha256d_attempt(&job, nonce, inner, outer, w);
        uint8_t got[32];
        for (int i = 0; i < 8; i++) store_be32(got + 4 * i, w[i]);
        if (memcmp(got, want, 32) != 0) {
            fprintf(stderr, "selftest %s: midstate SHA256d differs from one-shot for nonce_width=%u\n", name, width);
            ok = 0;
        }
    }
    return ok;
}

/* ------------------------------------------------------------ main */

static void usage(FILE *f) {
    fprintf(f,
            "usage: sha256d-grind [--workers N] [--quiet] [--impl auto|portable|shani]\n"
            "                     [--nonce-start N] [--nonce-count N] [--enumerate] [--target96 HEX]\n"
            "       sha256d-grind --selftest | --protocol-version | --help\n"
            "\n"
            "Native SHA256d grinder speaking pyrxd's external-miner protocol v%d: one JSON request on\n"
            "stdin, one JSON response on stdout, progress frames on stderr. See\n"
            "docs/concepts/parallel-mining.md.\n"
            "\n"
            "  --workers N      threads (default: the CPUs this process may run on)\n"
            "  --quiet          no progress frames or exhaustion message on stderr\n"
            "  --impl X         SHA-256 compression: auto (default), portable, or shani\n"
            "  --selftest       run the SHA-256 known-answer tests on every usable\n"
            "                   implementation, print the one auto would pick, and exit\n"
            "\n"
            "Test and diagnostic options (pyrxd's request never needs them):\n"
            "  --nonce-start N  first nonce to try (default 0)\n"
            "  --nonce-count N  nonces to try (default: the whole 2**(8*nonce_width) space)\n"
            "  --enumerate      try every nonce in the range and print each hit as\n"
            "                   '<nonce_hex> <digest_hex>', sorted; range at most 2**20\n"
            "  --target96 HEX   replace the rule's target with this 96-bit value (a hit is\n"
            "                   digest[0:12], big-endian, below it; up to 2**96)\n"
            "\n"
            "Exit codes:\n"
            "  0  solution found (stdout: {nonce_hex, attempts, elapsed_s})\n"
            "  1  usage / protocol error (stderr has details)\n"
            "  2  nonce range exhausted (stdout: {\"exhausted\": true})\n"
            "  3  solution found but writing it to stdout failed (stderr has details)\n",
            PROTOCOL_VERSION);
}

static int cmp_hit(const void *a, const void *b) {
    const uint64_t x = ((const hit_t *)a)->nonce, y = ((const hit_t *)b)->nonce;
    return (x > y) - (x < y);
}

static int read_all_stdin(char *buf, size_t cap, size_t *len) {
    size_t n = 0;
    for (;;) {
        if (n == cap) break;
        const size_t r = fread(buf + n, 1, cap - n, stdin);
        n += r;
        if (r == 0) {
            if (ferror(stdin)) return 0;
            break;
        }
    }
    *len = n;
    return 1;
}

int main(int argc, char **argv) {
    /*
     * If the process that started us dies without killing us (SIGKILL, a crash), stop rather
     * than grind on with no one to report to: the kernel's parent-death signal on Linux, and on
     * every platform the parent-pid check in the wait loop below.
     */
    const pid_t parent_at_start = getppid();
#if defined(__linux__)
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
#endif

    int workers = 0, quiet = 0, enumerate = 0, selftest = 0;
    const char *impl = "auto";
    uint64_t nonce_start = 0, nonce_count = 0;
    int have_count = 0, have_target96 = 0;
    u128 target96_override = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *val = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(a, "--protocol-version") == 0) {
            printf("sha256d-grind protocol v%d\n", PROTOCOL_VERSION);
            return 0;
        } else if (strcmp(a, "--quiet") == 0) {
            quiet = 1;
        } else if (strcmp(a, "--enumerate") == 0) {
            enumerate = 1;
        } else if (strcmp(a, "--selftest") == 0) {
            selftest = 1;
        } else if (strcmp(a, "--workers") == 0) {
            uint64_t v;
            if (!parse_u64_arg(val, &v) || v < 1 || v > MAX_THREADS) {
                fprintf(stderr, "--workers must be an integer from 1 to %d\n", MAX_THREADS);
                return EXIT_USAGE;
            }
            workers = (int)v;
            i++;
        } else if (strcmp(a, "--impl") == 0) {
            if (val == NULL || (strcmp(val, "auto") != 0 && strcmp(val, "portable") != 0 && strcmp(val, "shani") != 0)) {
                fprintf(stderr, "--impl must be auto, portable or shani\n");
                return EXIT_USAGE;
            }
            impl = val;
            i++;
        } else if (strcmp(a, "--nonce-start") == 0) {
            if (!parse_u64_arg(val, &nonce_start)) {
                fprintf(stderr, "--nonce-start must be a non-negative integer (decimal or 0x hex)\n");
                return EXIT_USAGE;
            }
            i++;
        } else if (strcmp(a, "--nonce-count") == 0) {
            if (!parse_u64_arg(val, &nonce_count) || nonce_count == 0) {
                fprintf(stderr, "--nonce-count must be a positive integer (decimal or 0x hex)\n");
                return EXIT_USAGE;
            }
            have_count = 1;
            i++;
        } else if (strcmp(a, "--target96") == 0) {
            if (val == NULL || *val == '\0' || strlen(val) > 25) {
                fprintf(stderr, "--target96 must be 1 to 25 hex digits\n");
                return EXIT_USAGE;
            }
            u128 v = 0;
            for (const char *s = val; *s; s++) {
                const int d = hexval((unsigned char)*s);
                if (d < 0) {
                    fprintf(stderr, "--target96 must be hex\n");
                    return EXIT_USAGE;
                }
                v = (v << 4) | (u128)d;
            }
            if (v == 0 || v > ((u128)1 << 96)) {
                fprintf(stderr, "--target96 must be in [1, 2**96]\n");
                return EXIT_USAGE;
            }
            target96_override = v;
            have_target96 = 1;
            i++;
        } else {
            fprintf(stderr, "unknown argument: %s\n", a);
            usage(stderr);
            return EXIT_USAGE;
        }
    }

    const int shani_ok = cpu_has_shani();
    transform_fn tf = sha256_transform_portable;
    const char *impl_name = "portable";
#if GRIND_HAVE_X86_SHANI
    if (strcmp(impl, "shani") == 0 && !shani_ok) {
        fprintf(stderr, "--impl shani: this CPU does not report the SHA extensions\n");
        return EXIT_USAGE;
    }
    if (shani_ok && strcmp(impl, "portable") != 0) {
        tf = sha256_transform_shani;
        impl_name = "shani";
    }
#else
    if (strcmp(impl, "shani") == 0) {
        fprintf(stderr, "--impl shani: not built for this architecture\n");
        return EXIT_USAGE;
    }
#endif

    if (selftest) {
        int ok = selftest_impl("portable", sha256_transform_portable);
#if GRIND_HAVE_X86_SHANI
        if (shani_ok) ok = selftest_impl("shani", sha256_transform_shani) && ok;
#endif
        printf("selftest %s: impl=%s shani_available=%d threads=%d\n", ok ? "ok" : "FAILED", impl_name, shani_ok,
               workers ? workers : default_threads());
        return ok ? 0 : EXIT_USAGE;
    }

    static char buf[MAX_REQUEST_BYTES + 1];
    size_t len;
    if (!read_all_stdin(buf, sizeof buf, &len)) {
        fprintf(stderr, "stdin read failed\n");
        return EXIT_USAGE;
    }
    if (len > MAX_REQUEST_BYTES) {
        fprintf(stderr, "request exceeds %d-byte cap\n", MAX_REQUEST_BYTES);
        return EXIT_USAGE;
    }
    request_t req;
    memset(&req, 0, sizeof req);
    const char *why = NULL;
    if (!parse_request(buf, len, &req, &why)) {
        fprintf(stderr, "protocol error: %s\n", why);
        return EXIT_USAGE;
    }

    job_t job;
    memset(&job, 0, sizeof job);
    job.transform = tf;
    job.nonce_width = req.nonce_width;
    job.target96 = have_target96 ? target96_override : (u128)req.target;
    memcpy(job.midstate, SHA256_IV, sizeof job.midstate);
    tf(job.midstate, req.preimage);
    const u128 space = (u128)1 << (8 * req.nonce_width);
    const u128 count = have_count ? (u128)nonce_count : space - (u128)nonce_start;
    job.start = nonce_start;
    job.end = (u128)nonce_start + count;
    if ((u128)nonce_start >= space || job.end > space) {
        fprintf(stderr, "nonce range [start, start + count) must lie inside the %u-byte nonce space\n",
                req.nonce_width);
        return EXIT_USAGE;
    }
    if (enumerate && count > MAX_ENUMERATE_NONCES) {
        fprintf(stderr, "--enumerate needs --nonce-count of at most %u\n", MAX_ENUMERATE_NONCES);
        return EXIT_USAGE;
    }

    const int n_threads = workers ? workers : default_threads();
    static sweep_t sw;
    sw.job = &job;
    sw.enumerate = enumerate;
    atomic_init(&sw.next_chunk, 0);
    atomic_init(&sw.stop, 0);
    atomic_init(&sw.attempts, 0);
    atomic_init(&sw.threads_done, 0);
    pthread_mutex_init(&sw.hit_mu, NULL);
    if (enumerate) {
        sw.cap_hits = (size_t)count;
        sw.hits = (hit_t *)calloc(sw.cap_hits, sizeof(hit_t));
        if (sw.hits == NULL) {
            fprintf(stderr, "out of memory\n");
            return EXIT_USAGE;
        }
    }

    const double started = now_s();
    pthread_t *tids = (pthread_t *)calloc((size_t)n_threads, sizeof(pthread_t));
    if (tids == NULL) {
        fprintf(stderr, "out of memory\n");
        return EXIT_USAGE;
    }
    int started_threads = 0;
    for (int t = 0; t < n_threads; t++) {
        if (pthread_create(&tids[t], NULL, sweep_thread, &sw) != 0) break;
        started_threads++;
    }
    if (started_threads == 0) {
        fprintf(stderr, "could not start any thread\n");
        return EXIT_USAGE;
    }

    double next_progress = started + PROGRESS_INTERVAL_S;
    while (atomic_load(&sw.threads_done) < started_threads) {
        const struct timespec ts = {0, POLL_INTERVAL_NS};
        nanosleep(&ts, NULL);
        if (getppid() != parent_at_start) _exit(EXIT_USAGE); /* orphaned: our parent is gone */
        const double t = now_s();
        if (!quiet && !enumerate && t >= next_progress) {
            next_progress = t + PROGRESS_INTERVAL_S;
            fprintf(stderr, "{\"progress\": {\"attempts\": %llu, \"elapsed_s\": %.3f}}\n",
                    (unsigned long long)atomic_load(&sw.attempts), t - started);
            fflush(stderr);
        }
    }
    for (int t = 0; t < started_threads; t++) pthread_join(tids[t], NULL);
    free(tids);
    const double elapsed = now_s() - started;
    const uint64_t attempts = atomic_load(&sw.attempts);

    if (enumerate) {
        if (sw.hits_overflow) {
            fprintf(stderr, "internal error: more hits than nonces\n");
            return EXIT_USAGE;
        }
        qsort(sw.hits, sw.n_hits, sizeof(hit_t), cmp_hit);
        for (size_t i = 0; i < sw.n_hits; i++) {
            uint8_t nb[8], d[32];
            char nh[17], dh[65];
            for (unsigned b = 0; b < job.nonce_width; b++) nb[b] = (uint8_t)(sw.hits[i].nonce >> (8 * b));
            for (int w = 0; w < 8; w++) store_be32(d + 4 * w, sw.hits[i].digest_words[w]);
            hex_encode(nb, job.nonce_width, nh);
            hex_encode(d, 32, dh);
            printf("%s %s\n", nh, dh);
        }
        fflush(stdout);
        free(sw.hits);
        return 0;
    }

    if (!sw.found) {
        if (!quiet) {
            fprintf(stderr, "exhausted %llu nonces across %d threads without finding a solution\n",
                    (unsigned long long)attempts, started_threads);
        }
        printf("{\"exhausted\": true}\n");
        fflush(stdout);
        return EXIT_EXHAUSTED;
    }
    uint8_t nb[8];
    char nh[17];
    for (unsigned b = 0; b < job.nonce_width; b++) nb[b] = (uint8_t)(sw.found_nonce >> (8 * b));
    hex_encode(nb, job.nonce_width, nh);
    const int written = printf("{\"nonce_hex\": \"%s\", \"attempts\": %llu, \"elapsed_s\": %.6f}\n", nh,
                               (unsigned long long)attempts, elapsed);
    if (written < 0 || fflush(stdout) != 0) {
        fprintf(stderr, "writing the solution to stdout failed: %s\n", strerror(errno));
        return EXIT_WRITE_FAILED;
    }
    return EXIT_FOUND;
}
