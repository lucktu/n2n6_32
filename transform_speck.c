#include "n2n.h"
#include "n2n_transforms.h"
#include "speck.h"
#include "random.h"
#include <time.h>

#define N2N_SPECK_TRANSFORM_VERSION   1
#define N2N_SPECK_NONCE_SIZE          16

typedef struct transop_speck {
    speck_context_t ctx;
} transop_speck_t;

/* Pearson hash 256 implementation - compatible with user's version */
static void pearson_hash_256(uint8_t *out, const uint8_t *in, size_t len) {
    uint8_t idx = 0;
    uint8_t hash[256];
    int i, j;

    /* Initialize hash table */
    for (i = 0; i < 256; i++) {
        hash[i] = (uint8_t)i;
    }

    /* Shuffle hash table using input data */
    for (i = 0; i < 256; i++) {
        idx = (hash[i] + in[i % len]) & 0xFF;
        uint8_t tmp = hash[i];
        hash[i] = hash[idx];
        hash[idx] = tmp;
    }

    /* Generate 256-bit hash */
    idx = 0;
    for (i = 0; i < 32; i++) {
        idx = (hash[idx] + i) & 0xFF;
        out[i] = hash[idx];
    }
}

/* n2n_rand implementation for compatibility */
static uint64_t n2n_rand(void) {
    static uint64_t seed = 0;
    if (seed == 0) {
        seed = time(NULL) ^ getpid();
    }
    seed = seed * 1103515245 + 12345;
    return seed;
}

/* Modified setup_speck_key function using pearson_hash_256 */
int setup_speck_key(void *priv, const uint8_t *encrypt_key, size_t encrypt_key_len) {
    transop_speck_t *speck_priv = (transop_speck_t *)priv;
    uint8_t key_mat_buf[32] = {0};

    /* Clear out any old possibly longer key matter. */
    memset(&(speck_priv->ctx), 0, sizeof(speck_context_t));

    /* The input key always gets hashed to make a more unpredictable and more complete use of the key space */
    pearson_hash_256(key_mat_buf, encrypt_key, encrypt_key_len);

    /* Expand the key material to the context (= round keys) */
    speck_expand_key(key_mat_buf, &speck_priv->ctx);

    traceEvent(TRACE_DEBUG, "Speck key setup completed\n");
    return 0;
}

int transop_deinit_speck(n2n_trans_op_t *arg) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    if (priv) {
#if defined (SPECK_ALIGNED_CTX)
        _mm_free(priv);
#else
        free(priv);
#endif
    }
    return 0;
}

/* Generate IV using n2n_rand for compatibility */
static void set_speck_iv(transop_speck_t *priv, uint8_t *ivec) {
    /* Keep in mind the following condition: N2N_SPECK_NONCE_SIZE % sizeof(rand_value) == 0 ! */
    uint64_t rand_value;
    uint8_t i;

    for (i = 0; i < N2N_SPECK_NONCE_SIZE; i += sizeof(rand_value)) {
        rand_value = n2n_rand();
        memcpy(ivec + i, &rand_value, sizeof(rand_value));
    }
}

ssize_t transop_encode_speck(n2n_trans_op_t *arg,
                            uint8_t *outbuf,
                            size_t out_len,
                            const uint8_t *inbuf,
                            size_t in_len) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    uint8_t nonce[N2N_SPECK_NONCE_SIZE];
    size_t idx = 0;

    if (out_len < in_len + N2N_SPECK_NONCE_SIZE + 1) {
        return -1;
    }
    if (!priv || !arg->priv) {
        traceEvent(TRACE_ERROR, "Speck transform not initialized");
        return -1;
    }

    /* Version byte */
    outbuf[idx++] = N2N_SPECK_TRANSFORM_VERSION;

    /* Generate and encode the IV using n2n_rand for compatibility */
    set_speck_iv(priv, nonce);
    memcpy(outbuf + idx, nonce, N2N_SPECK_NONCE_SIZE);
    idx += N2N_SPECK_NONCE_SIZE;

    /* Encrypt data */
    speck_ctr(outbuf + idx, inbuf, in_len, nonce, &priv->ctx);
    idx += in_len;

    traceEvent(TRACE_DEBUG, "encode_speck: encrypted %u bytes.\n", in_len);
    return idx;
}

ssize_t transop_decode_speck(n2n_trans_op_t *arg,
                             uint8_t *outbuf,
                             size_t out_len,
                             const uint8_t *inbuf,
                             size_t in_len) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    uint8_t nonce[N2N_SPECK_NONCE_SIZE];
    size_t idx = 0;

    if (in_len < N2N_SPECK_NONCE_SIZE + 1) {
        return -1;
    }

    /* Check version */
    if (inbuf[idx++] != N2N_SPECK_TRANSFORM_VERSION) {
        traceEvent(TRACE_ERROR, "decode_speck unsupported Speck version %u.", inbuf[idx-1]);
        return -1;
    }

    /* Extract nonce */
    memcpy(nonce, inbuf + idx, N2N_SPECK_NONCE_SIZE);
    idx += N2N_SPECK_NONCE_SIZE;

    /* Decrypt data */
    speck_ctr(outbuf, inbuf + idx, in_len - idx, nonce, &priv->ctx);

    traceEvent(TRACE_DEBUG, "decode_speck: decrypted %u bytes.\n", in_len - idx);
    return in_len - idx;
}

n2n_tostat_t transop_tick_speck(n2n_trans_op_t *arg, time_t now) {
    n2n_tostat_t status;
    status.can_tx = 1;
    status.tx_spec.t = N2N_TRANSFORM_ID_SPECK;
    status.tx_spec.valid_from = 0;
    status.tx_spec.valid_until = 0xFFFFFFFF;
    return status;
}

int transop_addspec_speck(n2n_trans_op_t *arg, const n2n_cipherspec_t *cspec) {
    const char *key_data = (const char *)cspec->opaque;
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    size_t key_len;

    /* Skip "0_" prefix if present */
    if (strlen(key_data) > 2 && key_data[0] == '0' && key_data[1] == '_') {
        key_data += 2;
    }

    key_len = strlen(key_data);

    /* Use setup_speck_key with pearson_hash_256 */
    return setup_speck_key(priv, (const uint8_t *)key_data, key_len);
}

int transop_speck_init(n2n_trans_op_t *ttt) {
    transop_speck_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_SPECK;

    ttt->tick = transop_tick_speck;
    ttt->deinit = transop_deinit_speck;
    ttt->fwd = transop_encode_speck;
    ttt->rev = transop_decode_speck;
    ttt->addspec = transop_addspec_speck;

#if defined (SPECK_ALIGNED_CTX)
    priv = (transop_speck_t*) _mm_malloc(sizeof(transop_speck_t), SPECK_ALIGNED_CTX);
#else
    priv = (transop_speck_t*) calloc(1, sizeof(transop_speck_t));
#endif
    if (!priv) {
        traceEvent(TRACE_ERROR, "cannot allocate transop_speck_t memory");
        return -1;
    }
    ttt->priv = priv;

    return 0;
}