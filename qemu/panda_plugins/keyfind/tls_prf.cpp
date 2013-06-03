/* PANDABEGINCOMMENT PANDAENDCOMMENT */
#include "keyfind.h"

/* Mostly taken from Wireshark
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

void
ssl_print_data(const char* name, const unsigned char* data, size_t len)
{
#ifdef DEBUG
    size_t i;
    fprintf(stderr,"%s[%d]:\n",name, (int) len);
    for (i=0; i< len; i++) {
        if ((i > 0) && (i%16 == 0))
            fprintf(stderr,"\n");
        fprintf(stderr,"%.2x ",data[i]&255);
    }
    fprintf(stderr,"\n");
#endif
}

void
ssl_print_string(const char* name, const StringInfo* data)
{
    ssl_print_data(name, data->data, data->data_len);
}

int
ssl_data_alloc(StringInfo* str, size_t len)
{
    str->data = (unsigned char *)malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (unsigned int) len;
    return 0;
}

static int
tls_hash(StringInfo* secret, StringInfo* seed, const EVP_MD *md, StringInfo* out)
{
    uint8_t   *ptr;
    unsigned int     left;
    int      tocpy;
    uint8_t   *A;
    uint8_t    _A[48],tmp[48];
    unsigned int     A_l,tmp_l;
    HMAC_CTX ctx;
    ptr  = out->data;
    left = out->data_len;

    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    A=seed->data;
    A_l=seed->data_len;

    while(left){
        HMAC_CTX_init(&ctx);
        HMAC_Init(&ctx, secret->data, secret->data_len, md);
        HMAC_Update(&ctx,A,A_l);
        HMAC_Final(&ctx,_A,&A_l);
        HMAC_cleanup(&ctx);
        A=_A;

        HMAC_CTX_init(&ctx);
        HMAC_Init(&ctx,secret->data,secret->data_len,md);
        HMAC_Update(&ctx,A,A_l);
        HMAC_Update(&ctx,seed->data,seed->data_len);
        HMAC_Final(&ctx,tmp,&tmp_l);
        HMAC_cleanup(&ctx);

        tocpy=std::min(left,tmp_l);
        memcpy(ptr,tmp,tocpy);
        ptr+=tocpy;
        left-=tocpy;
    }

    ssl_print_string("hash out", out);
    return (0);
}

int
tls_prf(StringInfo* secret, const char *usage,
        StringInfo* rnd1, StringInfo* rnd2, StringInfo* out)
{
    StringInfo  seed, sha_out, md5_out;
    uint8_t     *ptr;
    StringInfo  s1, s2;
    unsigned int       i,s_l, r;
    size_t      usage_len;
    r         = -1;
    usage_len = strlen(usage);

    /* initalize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, std::max(out->data_len,20U)) < 0) {
        fprintf(stderr,"tls_prf: can't allocate sha out\n");
        return -1;
    }
    if (ssl_data_alloc(&md5_out, std::max(out->data_len,16U)) < 0) {
        fprintf(stderr,"tls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2->data_len) < 0) {
        fprintf(stderr, "tls_prf: can't allocate rnd %d\n",
                         (int) (usage_len+rnd1->data_len+rnd2->data_len));
        goto free_md5;
    }

    ptr=seed.data;
    memcpy(ptr,usage,usage_len);
    ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len);
    ptr+=rnd1->data_len;
    memcpy(ptr,rnd2->data,rnd2->data_len);
    /*ptr+=rnd2->data_len;*/

    /* initalize buffer for client/server seeds*/
    s_l=secret->data_len/2 + secret->data_len%2;
    if (ssl_data_alloc(&s1, s_l) < 0) {
        fprintf(stderr,"tls_prf: can't allocate secret %d\n", s_l);
        goto free_seed;
    }
    if (ssl_data_alloc(&s2, s_l) < 0) {
        fprintf(stderr,"tls_prf: can't allocate secret(2) %d\n", s_l);
        goto free_s1;
    }

    memcpy(s1.data,secret->data,s_l);
    memcpy(s2.data,secret->data + (secret->data_len - s_l),s_l);

    //fprintf(stderr,"tls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len, seed.data_len);
    if(tls_hash(&s1,&seed,EVP_md5(),&md5_out) != 0)
        goto free_all;
    //fprintf(stderr,"tls_prf: tls_hash(sha)\n");
    if(tls_hash(&s2,&seed,EVP_sha1(),&sha_out) != 0)
        goto free_all;

    for(i=0;i<out->data_len;i++)
      out->data[i]=md5_out.data[i] ^ sha_out.data[i];
    r =0;

    ssl_print_string("PRF out",out);
free_all:
    free(s2.data);
free_s1:
    free(s1.data);
free_seed:
    free(seed.data);
free_md5:
    free(md5_out.data);
free_sha:
    free(sha_out.data);
    return r;
}

int
tls12_prf(const EVP_MD *md, StringInfo* secret, const char* usage, StringInfo* rnd1, StringInfo* rnd2, StringInfo* out)
{
    StringInfo label_seed;
    size_t     usage_len;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2->data_len) < 0) {
        fprintf(stderr,"tls12_prf: can't allocate label_seed\n");
        return -1;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    //fprintf(stderr,"tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", EVP_MD_name(md), secret->data_len, label_seed.data_len);
    if (tls_hash(secret, &label_seed, md, out) != 0){
        free(label_seed.data);
        return -1;
    }
    ssl_print_string("PRF out", out);
    return 0;
}
