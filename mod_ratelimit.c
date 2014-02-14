/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"

#include "mod_ratelimit.h"

#define RATE_LIMIT_FILTER_NAME "RATE_LIMIT"
#define RATE_INTERVAL_MS (200)

typedef enum rl_state_e
{
    RATE_ERROR,
    RATE_LIMIT,
    RATE_FULLSPEED
} rl_state_e;

typedef struct rl_ctx_t
{
    int speed;
    int chunk_size;
    int collected_bytes;
    rl_state_e state;
    apr_bucket_brigade *tmpbb;
    // tail of the input brigade
    apr_bucket_brigade *holdingbb;
    apr_bucket_brigade *collectorbb;
} rl_ctx_t;

#if 1
static void brigade_dump(request_rec *r, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    int i = 0;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e), i++) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "brigade: [%d] %s", i, e->type->name);

    }
}
#endif

static apr_status_t
rate_limit_filter(ap_filter_t *f, apr_bucket_brigade *input_bb)
{
    apr_status_t rv = APR_SUCCESS;
    rl_ctx_t *ctx = f->ctx;
    apr_bucket *fb;
    int do_sleep = 0;
    apr_bucket_alloc_t *ba = f->r->connection->bucket_alloc;
    apr_bucket_brigade *bb = input_bb;
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "rl: start");
    brigade_dump(f->r, bb);

    if (f->c->aborted) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "rl: conn aborted");
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (ctx == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "rl: init context");
        const char *rl = NULL;
        int ratelimit;

        /* no subrequests. */
        if (f->r->main != NULL) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        rl = apr_table_get(f->r->subprocess_env, "rate-limit");

        if (rl == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "rl: can not find rate-limit, removing filter");
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "rl: found rate-limit %s", rl);

        /* rl is in kilo bytes / second  */
        ratelimit = atoi(rl) * 1024;
        if (ratelimit <= 0) {
            /* remove ourselves */
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* first run, init stuff */
        ctx = apr_palloc(f->r->pool, sizeof(rl_ctx_t));
        f->ctx = ctx;
        ctx->state = RATE_LIMIT;
        ctx->speed = ratelimit;

        /* calculate how many bytes / interval we want to send */
        /* speed is bytes / second, so, how many  (speed / 1000 % interval) */
        ctx->chunk_size = (ctx->speed / (1000 / RATE_INTERVAL_MS));
        ctx->collected_bytes = 0;
        ctx->tmpbb = apr_brigade_create(f->r->pool, ba);
        ctx->holdingbb = apr_brigade_create(f->r->pool, ba);
        ctx->collectorbb = apr_brigade_create(f->r->pool, ba);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "rl: chunk size %d", ctx->chunk_size);
    }

    apr_off_t len = 0;
    apr_brigade_length(input_bb, 1, &len);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                      "rl: input_bb len %ld", len);
    APR_BRIGADE_CONCAT(ctx->collectorbb, input_bb);
    ctx->collected_bytes += len;
    int is_last_brigade = APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(ctx->collectorbb));

    // mod proxy returns small brigades under 8000 bytes,
    // so we need to collect them
    if (ctx->collected_bytes < ctx->chunk_size && !is_last_brigade) {
        return rv;
    }

    bb = ctx->collectorbb;

    while (ctx->state != RATE_ERROR &&
           (!APR_BRIGADE_EMPTY(bb) || !APR_BRIGADE_EMPTY(ctx->holdingbb))) {
        apr_bucket *e;

        if (!APR_BRIGADE_EMPTY(ctx->holdingbb)) {
            APR_BRIGADE_CONCAT(bb, ctx->holdingbb);
            apr_brigade_cleanup(ctx->holdingbb);
        }

        while (ctx->state == RATE_FULLSPEED && !APR_BRIGADE_EMPTY(bb)) {
            /* Find where we 'stop' going full speed. */
            for (e = APR_BRIGADE_FIRST(bb);
                 e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
                if (AP_RL_BUCKET_IS_END(e)) {
                    apr_bucket *f;
                    f = APR_RING_LAST(&bb->list);
                    APR_RING_UNSPLICE(e, f, link);
                    APR_RING_SPLICE_TAIL(&ctx->holdingbb->list, e, f,
                                         apr_bucket, link);
                    ctx->state = RATE_LIMIT;
                    break;
                }
            }

            if (f->c->aborted) {
                apr_brigade_cleanup(bb);
                ctx->state = RATE_ERROR;
                break;
            }

            fb = apr_bucket_flush_create(ba);
            APR_BRIGADE_INSERT_TAIL(bb, fb);
            rv = ap_pass_brigade(f->next, bb);

            if (rv != APR_SUCCESS) {
                ctx->state = RATE_ERROR;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              "rl: full speed brigade pass failed.");
            }
        }

        while (ctx->state == RATE_LIMIT && !APR_BRIGADE_EMPTY(bb)) {
            for (e = APR_BRIGADE_FIRST(bb);
                 e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
                if (AP_RL_BUCKET_IS_START(e)) {
                    apr_bucket *f1;
                    f1 = APR_RING_LAST(&bb->list);
                    APR_RING_UNSPLICE(e, f1, link);
                    APR_RING_SPLICE_TAIL(&ctx->holdingbb->list, e, f1,
                                         apr_bucket, link);
                    ctx->state = RATE_FULLSPEED;
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                              "rl: going full speed");
                    brigade_dump(f->r, ctx->holdingbb);
                    break;
                }
            }

            while (!APR_BRIGADE_EMPTY(bb)) {
                apr_bucket *stop_point;

                if (f->c->aborted) {
                    apr_brigade_cleanup(bb);
                    ctx->state = RATE_ERROR;
                    break;
                }

                if (do_sleep) {
                }
                else {
                    do_sleep = 1;
                }

                rv = apr_brigade_partition(bb, ctx->chunk_size, &stop_point);
                if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
                    ctx->state = RATE_ERROR;
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                                  "rl: partition failed.");
                    break;
                }

                if (stop_point != APR_BRIGADE_SENTINEL(bb)) {
                    apr_bucket *f;
                    apr_bucket *e = APR_BUCKET_PREV(stop_point);
                    f = APR_RING_FIRST(&bb->list);
                    APR_RING_UNSPLICE(f, e, link);
                    APR_RING_SPLICE_HEAD(&ctx->tmpbb->list, f, e, apr_bucket,
                                         link);
                }
                else {
                    APR_BRIGADE_CONCAT(ctx->tmpbb, bb);
                }

                apr_brigade_length(ctx->tmpbb, 1, &len);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                                  "rl: tmpbb len %d", len);

                fb = apr_bucket_flush_create(ba);

                APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, fb);

#if 1
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "tmpbb");
                brigade_dump(f->r, ctx->tmpbb);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "bb");
                brigade_dump(f->r, bb);
#endif

                rv = ap_pass_brigade(f->next, ctx->tmpbb);
                apr_brigade_cleanup(ctx->tmpbb);
                ctx->collected_bytes -= len;

                if (rv != APR_SUCCESS) {
                    ctx->state = RATE_ERROR;
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                                  "rl: brigade pass failed.");
                    break;
                }

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                                  "rl: remaining len %d", ctx->collected_bytes);

                if (ctx->collected_bytes > 0) {
                    apr_sleep(RATE_INTERVAL_MS * 1000);
                }

                if (ctx->collected_bytes < ctx->chunk_size && !is_last_brigade) {
                    return rv;
                }
            }
        }
    }

    return rv;
}


static apr_status_t
rl_bucket_read(apr_bucket *b, const char **str,
               apr_size_t *len, apr_read_type_e block)
{
    *str = NULL;
    *len = 0;
    return APR_SUCCESS;
}

AP_RL_DECLARE(apr_bucket *)
    ap_rl_end_create(apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->length = 0;
    b->start = 0;
    b->data = NULL;
    b->type = &ap_rl_bucket_type_end;

    return b;
}

AP_RL_DECLARE(apr_bucket *)
    ap_rl_start_create(apr_bucket_alloc_t *list)
{
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->length = 0;
    b->start = 0;
    b->data = NULL;
    b->type = &ap_rl_bucket_type_start;

    return b;
}



AP_RL_DECLARE_DATA const apr_bucket_type_t ap_rl_bucket_type_end = {
    "RL_END", 5, APR_BUCKET_METADATA,
    apr_bucket_destroy_noop,
    rl_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_simple_copy
};


AP_RL_DECLARE_DATA const apr_bucket_type_t ap_rl_bucket_type_start = {
    "RL_START", 5, APR_BUCKET_METADATA,
    apr_bucket_destroy_noop,
    rl_bucket_read,
    apr_bucket_setaside_noop,
    apr_bucket_split_notimpl,
    apr_bucket_simple_copy
};




static void register_hooks(apr_pool_t *p)
{
    /* run after mod_deflate etc etc, but not at connection level, ie, mod_ssl. */
    ap_register_output_filter(RATE_LIMIT_FILTER_NAME, rate_limit_filter,
                              NULL, AP_FTYPE_PROTOCOL + 3);
}

/************************************************************************
 * apache module definition
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA ratelimit_module ={
  STANDARD20_MODULE_STUFF,
  NULL,                    /**< dir config creater */
  NULL,                     /**< dir merger */
  NULL,                    /**< server config */
  NULL,                     /**< server merger */
  NULL,                      /**< command table */
  register_hooks,                       /**< hook registery */
};
