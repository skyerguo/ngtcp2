/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "ngtcp2_rtb_test.h"

#include <assert.h>

#include <CUnit/CUnit.h>

#include "ngtcp2_rtb.h"
#include "ngtcp2_test_helper.h"
#include "ngtcp2_mem.h"
#include "ngtcp2_pkt.h"

static void conn_stat_init(ngtcp2_conn_stat *cstat) {
  memset(cstat, 0, sizeof(*cstat));
}

void test_ngtcp2_rtb_add(void) {
  ngtcp2_rtb rtb;
  ngtcp2_rtb_entry *ent;
  int rv;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_pkt_hd hd;
  ngtcp2_log log;
  ngtcp2_cid dcid;
  ngtcp2_ksl_it it;
  ngtcp2_conn_stat cstat;
  ngtcp2_cc cc;
  ngtcp2_strm crypto;
  const ngtcp2_pktns_id pktns_id = NGTCP2_PKTNS_ID_HANDSHAKE;
  ngtcp2_rst rst;

  ngtcp2_strm_init(&crypto, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);
  dcid_init(&dcid);
  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, &dcid, NULL,
                     1000000007, 1, NGTCP2_PROTO_VER_MAX, 0);

  rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, 10, 0, NGTCP2_RTB_ENTRY_FLAG_NONE,
                            mem);

  CU_ASSERT(0 == rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, &dcid, NULL,
                     1000000008, 2, NGTCP2_PROTO_VER_MAX, 0);

  rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, 9, 0, NGTCP2_RTB_ENTRY_FLAG_NONE,
                            mem);

  CU_ASSERT(0 == rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat);

  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, &dcid, NULL,
                     1000000009, 4, NGTCP2_PROTO_VER_MAX, 0);

  rv = ngtcp2_rtb_entry_new(&ent, &hd, NULL, 11, 0, NGTCP2_RTB_ENTRY_FLAG_NONE,
                            mem);

  CU_ASSERT(0 == rv);

  ngtcp2_rtb_add(&rtb, ent, &cstat);

  it = ngtcp2_rtb_head(&rtb);
  ent = ngtcp2_ksl_it_get(&it);

  /* Check the top of the queue */
  CU_ASSERT(1000000009 == ent->hd.pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(1000000008 == ent->hd.pkt_num);

  ngtcp2_ksl_it_next(&it);
  ent = ngtcp2_ksl_it_get(&it);

  CU_ASSERT(1000000007 == ent->hd.pkt_num);

  ngtcp2_ksl_it_next(&it);

  CU_ASSERT(ngtcp2_ksl_it_end(&it));

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);
  ngtcp2_strm_free(&crypto);
}

static void add_rtb_entry_range(ngtcp2_rtb *rtb, int64_t base_pkt_num,
                                size_t len, ngtcp2_conn_stat *cstat,
                                const ngtcp2_mem *mem) {
  ngtcp2_pkt_hd hd;
  ngtcp2_rtb_entry *ent;
  size_t i;
  ngtcp2_cid dcid;

  dcid_init(&dcid);

  for (i = 0; i < len; ++i) {
    ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, &dcid, NULL,
                       base_pkt_num + (int64_t)i, 1, NGTCP2_PROTO_VER_MAX, 0);
    ngtcp2_rtb_entry_new(&ent, &hd, NULL, 0, 0, NGTCP2_RTB_ENTRY_FLAG_NONE,
                         mem);
    ngtcp2_rtb_add(rtb, ent, cstat);
  }
}

static void setup_rtb_fixture(ngtcp2_rtb *rtb, ngtcp2_conn_stat *cstat,
                              const ngtcp2_mem *mem) {
  /* 100, ..., 154 */
  add_rtb_entry_range(rtb, 100, 55, cstat, mem);
  /* 180, ..., 184 */
  add_rtb_entry_range(rtb, 180, 5, cstat, mem);
  /* 440, ..., 446 */
  add_rtb_entry_range(rtb, 440, 7, cstat, mem);
}

static void assert_rtb_entry_not_found(ngtcp2_rtb *rtb, int64_t pkt_num) {
  ngtcp2_ksl_it it = ngtcp2_rtb_head(rtb);
  ngtcp2_rtb_entry *ent;

  for (; !ngtcp2_ksl_it_end(&it); ngtcp2_ksl_it_next(&it)) {
    ent = ngtcp2_ksl_it_get(&it);
    CU_ASSERT(ent->hd.pkt_num != pkt_num);
  }
}

void test_ngtcp2_rtb_recv_ack(void) {
  ngtcp2_rtb rtb;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_max_frame mfr;
  ngtcp2_ack *fr = &mfr.ackfr.ack;
  ngtcp2_ack_blk *blks;
  ngtcp2_log log;
  ngtcp2_conn_stat cstat;
  ngtcp2_cc cc;
  ngtcp2_pkt_hd hd;
  ngtcp2_ssize num_acked;
  ngtcp2_strm crypto;
  const ngtcp2_pktns_id pktns_id = NGTCP2_PKTNS_ID_HANDSHAKE;
  ngtcp2_rst rst;

  ngtcp2_strm_init(&crypto, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_SHORT, NULL, NULL, 0,
                     1, NGTCP2_PROTO_VER_MAX, 0);

  /* no ack block */
  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);
  setup_rtb_fixture(&rtb, &cstat, mem);

  CU_ASSERT(67 == ngtcp2_ksl_len(&rtb.ents));

  fr->largest_ack = 446;
  fr->first_ack_blklen = 1;
  fr->num_blks = 0;

  num_acked =
      ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, NULL, 1000000009, 1000000009);

  CU_ASSERT(2 == num_acked);
  CU_ASSERT(65 == ngtcp2_ksl_len(&rtb.ents));
  assert_rtb_entry_not_found(&rtb, 446);
  assert_rtb_entry_not_found(&rtb, 445);

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);

  /* with ack block */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);
  setup_rtb_fixture(&rtb, &cstat, mem);

  fr->largest_ack = 441;
  fr->first_ack_blklen = 3; /* (441), (440), 439, 438 */
  fr->num_blks = 2;
  blks = fr->blks;
  blks[0].gap = 253;
  blks[0].blklen = 0; /* (183) */
  blks[1].gap = 1;    /* 182, 181 */
  blks[1].blklen = 1; /* (180), 179 */

  num_acked =
      ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, NULL, 1000000009, 1000000009);

  CU_ASSERT(4 == num_acked);
  CU_ASSERT(63 == ngtcp2_ksl_len(&rtb.ents));
  CU_ASSERT(441 == rtb.largest_acked_tx_pkt_num);
  assert_rtb_entry_not_found(&rtb, 441);
  assert_rtb_entry_not_found(&rtb, 440);
  assert_rtb_entry_not_found(&rtb, 183);
  assert_rtb_entry_not_found(&rtb, 180);

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);

  /* gap+blklen points to pkt_num 0 */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, mem);

  fr->largest_ack = 250;
  fr->first_ack_blklen = 0;
  fr->num_blks = 1;
  fr->blks[0].gap = 248;
  fr->blks[0].blklen = 0;

  num_acked =
      ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, NULL, 1000000009, 1000000009);

  CU_ASSERT(1 == num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);

  /* pkt_num = 0 (first ack block) */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, mem);

  fr->largest_ack = 0;
  fr->first_ack_blklen = 0;
  fr->num_blks = 0;

  num_acked =
      ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, NULL, 1000000009, 1000000009);

  CU_ASSERT(1 == num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);

  /* pkt_num = 0 */
  conn_stat_init(&cstat);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);
  add_rtb_entry_range(&rtb, 0, 1, &cstat, mem);

  fr->largest_ack = 2;
  fr->first_ack_blklen = 0;
  fr->num_blks = 1;
  fr->blks[0].gap = 0;
  fr->blks[0].blklen = 0;

  num_acked =
      ngtcp2_rtb_recv_ack(&rtb, fr, &cstat, NULL, NULL, 1000000009, 1000000009);

  CU_ASSERT(1 == num_acked);
  assert_rtb_entry_not_found(&rtb, 0);

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);
  ngtcp2_strm_free(&crypto);
}

void test_ngtcp2_rtb_lost_pkt_ts(void) {
  ngtcp2_rtb rtb;
  const ngtcp2_pktns_id pktns_id = NGTCP2_PKTNS_ID_APPLICATION;
  ngtcp2_strm crypto;
  ngtcp2_log log;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cc cc;
  ngtcp2_rst rst;
  ngtcp2_conn_stat cstat;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;

  ngtcp2_strm_init(&crypto, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);

  add_rtb_entry_range(&rtb, 0, 1, &cstat, mem);

  CU_ASSERT(UINT64_MAX == ngtcp2_rtb_lost_pkt_ts(&rtb));

  it = ngtcp2_ksl_end(&rtb.ents);
  ngtcp2_ksl_it_prev(&it);
  ent = ngtcp2_ksl_it_get(&it);
  ent->flags |= NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
  ent->lost_ts = 16777217;

  CU_ASSERT(16777217 == ngtcp2_rtb_lost_pkt_ts(&rtb));

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);
  ngtcp2_strm_free(&crypto);
}

void test_ngtcp2_rtb_remove_expired_lost_pkt(void) {
  ngtcp2_rtb rtb;
  const ngtcp2_pktns_id pktns_id = NGTCP2_PKTNS_ID_APPLICATION;
  ngtcp2_strm crypto;
  ngtcp2_log log;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cc cc;
  ngtcp2_rst rst;
  ngtcp2_conn_stat cstat;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  size_t i;

  ngtcp2_strm_init(&crypto, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);

  add_rtb_entry_range(&rtb, 0, 7, &cstat, mem);

  it = ngtcp2_ksl_end(&rtb.ents);

  for (i = 0; i < 5; ++i) {
    ngtcp2_ksl_it_prev(&it);
    ent = ngtcp2_ksl_it_get(&it);
    ent->flags |= NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
    ent->lost_ts = 16777217 + i;
  }

  ngtcp2_rtb_remove_expired_lost_pkt(&rtb, 1, 16777219);

  CU_ASSERT(5 == ngtcp2_ksl_len(&rtb.ents));

  ngtcp2_rtb_remove_expired_lost_pkt(&rtb, 1, 16777223);

  CU_ASSERT(2 == ngtcp2_ksl_len(&rtb.ents));

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);
  ngtcp2_strm_free(&crypto);
}

void test_ngtcp2_rtb_remove_excessive_lost_pkt(void) {
  ngtcp2_rtb rtb;
  const ngtcp2_pktns_id pktns_id = NGTCP2_PKTNS_ID_APPLICATION;
  ngtcp2_strm crypto;
  ngtcp2_log log;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  ngtcp2_cc cc;
  ngtcp2_rst rst;
  ngtcp2_conn_stat cstat;
  ngtcp2_ksl_it it;
  ngtcp2_rtb_entry *ent;
  size_t i;

  ngtcp2_strm_init(&crypto, 0, NGTCP2_STRM_FLAG_NONE, 0, 0, NULL, mem);
  ngtcp2_log_init(&log, NULL, NULL, 0, NULL);

  conn_stat_init(&cstat);
  ngtcp2_rst_init(&rst);
  ngtcp2_cc_reno_cc_init(&cc, &log, mem);
  ngtcp2_rtb_init(&rtb, pktns_id, &crypto, &rst, &cc, &log, NULL, mem);

  add_rtb_entry_range(&rtb, 0, 7, &cstat, mem);

  it = ngtcp2_ksl_end(&rtb.ents);

  for (i = 0; i < 5; ++i) {
    ngtcp2_ksl_it_prev(&it);
    ent = ngtcp2_ksl_it_get(&it);
    ent->flags |= NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
    ent->lost_ts = 16777217;
    ++rtb.num_lost_pkts;
  }

  ngtcp2_rtb_remove_excessive_lost_pkt(&rtb, 2);

  CU_ASSERT(4 == ngtcp2_ksl_len(&rtb.ents));

  ngtcp2_rtb_free(&rtb);
  ngtcp2_cc_reno_cc_free(&cc, mem);
  ngtcp2_strm_free(&crypto);
}
