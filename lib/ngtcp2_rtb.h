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
#ifndef NGTCP2_RTB_H
#define NGTCP2_RTB_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_pq.h"
#include "ngtcp2_map.h"

struct ngtcp2_conn;
typedef struct ngtcp2_conn ngtcp2_conn;

struct ngtcp2_frame_chain;
typedef struct ngtcp2_frame_chain ngtcp2_frame_chain;

/*
 * ngtcp2_frame_chain chains frames in a single packet.
 */
struct ngtcp2_frame_chain {
  ngtcp2_frame_chain *next;
  ngtcp2_frame fr;
};

/*
 * ngtcp2_frame_chain_new allocates ngtcp2_frame_chain object and
 * assigns its pointer to |*pfrc|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_frame_chain_new(ngtcp2_frame_chain **pfrc, ngtcp2_mem *mem);

/*
 * ngtcp2_frame_chain_del deallocates |frc|.  It also deallocates the
 * memory pointed by |frc|.
 */
void ngtcp2_frame_chain_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem);

/*
 * ngtcp2_frame_chain_init initializes |frc|.
 */
void ngtcp2_frame_chain_init(ngtcp2_frame_chain *frc);

typedef enum {
  NGTCP2_RTB_FLAG_NONE = 0x00,
  /* NGTCP2_RTB_FLAG_UNPROTECTED indicates that the entry contains
     frames which were sent in an unprotected packet. */
  NGTCP2_RTB_FLAG_UNPROTECTED = 0x1,
} ngtcp2_rtb_flag;

struct ngtcp2_rtb_entry;
typedef struct ngtcp2_rtb_entry ngtcp2_rtb_entry;

/*
 * ngtcp2_rtb_entry is an object stored in ngtcp2_rtb.  It corresponds
 * to the one packet which is waiting for its ACK.
 */
struct ngtcp2_rtb_entry {
  ngtcp2_pq_entry pe;
  ngtcp2_rtb_entry **pprev, *next;

  ngtcp2_pkt_hd hd;
  ngtcp2_frame_chain *frc;
  /* expiry is the time point when this entry expires, and the
     retransmission is required. */
  ngtcp2_tstamp expiry;
  /* deadline is the time point when the library gives up
     retransmission of a packet, and closes its connection. */
  ngtcp2_tstamp deadline;
  /* count is the number of times a retransmission has been sent. */
  size_t count;
  /* pktlen is the length of QUIC packet */
  size_t pktlen;
  /* flags is bitwise-OR of zero or more of ngtcp2_rtb_flag. */
  uint8_t flags;
};

/*
 * ngtcp2_rtb_entry_new allocates ngtcp2_rtb_entry object, and assigns
 * its pointer to |*pent|.  On success, |*pent| takes ownership of
 * |frc|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_rtb_entry_new(ngtcp2_rtb_entry **pent, const ngtcp2_pkt_hd *hd,
                         ngtcp2_frame_chain *frc, ngtcp2_tstamp ts,
                         ngtcp2_tstamp deadline, size_t pktlen, uint8_t flags,
                         ngtcp2_mem *mem);

/*
 * ngtcp2_rtb_entry_del deallocates |ent|.  It also frees memory
 * pointed by |ent|.
 */
void ngtcp2_rtb_entry_del(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem);

/*
 * ngtcp2_rtb_entry_extend_expiry extends expiry for a next
 * retransmission.
 */
void ngtcp2_rtb_entry_extend_expiry(ngtcp2_rtb_entry *ent, ngtcp2_tstamp ts);

/*
 * ngtcp2_rtb tracks sent packets, and its ACK timeout for
 * retransmission.
 */
typedef struct {
  /* pq is a priority queue, and sorted by lesser timeout */
  ngtcp2_pq pq;
  /* head points to the singly linked list of ngtcp2_rtb_entry, sorted
     by decreasing order of packet number. */
  ngtcp2_rtb_entry *head;
  ngtcp2_mem *mem;
  /* bytes_in_flight is the sum of packet length linked from head. */
  size_t bytes_in_flight;
  /* largest_acked is the largest packet number acknowledged by the
     peer. */
  uint64_t largest_acked;
} ngtcp2_rtb;

/*
 * ngtcp2_rtb_init initializes |rtb|.
 */
void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_mem *mem);

/*
 * ngtcp2_rtb_free deallocates resources allocated for |rtb|.
 */
void ngtcp2_rtb_free(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_add adds |ent| to |rtb|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 * NGTCP2_ERR_INVALID_ARGUMENT
 *     The same packet number has already been added.
 */
int ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent);

/*
 * ngtcp2_rtb_top returns the entry which has the least expiry value.
 * It returns NULL if there is no entry.
 */
ngtcp2_rtb_entry *ngtcp2_rtb_top(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_pop removes the entry which has the least expiry value.
 * It does nothing if there is no entry.
 */
void ngtcp2_rtb_pop(ngtcp2_rtb *rtb);

/*
 * ngtcp2_rtb_recv_ack removes acked ngtcp2_rtb_entry from |rtb|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_CALLBACK_FAILURE
 *     User callback failed
 */
int ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr,
                        uint8_t unprotected, ngtcp2_conn *conn);

#endif /* NGTCP2_RTB_H */
