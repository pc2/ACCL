/*******************************************************************************
#  Copyright (C) 2021 Xilinx, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
# *******************************************************************************/
#include "eth_intf.h"

struct tcp_receive_context {
  ap_uint<DATA_WIDTH> partial;
  ap_uint<7> partial_bytes;
  unsigned remaining;
  ap_uint<DEST_WIDTH> target;
};

using tcp_byte_count = ap_uint<7>;
using tcp_buffer_count = ap_uint<6>;

static ap_uint<DATA_WIDTH / 8> tcp_byte_keep(tcp_byte_count bytes) {
#pragma HLS INLINE
  ap_uint<DATA_WIDTH / 8> keep = 0;
  for (unsigned byte = 0; byte < DATA_WIDTH / 8; ++byte) {
#pragma HLS UNROLL
    keep[byte] = byte < bytes;
  }
  return keep;
}

static ap_uint<DATA_WIDTH> tcp_byte_mask(tcp_byte_count bytes) {
#pragma HLS INLINE
  ap_uint<DATA_WIDTH> mask = 0;
  for (unsigned byte = 0; byte < DATA_WIDTH / 8; ++byte) {
#pragma HLS UNROLL
    mask.range(byte * 8 + 7, byte * 8) = byte < bytes ? 255 : 0;
  }
  return mask;
}

static ap_uint<DATA_WIDTH> tcp_take_bytes(STREAM<stream_word> &input,
                                          ap_uint<2 * DATA_WIDTH> &buffer,
                                          tcp_buffer_count &buffered,
                                          unsigned &available,
                                          tcp_byte_count bytes) {
#pragma HLS INLINE
  const unsigned word_bytes = DATA_WIDTH / 8;
  if (buffered < bytes) {
    stream_word word = STREAM_READ(input);
    buffer |= ap_uint<2 * DATA_WIDTH>(word.data) << (buffered * 8);
  }
  ap_uint<DATA_WIDTH> result = buffer;
  if (bytes < word_bytes) {
    result &= tcp_byte_mask(bytes);
  }
  buffer >>= bytes * 8;
  // Availability limits valid data, the buffer count wraps modulo 64 bytes.
  buffered -= bytes;
  available -= bytes;
  return result;
}

static void tcp_emit_payload(STREAM<stream_word> &output,
                             tcp_receive_context &context,
                             ap_uint<DATA_WIDTH> data, tcp_byte_count bytes,
                             bool last_fragment_word) {
#pragma HLS INLINE
  const unsigned word_bytes = DATA_WIDTH / 8;
  context.remaining -= bytes;
  stream_word word;
  word.dest = context.target;
  if (context.target == 0) {
    word.data = data;
    word.keep = tcp_byte_keep(bytes);
    word.strb = word.keep;
    word.last = last_fragment_word;
    STREAM_WRITE(output, word);
  } else {
    ap_uint<2 * DATA_WIDTH> combined = context.partial;
    combined |= ap_uint<2 * DATA_WIDTH>(data) << (context.partial_bytes * 8);
    unsigned total = context.partial_bytes + bytes;
    if (total >= word_bytes) {
      word.data = combined;
      word.keep = -1;
      word.strb = word.keep;
      word.last = context.remaining == 0 && total == word_bytes;
      STREAM_WRITE(output, word);
      context.partial = combined >> DATA_WIDTH;
      context.partial_bytes = total - word_bytes;
    } else {
      context.partial = combined;
      context.partial_bytes = total;
    }
  }
}

void tcp_depacketizer(STREAM<stream_word> &in, STREAM<stream_word> &out,
                      STREAM<eth_header> &sts,
                      STREAM<eth_notification> &notif_in,
                      STREAM<eth_notification> &notif_out) {
#pragma HLS INTERFACE axis register both port = in
#pragma HLS INTERFACE axis register both port = out
#pragma HLS INTERFACE axis register both port = sts
#pragma HLS INTERFACE axis register both port = notif_in
#pragma HLS INTERFACE axis register both port = notif_out
#pragma HLS INTERFACE s_axilite port = return

  const unsigned word_bytes = DATA_WIDTH / 8;
  const unsigned max_dma_bytes =
      ((8 * 1024 * 1024 - 1) / word_bytes) * word_bytes;
  static tcp_receive_context contexts[1024] = {};
  if (STREAM_IS_EMPTY(notif_in)) {
    return;
  }
  eth_notification notification = STREAM_READ(notif_in);
  if (notification.length == 0) {
    return;
  }
  unsigned available = notification.length;
  tcp_receive_context context = contexts[notification.session_id];
  ap_uint<2 * DATA_WIDTH> buffer = 0;
  tcp_buffer_count buffered = 0;
  while (available != 0) {
    if (context.remaining == 0) {
      unsigned bytes = word_bytes - context.partial_bytes;
      if (bytes > available) {
        bytes = available;
      }
      auto data = tcp_take_bytes(in, buffer, buffered, available, bytes);
      context.partial |= data << (context.partial_bytes * 8);
      context.partial_bytes += bytes;
      if (context.partial_bytes != word_bytes) {
        break;
      }
      eth_header header(context.partial.range(HEADER_LENGTH - 1, 0));
      context.remaining = header.count;
      context.target = header.strm;
      context.partial = 0;
      context.partial_bytes = 0;
      if (context.remaining != 0 && context.target == 0) {
        eth_notification notice;
        notice.session_id = notification.session_id;
        notice.type = 0;
        notice.length = context.remaining;
        STREAM_WRITE(sts, header);
        STREAM_WRITE(notif_out, notice);
      }
      if (context.remaining == 0 || available == 0) {
        continue;
      }
    }

    unsigned fragment_bytes = context.remaining;
    if (fragment_bytes > available) {
      fragment_bytes = available;
    }
    if (fragment_bytes > max_dma_bytes) {
      fragment_bytes = max_dma_bytes;
    }
    eth_notification notice;
    notice.session_id = notification.session_id;
    notice.length = fragment_bytes;
    if (context.target == 0) {
      notice.type = 1;
      STREAM_WRITE(notif_out, notice);
    }
    ap_uint<17> full_words = fragment_bytes / word_bytes;
    tcp_byte_count tail_bytes = fragment_bytes % word_bytes;
    for (ap_uint<17> index = 0; index < full_words; ++index) {
#pragma HLS PIPELINE II = 1
      tcp_buffer_count word_buffered = buffered;
      auto data =
          tcp_take_bytes(in, buffer, word_buffered, available, word_bytes);
      tcp_emit_payload(out, context, data, word_bytes,
                       index + 1 == full_words && tail_bytes == 0);
    }
    if (tail_bytes != 0) {
      auto data = tcp_take_bytes(in, buffer, buffered, available, tail_bytes);
      tcp_emit_payload(out, context, data, tail_bytes, true);
    }
    if (context.target != 0 && context.remaining == 0 &&
        context.partial_bytes != 0) {
      stream_word word;
      word.dest = context.target;
      word.data = context.partial;
      word.keep = tcp_byte_keep(context.partial_bytes);
      word.strb = word.keep;
      word.last = 1;
      STREAM_WRITE(out, word);
      context.partial = 0;
      context.partial_bytes = 0;
    }
    if (context.target == 0) {
      notice.type = 2;
      STREAM_WRITE(notif_out, notice);
    }
  }
  contexts[notification.session_id] = context;
}
