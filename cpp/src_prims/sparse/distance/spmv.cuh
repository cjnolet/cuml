/*
 * Copyright (c) 2020, NVIDIA CORPORATION.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <raft/cudart_utils.h>
#include <sparse/utils.h>
#include <common/device_buffer.hpp>
#include <cuml/common/cuml_allocator.hpp>
#include <raft/cuda_utils.cuh>
#include <sparse/csr.cuh>

#include <sparse/selection.cuh>

#include <raft/device_atomics.cuh>

#include <limits.h>

#include <cuml/neighbors/knn.hpp>

#include <nvfunctional>

#include <cusparse_v2.h>
#include <raft/sparse/cusparse_wrappers.h>

#include <cub/block/block_load.cuh>
#include <cub/block/block_radix_sort.cuh>
#include <cub/block/block_store.cuh>

#include <sparse/distance/common.h>

namespace MLCommon {
namespace Sparse {
namespace Distance {

/**
 * Load-balanced sparse-matrix-sparse-matrix multiplication (SPMM) kernel with
 * sparse-matrix-sparse-vector multiplication layout (SPMV).
 * This is intended to be scheduled n_chunks_b times for each row of a.
 * The steps are as follows:
 *
 * 1. Load row from A into dense vector in shared memory.
 *    This can be chunked in the future if necessary.
 * 2. Threads of block all step through chunks of B in parallel.
 *    When a new row is encountered in row_indices_b, a segmented
 *    reduction is performed across the warps and then across the
 *    block and the final value written out to host memory.
 *
 * Reference: https://www.icl.utk.edu/files/publications/2020/icl-utk-1421-2020.pdf
 *
 * @tparam value_idx
 * @tparam value_t
 * @tparam tpb
 * @tparam buffer_size
 * @tparam chunk_size
 * @param indptrA
 * @param indicesA
 * @param dataA
 * @param rowsB
 * @param indicesB
 * @param dataB
 * @param m
 * @param n
 * @param out
 */
template <typename value_idx, typename value_t, int tpb, int buffer_size,
          bool rev, typename kv_t, typename init_f, typename put_f,
          typename get_f, typename reduce_f, typename accum_f, typename write_f>
__global__ void balanced_coo_generalized_spmv_kernel(
  value_idx *indptrA, value_idx *indicesA, value_t *dataA, value_idx *rowsB,
  value_idx *indicesB, value_t *dataB, value_idx m, value_idx n, value_idx dim,
  value_idx nnz_b, value_t *out, int n_blocks_per_row, int chunk_size,
  init_f init_func, put_f put_func, get_f get_func, reduce_f reduce_func,
  accum_f accum_func, write_f write_func) {
  typedef cub::WarpReduce<value_t> warp_reduce;

  value_idx cur_row_a = blockIdx.x / n_blocks_per_row;
  value_idx cur_chunk_offset = blockIdx.x % n_blocks_per_row;

  // chunk starting offset
  value_idx ind_offset = cur_chunk_offset * chunk_size * tpb;

  // how many total cols will be processed by this block (should be <= chunk_size * n_threads)
  value_idx active_chunk_size = min(chunk_size * tpb, nnz_b - ind_offset);

  int tid = threadIdx.x;
  int warp_id = tid / 32;

  // compute id relative to current warp
  unsigned int lane_id = tid & 31;
  value_idx ind = ind_offset + threadIdx.x;

  if (cur_row_a > m || cur_chunk_offset > n_blocks_per_row) return;
  if (ind >= nnz_b) return;

  __shared__ kv_t A[buffer_size];
  __shared__ value_idx offsets_a[2];
  __shared__ typename warp_reduce::TempStorage temp_storage[8];

  if (tid == 0) {
    offsets_a[0] = indptrA[cur_row_a];
    offsets_a[1] = indptrA[cur_row_a + 1];

    // Create dense vector A and populate with 0s
    memset(A, 0, buffer_size * sizeof(kv_t));
  }

  __syncthreads();

  value_idx start_offset_a = offsets_a[0];
  value_idx stop_offset_a = offsets_a[1];

  // Convert current row vector in A to dense
  for (int i = tid; i < (stop_offset_a - start_offset_a); i += blockDim.x) {
    A[indicesA[start_offset_a + i]] = dataA[start_offset_a + i];
  }

  __syncthreads();

  value_idx cur_row_b = -1;
  value_t c = 0.0;

  auto warp_red = warp_reduce(temp_storage[warp_id]);

  if (tid < active_chunk_size) {
    cur_row_b = rowsB[ind];
    value_t a_col = A[indicesB[ind]];
    if (!rev || a_col == 0.0) c = reduce_func(a_col, dataB[ind]);
  }

  // loop through chunks in parallel, reducing when a new row is
  // encountered by each thread
  for (int i = tid; i < active_chunk_size; i += blockDim.x) {
    value_idx ind_next = ind + blockDim.x;
    value_idx next_row_b = -1;

    if (i + blockDim.x < active_chunk_size) next_row_b = rowsB[ind_next];

    if (next_row_b != cur_row_b) {
      unsigned int peer_group = get_peer_group(cur_row_b);
      bool is_leader = get_lowest_peer(peer_group) == lane_id;

      value_t v = warp_red.HeadSegmentedReduce(c, is_leader, accum_func);

      // thread with lowest lane id among peers writes out
      if (is_leader && v != 0.0) {
        value_idx idx =
          !rev ? cur_row_a * n + cur_row_b : cur_row_b * m + cur_row_a;
        write_func(out + idx, v);
      }
      c = 0.0;
    }

    if (next_row_b != -1) {
      ind = ind_next;
      value_t a_col = A[indicesB[ind]];
      if (!rev || a_col == 0.0)
        c = accum_func(c, reduce_func(a_col, dataB[ind]));
      cur_row_b = next_row_b;
    }
  }
}

template <typename value_idx, typename value_t, int tpb = 1024>
inline int balanced_coo_spmv_compute_smem() {
  // compute max shared mem to use
  return raft::getSharedMemPerBlock() - (2 * sizeof(value_idx)) -
         (tpb * sizeof(value_t));
}

/**
 * Performs generalized sparse-matrix-sparse-matrix multiplication via a
 * sparse-matrix-sparse-vector layout. Each vector of A is loaded
 * into shared memory in dense form and the non-zeros of B
 * load balanced across the threads of each block.
 * @tparam value_idx
 * @tparam value_t
 * @tparam max_buffer_size
 * @tparam threads_per_block
 * @tparam reduce_f
 * @tparam accum_f
 * @param out_dists
 * @param config_
 * @param reduce_func
 * @param accum_func
 */
template <typename value_idx, typename value_t, int threads_per_block = 1024,
          int chunk_size = 500000, typename reduce_f, typename accum_f,
          typename write_f>
inline void balanced_coo_pairwise_generalized_spmv(
  value_t *out_dists, const distances_config_t<value_idx, value_t> &config_,
  value_idx *coo_rows_b, reduce_f reduce_func, accum_f accum_func,
  write_f write_func) {
  CUDA_CHECK(cudaMemsetAsync(
    out_dists, 0, config_.a_nrows * config_.b_nrows * sizeof(value_t),
    config_.stream));
  int n_warps_per_row =
    raft::ceildiv(config_.b_nnz, chunk_size * threads_per_block);
  int n_blocks = config_.a_nrows * n_warps_per_row;

  CUML_LOG_DEBUG("n_blocks: %d", n_blocks);
  CUML_LOG_DEBUG("n_warps_per_row: %d", n_warps_per_row);

  // @TODO: Compute this.
  constexpr int smem = 11000;

  balanced_coo_generalized_spmv_kernel<value_idx, value_t, threads_per_block,
                                       smem, false, value_t>
    <<<n_blocks, threads_per_block, 0, config_.stream>>>(
      config_.a_indptr, config_.a_indices, config_.a_data, coo_rows_b,
      config_.b_indices, config_.b_data, config_.a_nrows, config_.b_nrows,
      config_.b_ncols, config_.b_nnz, out_dists, n_warps_per_row, chunk_size,
      [] __device__() { return 0.0; },
      [] __device__(value_t * cache, value_idx k, value_t v) { cache[k] = v; },
      [] __device__(value_t * cache, value_idx k) { return cache[k]; },
      reduce_func, accum_func, write_func);
};

/**
 * Used for computing distances where the reduction (e.g. product()) function performs
 * an implicit union (reduce(x, 0) = x) to capture the difference A-B. This is
 * necessary because the SPMV kernel will only compute the intersection & B-A.
 * @tparam value_idx
 * @tparam value_t
 * @tparam max_buffer_size
 * @tparam threads_per_block
 * @tparam reduce_f
 * @tparam accum_f
 * @param out_dists
 * @param config_
 * @param reduce_func
 * @param accum_func
 */
template <typename value_idx, typename value_t, int threads_per_block = 1024,
          int chunk_size = 500000, typename reduce_f, typename accum_f,
          typename write_f>
inline void balanced_coo_pairwise_generalized_spmv_rev(
  value_t *out_dists, const distances_config_t<value_idx, value_t> &config_,
  value_idx *coo_rows_a, reduce_f reduce_func, accum_f accum_func,
  write_f write_func) {
  int n_warps_per_row =
    raft::ceildiv(config_.a_nnz, chunk_size * threads_per_block);
  int n_blocks = config_.b_nrows * n_warps_per_row;

  CUML_LOG_DEBUG("n_blocks: %d", n_blocks);
  CUML_LOG_DEBUG("n_warps_per_row: %d", n_warps_per_row);

  // @TODO: Compute this.
  constexpr int smem = 11000;

  balanced_coo_generalized_spmv_kernel<value_idx, value_t, threads_per_block,
                                       smem, true, value_t>
    <<<n_blocks, threads_per_block, 0, config_.stream>>>(
      config_.b_indptr, config_.b_indices, config_.b_data, coo_rows_a,
      config_.a_indices, config_.a_data, config_.b_nrows, config_.a_nrows,
      config_.a_ncols, config_.a_nnz, out_dists, n_warps_per_row, chunk_size,
      [] __device__() { return 0.0; },
      [] __device__(value_t * cache, value_idx k, value_t v) { cache[k] = v; },
      [] __device__(value_t * cache, value_idx k) { return cache[k]; },
      reduce_func, accum_func, write_func);
};
}  // namespace Distance
}  // namespace Sparse
};  // namespace MLCommon
