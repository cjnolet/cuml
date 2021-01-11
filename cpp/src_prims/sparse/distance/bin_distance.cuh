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

#include <limits.h>
#include <raft/cudart_utils.h>
#include <sparse/distance/common.h>

#include <raft/cudart_utils.h>
#include <raft/linalg/distance_type.h>
#include <raft/sparse/cusparse_wrappers.h>
#include <raft/cuda_utils.cuh>

#include <common/device_buffer.hpp>

#include <sparse/utils.h>
#include <sparse/csr.cuh>

#include <sparse/distance/common.h>
#include <sparse/distance/ip_distance.cuh>

#include <cuml/common/cuml_allocator.hpp>
#include <cuml/neighbors/knn.hpp>

#include <nvfunctional>

#include <cusparse_v2.h>

namespace MLCommon {
namespace Sparse {
namespace Distance {

// @TODO: Move this into sparse prims (coo_norm)
template <typename value_idx, typename value_t>
__global__ void compute_binary_row_norm_kernel(value_t *out,
                                               const value_idx *coo_rows,
                                               const value_t *data,
                                               value_idx nnz) {
  value_idx i = blockDim.x * blockIdx.x + threadIdx.x;
  if (i < nnz) {
    atomicAdd(&out[coo_rows[i]], data[i] > 0.0);
  }
}

template <typename value_idx, typename value_t>
__global__ void compute_jaccard_warp_kernel(value_t *C, const value_t *Q_norms,
                                            const value_t *R_norms,
                                            value_idx n_rows,
                                            value_idx n_cols) {
  value_idx tid = blockDim.x * blockIdx.x + threadIdx.x;
  value_idx i = tid / n_cols;
  value_idx j = tid % n_cols;

  if (i >= n_rows || j >= n_cols) return;

  value_t q_r_union = Q_norms[i] + R_norms[j];
  value_t dot = C[i * n_cols + j];

  value_t val = 1 - (dot / (q_r_union - dot));

  C[i * n_cols + j] = val;
}

template <typename value_idx, typename value_t, int tpb = 1024>
void compute_jaccard(value_t *C, const value_t *Q_norms, const value_t *R_norms,
                     value_idx n_rows, value_idx n_cols, cudaStream_t stream) {
  int blocks = raft::ceildiv(n_rows * n_cols, tpb);
  compute_jaccard_warp_kernel<<<blocks, tpb, 0, stream>>>(C, Q_norms, R_norms,
                                                          n_rows, n_cols);
}

template <typename value_idx, typename value_t, int tpb = 1024>
void compute_jaccard_distance(value_t *out, const value_idx *Q_coo_rows,
                              const value_t *Q_data, value_idx Q_nnz,
                              const value_idx *R_coo_rows,
                              const value_t *R_data, value_idx R_nnz,
                              value_idx m, value_idx n, cusparseHandle_t handle,
                              std::shared_ptr<deviceAllocator> alloc,
                              cudaStream_t stream) {
  device_buffer<value_t> Q_norms(alloc, stream, m);
  device_buffer<value_t> R_norms(alloc, stream, n);
  CUDA_CHECK(
    cudaMemsetAsync(Q_norms.data(), 0, Q_norms.size() * sizeof(value_t)));
  CUDA_CHECK(
    cudaMemsetAsync(R_norms.data(), 0, R_norms.size() * sizeof(value_t)));

  compute_binary_row_norm_kernel<<<raft::ceildiv(Q_nnz, tpb), tpb, 0, stream>>>(
    Q_norms.data(), Q_coo_rows, Q_data, Q_nnz);
  compute_binary_row_norm_kernel<<<raft::ceildiv(R_nnz, tpb), tpb, 0, stream>>>(
    R_norms.data(), R_coo_rows, R_data, R_nnz);

  compute_jaccard(out, Q_norms.data(), R_norms.data(), m, n, stream);
}

/**
 * L2 distance using the expanded form: sum(x_k)^2 + sum(y_k)^2 - 2 * sum(x_k * y_k)
 * The expanded form is more efficient for sparse data.
 */
template <typename value_idx = int, typename value_t = float>
class jaccard_expanded_distances_t : public distances_t<value_t> {
 public:
  explicit jaccard_expanded_distances_t(
    const distances_config_t<value_idx, value_t> &config)
    : config_(config),
      workspace(config.allocator, config.stream, 0),
      ip_dists(config) {}

  void compute(value_t *out_dists) {
    CUML_LOG_DEBUG("Computing inner products");
    ip_dists.compute(out_dists);

    value_idx *b_indices = ip_dists.trans_indices();
    value_t *b_data = ip_dists.trans_data();

    CUML_LOG_DEBUG("Computing COO row index array");
    device_buffer<value_idx> search_coo_rows(config_.allocator, config_.stream,
                                             config_.a_nnz);
    csr_to_coo(config_.a_indptr, config_.a_nrows, search_coo_rows.data(),
               config_.a_nnz, config_.stream);

    CUML_LOG_DEBUG("Done.");

    CUML_LOG_DEBUG("Computing Jaccard");
    compute_jaccard_distance(out_dists, search_coo_rows.data(), config_.a_data,
                             config_.a_nnz, b_indices, b_data, config_.b_nnz,
                             config_.a_nrows, config_.b_nrows, config_.handle,
                             config_.allocator, config_.stream);
    CUML_LOG_DEBUG("Done.");
  }

  ~jaccard_expanded_distances_t() = default;

 private:
  distances_config_t<value_idx, value_t> config_;
  device_buffer<char> workspace;
  ip_distances_t<value_idx, value_t> ip_dists;
};
};  // END namespace Distance
};  // END namespace Sparse
};  // END namespace MLCommon