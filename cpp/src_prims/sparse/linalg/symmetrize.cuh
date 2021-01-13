/*
 * Copyright (c) 2018-2020, NVIDIA CORPORATION.
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

#include <cuml/common/logger.hpp>

#include <cuml/cuml_api.h>
#include <raft/cudart_utils.h>
#include <common/allocatorAdapter.hpp>
#include <raft/cuda_utils.cuh>

#include <common/cumlHandle.hpp>
#include <cuml/neighbors/knn.hpp>

#include <distance/distance.cuh>

#include <cuml/cluster/linkage.hpp>

#include <raft/linalg/distance_type.h>
#include <raft/mr/device/buffer.hpp>
#include <raft/sparse/mst/mst.cuh>

#include <thrust/device_ptr.h>
#include <thrust/execution_policy.h>
#include <thrust/scan.h>
#include <thrust/sort.h>

namespace raft {
namespace sparse {
namespace linalg {

template <typename value_idx>
__global__ void compute_duplicates_diffs(const value_idx *rows,
                                         const value_idx *cols, value_idx *diff,
                                         size_t nnz) {
  size_t tid = blockDim.x * blockIdx.x + threadIdx.x;
  if (tid >= nnz) return;

  value_idx d = 1;
  if (tid == 0 || (rows[tid - 1] == rows[tid] && cols[tid - 1] == cols[tid]))
    d = 0;
  diff[tid] = d;
}

template <typename value_idx, typename value_t>
__global__ void reduce_duplicates_kernel(
  const value_idx *src_rows, const value_idx *src_cols, const value_t *src_vals,
  const value_idx *index, value_idx *out_rows, value_idx *out_cols,
  value_t *out_vals, size_t nnz) {
  size_t tid = blockDim.x * blockIdx.x + threadIdx.x;

  if (tid < nnz) {
    value_idx idx = index[tid];
    atomicMax(&out_vals[idx], src_vals[tid]);
    out_rows[idx] = src_rows[tid];
    out_cols[idx] = src_cols[tid];
  }
}

/**
 * Symmetrizes a COO matrix
 */
template <typename value_idx, typename value_t>
void symmetrize(const raft::handle_t &handle, const value_idx *rows,
                const value_idx *cols, const value_t *vals, size_t m, size_t n,
                size_t nnz, MLCommon::Sparse::COO<value_t, value_idx> &out) {
  auto d_alloc = handle.get_device_allocator();
  auto stream = handle.get_stream();

  // copy rows to cols and cols to rows
  raft::mr::device::buffer<value_idx> symm_rows(d_alloc, stream, nnz * 2);
  raft::mr::device::buffer<value_idx> symm_cols(d_alloc, stream, nnz * 2);
  raft::mr::device::buffer<value_t> symm_vals(d_alloc, stream, nnz * 2);

  raft::copy_async(symm_rows.data(), rows, nnz, stream);
  raft::copy_async(symm_rows.data() + nnz, cols, nnz, stream);
  raft::copy_async(symm_cols.data(), cols, nnz, stream);
  raft::copy_async(symm_cols.data() + nnz, rows, nnz, stream);

  raft::copy_async(symm_vals.data(), vals, nnz, stream);
  raft::copy_async(symm_vals.data() + nnz, vals, nnz, stream);

  // sort COO
  MLCommon::Sparse::coo_sort(m, n, nnz * 2, symm_rows.data(), symm_cols.data(),
                             symm_vals.data(), d_alloc, stream);

  CUDA_CHECK(cudaStreamSynchronize(stream));
  CUDA_CHECK(cudaGetLastError());

  // compute diffs & take exclusive scan
  raft::mr::device::buffer<value_idx> diff(d_alloc, stream, (nnz * 2) + 1);

  CUDA_CHECK(cudaMemsetAsync(diff.data(), 0,
                             ((nnz * 2) + 1) * sizeof(value_idx), stream));

  compute_duplicates_diffs<<<raft::ceildiv(nnz * 2, (size_t)1024), 1024, 0,
                             stream>>>(symm_rows.data(), symm_cols.data(),
                                       diff.data(), nnz * 2);

  CUDA_CHECK(cudaStreamSynchronize(stream));
  CUDA_CHECK(cudaGetLastError());

  thrust::device_ptr<value_idx> dev = thrust::device_pointer_cast(diff.data());

  ML::thrustAllocatorAdapter alloc(d_alloc, stream);
  thrust::exclusive_scan(thrust::cuda::par(alloc).on(stream), dev,
                         dev + diff.size(), dev);

  CUDA_CHECK(cudaStreamSynchronize(stream));
  CUDA_CHECK(cudaGetLastError());

  // compute final size
  value_idx size = 0;
  raft::update_host(&size, diff.data() + (diff.size() - 1), 1, stream);
  CUDA_CHECK(cudaStreamSynchronize(stream));

  size++;

  out.allocate(size, m, n, true, stream);

  // perform reduce
  reduce_duplicates_kernel<<<raft::ceildiv(nnz * 2, (size_t)1024), 1024, 0,
                             stream>>>(
    symm_rows.data(), symm_cols.data(), symm_vals.data(), diff.data() + 1,
    out.rows(), out.cols(), out.vals(), nnz * 2);
}

};  // end namespace linalg
};  // end namespace sparse
};  // end namespace raft
