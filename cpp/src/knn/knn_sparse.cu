/*
 * Copyright (c) 2019-2020, NVIDIA CORPORATION.
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

#include <common/cumlHandle.hpp>

#include <cuml/common/logger.hpp>
#include <cuml/neighbors/knn_sparse.hpp>

#include <sparse/knn.cuh>

#include <cusparse_v2.h>

namespace ML {
namespace Sparse {

void brute_force_knn(cumlHandle &handle, const int *idxIndptr,
                     const int *idxIndices, const float *idxData, size_t idxNNZ,
                     size_t n_idx_rows, size_t n_idx_cols,
                     const int *queryIndptr, const int *queryIndices,
                     const float *queryData, size_t queryNNZ,
                     size_t n_query_rows, size_t n_query_cols,
                     int *output_indices, float *output_dists, int k,
                     size_t batch_size,  // approx 1M
                     ML::MetricType metric, float metricArg,
                     bool expanded_form) {
  std::shared_ptr<deviceAllocator> d_alloc = handle.getDeviceAllocator();
  cusparseHandle_t cusparse_handle = handle.getImpl().getcusparseHandle();
  cudaStream_t stream = handle.getStream();

  MLCommon::Sparse::Selection::brute_force_knn(
    idxIndptr, idxIndices, idxData, idxNNZ, n_idx_rows, n_idx_cols, queryIndptr,
    queryIndices, queryData, queryNNZ, n_query_rows, n_query_cols,
    output_indices, output_dists, k, cusparse_handle, d_alloc, stream,
    batch_size, metric, metricArg, expanded_form);
}
};  // namespace Sparse
};  // namespace ML
