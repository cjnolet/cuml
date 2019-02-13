/*
 * Copyright (c) 2019, NVIDIA CORPORATION.
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

#include "knn/knn.h"
#include "umap/umap.h"

#include "cuda_utils.h"

#include "stats/mean.h"
#include "sparse/coo.h"

#include <cuda_runtime.h>

#include <cusparse_v2.h>


#include <stdio.h>
#include <string>

namespace UMAP {
    namespace FuzzySimplSet {
        namespace Naive {

            using namespace ML;

            static const float MAX_FLOAT = std::numeric_limits<float>::max();


            static const float SMOOTH_K_TOLERANCE = 1e-5;
            static const float MIN_K_DIST_SCALE = 1e-3;

            /**
             * Computes a continuous version of the distance to the kth nearest neighbor.
             * That is, this is similar to knn-distance but allows continuous k values
             * rather than requiring an integral k. In essence, we are simply computing
             * the distance such that the cardinality of fuzzy set we generate is k.
             *
             * TODO: Optimize for coalesced reads
             *
             * @param knn_dists: Distances to nearest neighbors for each sample. Each row should
             * 					 be a sorted list of distances to a given sample's nearest neighbors.
             *
             * @param n: The number of samples
             * @param k: The number of neighbors
             *
             * @param local_connectivity: The local connectivity required -- i.e. the number of nearest
             * 							  neighbors that should be assumed to be connected at a local
             * 							  level. The higher this value the more connecte the manifold
             * 							  becomes locally. In practice, this should not be more than the
             * 							  local intrinsic dimension of the manifold.
             *
             * @param sigmas: An array of size n representing the distance to the kth nearest neighbor,
             * 				  as suitably approximated.
             * @parasm rhos:  An array of size n representing the distance to the 1st nearest neighbor
             * 				  for each point.
             *
             * Descriptions adapted from: https://github.com/lmcinnes/umap/blob/master/umap/umap_.py
             *
             */
            template<int TPB_X, typename T>
            __global__ void smooth_knn_dist(const T *knn_dists, int n,
                    float mean_dist, T *sigmas,
                    T *rhos,			// Size of n, iniitalized to zeros
                    int n_neighbors, float local_connectivity, int n_iter = 64,
                    float bandwidth = 1.0) {

                float target = __log2f(n_neighbors) * bandwidth;

                // row-based matrix 1 thread per row
                int row = (blockIdx.x * TPB_X) + threadIdx.x;
                int i = row * n_neighbors; // each thread processes one row of the dist matrix

                if (row < n) {
                    float lo = 0.0;
                    float hi = MAX_FLOAT;
                    float mid = 1.0;

                    float *ith_distances = new float[n_neighbors];
                    float *non_zero_dists = new float[n_neighbors];

                    int total_nonzero = 0;
                    int max_nonzero = -1;
                    float sum = 0;

                    for (int idx = 0; idx < n_neighbors; idx++) {
                        ith_distances[idx] = knn_dists[i + idx];

                        sum += ith_distances[idx];

                        if (ith_distances[idx] != 0.0) {
                            non_zero_dists[total_nonzero] = ith_distances[idx];
                            ++total_nonzero;
                        }

                        if (ith_distances[idx] > max_nonzero)
                            max_nonzero = ith_distances[idx];
                    }

                    float ith_distances_mean = sum / n_neighbors;

                    if (total_nonzero > local_connectivity) {
                        int index = int(local_connectivity);
                        float interpolation = local_connectivity - index;

                        if (index > 0) {
                            rhos[i] = non_zero_dists[index - 1];
                            if (interpolation > SMOOTH_K_TOLERANCE)
                                rhos[i] += interpolation
                                        * (non_zero_dists[index]
                                                - non_zero_dists[index - 1]);
                            else
                                rhos[i] = interpolation * non_zero_dists[0];

                        } else if (total_nonzero > 0)
                            rhos[i] = max_nonzero;
                    }

                    for (int iter = 0; iter < n_iter; iter++) {
                        float psum = 0.0;
                        for (int j = 0; j < n_neighbors; j++) {
                            float d = knn_dists[i + j] - rhos[i];
                            if (d > 0)
                                psum += exp(-(d / mid));
                            else
                                psum += 1.0;
                        }

                        if (fabsf(psum - target) < SMOOTH_K_TOLERANCE)
                            break;

                        if (psum > target) {
                            hi = mid;
                            mid = (lo + hi) / 2.0;
                        } else {
                            lo = mid;
                            if (hi == MAX_FLOAT)
                                mid *= 2;
                            else
                                mid = (lo + hi) / 2.0;
                        }
                    }

                    sigmas[i] = mid;

                    if (rhos[i] > 0.0) {
                        if (sigmas[i] < MIN_K_DIST_SCALE * ith_distances_mean)
                            sigmas[i] = MIN_K_DIST_SCALE * ith_distances_mean;
                    } else {
                        if (sigmas[i] < MIN_K_DIST_SCALE * mean_dist)
                            sigmas[i] = MIN_K_DIST_SCALE * mean_dist;
                    }

                }

            }

            /**
             * Construct the membership strength data for the 1-skeleton of each local
             * fuzzy simplicial set -- this is formed as a sparse matrix (COO) where each
             * row is a local fuzzy simplicial set, with a membership strength for the
             * 1-simplex to each other data point.
             *
             * TODO: Optimize for coalesced reads.
             *
             * @param knn_indices: the knn index matrix of size (n, k)
             * @param knn_dists: the knn distance matrix of size (n, k)
             * @param sigmas: array of size n representing distance to kth nearest neighbor
             * @param rhos: array of size n representing distance to the first nearest neighbor
             *
             * @return rows: long array of size n
             * 		   cols: long array of size k
             * 		   vals: T array of size n*k
             *
             * Descriptions adapted from: https://github.com/lmcinnes/umap/blob/master/umap/umap_.py
             */
            template<int TPB_X, typename T>
            __global__ void compute_membership_strength(const long *knn_indices,
                    const float *knn_dists,  // nn outputs
                    const T *sigmas, const T *rhos, // continuous dists to nearest neighbors
                    T *vals, int *rows, int *cols,  // result coo
                    int n, int n_neighbors) {	 // model params

                // row-based matrix is best
                int row = (blockIdx.x * TPB_X) + threadIdx.x;
                int i = row * n_neighbors; //	one row per thread

                if (row < n) {

                    T cur_rho = rhos[i];
                    T cur_sigma = sigmas[i];

                    for (int j = 0; j < n_neighbors; j++) {

                        int idx = i + j;

                        long cur_knn_ind = knn_indices[idx];
                        T cur_knn_dist = knn_dists[idx];

                        T val = 0.0;
                        if (cur_knn_ind == -1)
                            continue;

                        if (cur_knn_ind == i)
                            val = 0.0;
                        else if (cur_knn_dist - cur_rho <= 0.0)
                            val = 1.0;
                        else
                            val = exp(
                                    -((cur_knn_dist - cur_rho) / (cur_sigma)));

                        rows[idx] = i;
                        cols[idx] = cur_knn_ind;
                        vals[idx] = val;
                    }
                }
            }

            template<int TPB_X, typename T>
            __global__ void compute_result(int *rows, int *cols, T *vals,
                    int *orows, int *ocols, T *ovals, int *rnnz, int n,
                    int n_neighbors, float set_op_mix_ratio) {

                int row = (blockIdx.x * TPB_X) + threadIdx.x;
                int i = row * n_neighbors; // each thread processes one row
                // Grab the n_neighbors from our transposed matrix,

                if (row < n) {

                    int nnz = 0;
                    for (int j = 0; j < n_neighbors; j++) {

                        int idx = i + j;
                        int out_idx = i * 2;

                        int row_lookup = cols[idx];
                        int t_start = row_lookup * n_neighbors; // Start at

                        T transpose = 0.0;
                        bool found_match = false;
                        for (int t_idx = 0; t_idx < n_neighbors; t_idx++) {

                            int f_idx = t_idx + t_start;
                            // If we find a match, let's get out of the loop
                            if (cols[f_idx] == rows[idx]
                                    && rows[f_idx] == cols[idx]
                                    && vals[f_idx] != 0.0) {
                                transpose = vals[f_idx];
                                found_match = true;
                                break;
                            }
                        }

                        // if we didn't find an exact match, we still need to add
                        // the transposed value into our current matrix.
                        if (!found_match && vals[idx] != 0.0) {
                            orows[out_idx + nnz] = cols[idx];
                            ocols[out_idx + nnz] = rows[idx];
                            ovals[out_idx + nnz] = vals[idx];
                            ++nnz;
                        }

                        T result = vals[idx];
                        T prod_matrix = result * transpose;

                        T res = set_op_mix_ratio
                                * (result - transpose - prod_matrix)
                                + (1.0 - set_op_mix_ratio) + prod_matrix;

                        if (res != 0.0) {
                            orows[out_idx + nnz] = rows[idx];
                            ocols[out_idx + nnz] = cols[idx];
                            ovals[out_idx + nnz] = res;
                            ++nnz;
                        }
                    }
                    rnnz[row] = nnz;
                    atomicAdd(rnnz + n, nnz);

                }
            }


            void print(std::string msg) {
                std::cout << msg << std::endl;
            }

            /**
             * Given a set of X, a neighborhood size, and a measure of distance, compute
             * the fuzzy simplicial set (here represented as a fuzzy graph in the form of
             * a sparse coo matrix) associated to the data. This is done by locally
             * approximating geodesic (manifold surface) distance at each point, creating
             * a fuzzy simplicial set for each such point, and then combining all the local
             * fuzzy simplicial sets into a global one via a fuzzy union.
             */
            template<int TPB_X, typename T>
            void launcher(const long *knn_indices, const float *knn_dists,
                    int n, int *rows, int *cols, T *vals, UMAPParams *params) {

                /**
                 * All of the kernels in this algorithm are row-based and
                 * upper-bounded by k. Prefer 1-row per thread, scheduled
                 * as a single dimension.
                 */
                dim3 grid(MLCommon::ceildiv(n, TPB_X), 1, 1);
                dim3 blk(TPB_X, 1, 1);

                /**
                 * Calculate mean distance through a parallel reduction
                 */

                T *dist_means_dev;
                MLCommon::allocate(dist_means_dev, params->n_neighbors);

                MLCommon::Stats::mean(dist_means_dev, knn_dists,
                        params->n_neighbors, n, false, false);

                CUDA_CHECK(cudaDeviceSynchronize());
                CUDA_CHECK(cudaPeekAtLastError());

                T *dist_means_host = (T*) malloc(params->n_neighbors * sizeof(T));
                MLCommon::updateHost(dist_means_host, dist_means_dev,params->n_neighbors);

                float sum = 0.0;
                for (int i = 0; i < params->n_neighbors; i++)
                    sum += dist_means_host[i];

                float mean_dist = sum / params->n_neighbors;

                /**
                 * Clean up memory for subsequent algorithms
                 */
                delete dist_means_host;
                CUDA_CHECK(cudaFree(dist_means_dev));

                print("Got past mean");

                T *sigmas;
                T *rhos;

                MLCommon::allocate(sigmas, n);
                MLCommon::allocate(rhos, n);

                /**
                 * Smooth kNN distances to be continuous
                 */
                smooth_knn_dist<TPB_X><<<grid, blk>>>(knn_dists, n, mean_dist, sigmas,
                        rhos, params->n_neighbors, params->local_connectivity);

                CUDA_CHECK(cudaDeviceSynchronize());
                CUDA_CHECK(cudaPeekAtLastError());

                print("Got past smooth_knn_dist");

                T* sigmas_h = (T*) malloc(n * sizeof(T));
                T* rhos_h = (T*) malloc(n * sizeof(T));
                MLCommon::updateHost(sigmas_h, sigmas, n);
                MLCommon::updateHost(rhos_h, rhos, n);

                int k = params->n_neighbors;

                /**
                 * Compute graph of membership strengths
                 */
                compute_membership_strength<TPB_X><<<grid, blk>>>(knn_indices,
                        knn_dists, sigmas, rhos, vals, rows, cols, n,
                        params->n_neighbors);

                CUDA_CHECK(cudaDeviceSynchronize());
                CUDA_CHECK(cudaPeekAtLastError());

                print("Got past compute membership strength");

                int *orows, *ocols, *rnnz;
                T *ovals;
                MLCommon::allocate(orows, n * k * 2, true);
                MLCommon::allocate(ocols, n * k * 2, true);
                MLCommon::allocate(ovals, n * k * 2, true);
                MLCommon::allocate(rnnz, n + 1, true);

                /**
                 * Weight directed graph of membership strengths (and include
                 * both sides).
                 */
                compute_result<TPB_X><<<grid, blk>>>(rows, cols, vals, orows, ocols,
                        ovals, rnnz, n, params->n_neighbors,
                        params->set_op_mix_ratio);

                CUDA_CHECK(cudaDeviceSynchronize());
                CUDA_CHECK(cudaPeekAtLastError());

                print("Got past compute result");

                int cur_coo_len = 0;
                MLCommon::updateHost(&cur_coo_len, rnnz + n, 1);

                /**
                 * Remove resulting zeros from COO
                 */
                int *crows, *ccols;
                T *cvals;
                MLCommon::allocate(crows, cur_coo_len, true);
                MLCommon::allocate(ccols, cur_coo_len, true);
                MLCommon::allocate(cvals, cur_coo_len, true);

                MLCommon::coo_remove_zeros<TPB_X, T>(n*k*2,
                        orows, ocols, ovals,
                        crows, ccols, cvals,
                        rnnz, n);

                print("Got past remove zeros");

                std::cout << "cur_coo_len=" << cur_coo_len << std::endl;

                MLCommon::coo_sort(n, k, cur_coo_len, crows, ccols, cvals);

                std::cout << MLCommon::arr2Str(crows, cur_coo_len, "rows") << std::endl;
                std::cout << MLCommon::arr2Str(ccols, cur_coo_len, "cols") << std::endl;
                std::cout << MLCommon::arr2Str(cvals, cur_coo_len, "vals") << std::endl;
            }
        }
    }
}
;
