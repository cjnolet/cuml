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

#include <raft/device_atomics.cuh>

namespace MLCommon {
namespace Sparse {
namespace Distance {

struct Sum {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t a, value_t b) {
    return a + b;
  }
};

struct SqDiff {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t a, value_t b) {
    return (a - b) * (a - b);
  }
};

struct PDiff {
  float p;

  PDiff(float p_) : p(p_) {}

  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t a, value_t b) {
    return powf(a - b, p);
  }
};

struct Max {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t a, value_t b) {
    return fmaxf(a, b);
  }
};

struct AtomicAdd {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t *a,
                                                         value_t b) {
    return atomicAdd(a, b);
  }
};

struct AtomicMax {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t *a,
                                                         value_t b) {
    return atomicMax(a, b);
  }
};

struct Product {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t a, value_t b) {
    return a * b;
  }
};

struct AbsDiff {
  template <typename value_t>
  __host__ __device__ __forceinline__ value_t operator()(value_t a, value_t b) {
    return fabsf(a - b);
  }
};
}  // namespace Distance
}  // namespace Sparse
};  // namespace MLCommon