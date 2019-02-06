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

#include "naive.h"

namespace UMAP {

namespace FuzzySimplSet {

	template<typename T>
	void run(const T *X, int n,
			 const long *knn_indices, const T *knn_dists,
			 T *sigmas, T *rhos,
			 UMAPParams *params,
			 int algorithm = 0) {

		switch(algorithm) {
		case 0:
			Naive::launcher(knn_indices, knn_dists, n,
					       sigmas, rhos,
					       params);
			break;
		}
	}
}
};
