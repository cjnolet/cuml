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
#include <vector>
#include <gtest/gtest.h>
#include <cuda_utils.h>
#include <test_utils.h>
#include <iostream>

namespace ML {

using namespace MLCommon;


/**
 *
 * NOTE: Not exhaustively testing the kNN implementation since
 * we are using FAISS for this. Just testing API to verify the
 * knn.cu class is accepting inputs and providing outputs as
 * expected.
 */
template<typename T>
class KNNTest: public ::testing::Test {
protected:
	void basicTest() {

		// Allocate input
        allocate(d_train_inputs, n * d);

        // Allocate reference arrays
        allocate<long>(d_ref_I, n*n);
        allocate(d_ref_D, n*n);

        // Allocate predicted arrays
        allocate<long>(d_pred_I, n*n);
        allocate(d_pred_D, n*n);

        // make testdata on host
        h_train_inputs.resize(n);
        updateDevice(d_train_inputs, h_train_inputs.data(), n*d, 0);

        h_res_D.resize(n*n);
        updateDevice(d_ref_D, h_res_D.data(), n*n, 0);

        h_res_I.resize(n*n);
        updateDevice<long>(d_ref_I, h_res_I.data(), n*n, 0);

    }

 	void SetUp() override {
		basicTest();
	}

	void TearDown() override {
		CUDA_CHECK(cudaFree(d_train_inputs));
		CUDA_CHECK(cudaFree(d_pred_I));
		CUDA_CHECK(cudaFree(d_pred_D));
		CUDA_CHECK(cudaFree(d_ref_I));
		CUDA_CHECK(cudaFree(d_ref_D));
	}

protected:

	T* d_train_inputs;

	int n = 3;
	int d = 1;

    std::vector<long> h_res_I = { 0, 1, 2, 1, 2, 0, 2, 1, 0 };
	std::vector<T> h_res_D = { 0.0, 2401.0,
	        2500.0, 0.0, 1.0, 2401.0, 0.0, 1.0, 2500.0 };
    std::vector<T> h_train_inputs = {1.0, 50.0, 51.0};


    long *d_pred_I;
    T* d_pred_D;

    long *d_ref_I;
    T* d_ref_D;

    kNN *knn = new kNN(d);

    kNNParams params[1];
};


typedef KNNTest<float> KNNTestF;
TEST_F(KNNTestF, Fit) {

    params[0] = { d_train_inputs, n };

    knn->fit(params, 1);
    knn->search(d_train_inputs, n, d_pred_I, d_pred_D, n);

	ASSERT_TRUE(
			devArrMatch(d_ref_D, d_pred_D, n*n, Compare<float>()));
	ASSERT_TRUE(
			devArrMatch(d_ref_I, d_pred_I, n*n, Compare<long>()));
}

typedef KNNTest<float> KNNTestFailsWithHostMemory;
TEST_F(KNNTestFailsWithHostMemory, Fit) {

    /*
     * Assert fitting with host memory fails
     */
    params[0] = { h_train_inputs.data(), n };
    bool caught = false;
    try {
        knn->fit(params, 1);
    } catch(const std::runtime_error &e) {
        caught = true;
    }
    ASSERT_TRUE(caught);


    /**
     * Assert searching with host memory search array fails
     */
    params[0] = { d_train_inputs, n };
    caught = false;
    try {
        knn->fit(params, 1);
        knn->search(h_train_inputs.data(), n, d_pred_I, d_pred_D, n);
    } catch(std::runtime_error &e) {
        caught = true;
    }
    ASSERT_TRUE(caught);

    /**
     * Assert searching with host memory indices array fails
     */
    params[0] = { d_train_inputs, n };
    caught = false;
    try {
        knn->fit(params, 1);
        knn->search(d_train_inputs, n, h_res_I.data(), d_pred_D, n);
    } catch(std::runtime_error &e) {
        caught = true;
    }
    ASSERT_TRUE(caught);


    /**
     * Assert searching with host memory dists array fails
     */
    params[0] = { d_train_inputs, n };
    caught = false;
    try {
        knn->fit(params, 1);
        knn->search(d_train_inputs, n, d_pred_I, h_res_D.data(), n);
    } catch(std::runtime_error &e) {
        caught = true;
    }
    ASSERT_TRUE(caught);
}

typedef KNNTest<float> KNNTestFitFromHostSingleDevice;
TEST_F(KNNTestFitFromHostSingleDevice, Fit) {

    int *devices = new int[1]{0};

    knn->fit_from_host(h_train_inputs.data(), n, devices, 1);

    knn->search(d_train_inputs, n, d_pred_I, d_pred_D, n);

    ASSERT_TRUE(
            devArrMatch(d_ref_D, d_pred_D, n*n, Compare<float>()));
    ASSERT_TRUE(
            devArrMatch(d_ref_I, d_pred_I, n*n, Compare<long>()));

    delete devices;
}

} // end namespace ML
