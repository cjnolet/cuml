#
# Copyright (c) 2019, NVIDIA CORPORATION.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# cython: profile=False
# distutils: language = c++
# cython: embedsignature = True
# cython: language_level = 3

import ctypes
import cudf
import numpy as np

import rmm

from libc.stdlib cimport malloc, free


from libcpp cimport bool
from libc.stdint cimport uintptr_t, uint32_t, uint64_t

from cuml.common.base import Base
from cuml.common.handle cimport cumlHandle
from cuml.decomposition.utils cimport *
from cuml.utils import get_cudf_column_ptr, get_dev_array_ptr, \
    input_to_dev_array, zeros

import numpy as np

from cuml.decomposition import PCA

cdef extern from "cumlprims/opg/matrix/data.hpp" \
    namespace "MLCommon::Matrix":

    cdef cppclass floatData_t:
        float *ptr
        size_t totalSize

    cdef cppclass doubleData_t:
        double *ptr
        size_t totalSize

cdef extern from "cumlprims/opg/matrix/part_descriptor.hpp" \
    namespace "MLCommon::Matrix":

    cdef cppclass RankSizePair:
        int rank
        size_t size

cdef extern from "cumlprims/opg/pca.hpp" namespace "ML::PCA::opg":

    cdef void fit_transform(cumlHandle& handle,
                  RankSizePair **input,
                  size_t n_parts,
                  floatData_t **rank_sizes,
                  float *trans_input,
                  float *components,
                  float *explained_var,
                  float *explained_var_ratio,
                  float *singular_vals,
                  float *mu,
                  float *noise_vars,
                  paramsPCA prms,
                  bool verbose) except +

    cdef void fit_transform(cumlHandle& handle,
                  RankSizePair **input,
                  size_t n_parts,
                  doubleData_t **rank_sizes,
                  double *trans_input,
                  double *components,
                  double *explained_var,
                  double *explained_var_ratio,
                  double *singular_vals,
                  double *mu,
                  double *noise_vars,
                  paramsPCA prms,
                  bool verbose) except +

    cdef void transform(cumlHandle& handle,
                  RankSizePair **input,
                  size_t n_parts,
                  floatData_t **rank_sizes,
                  float *components,
                  float *trans_input,            
                  float *singular_vals,
                  float *mu,                
                  paramsPCA prms,
                  bool verbose) except +

    cdef void transform(cumlHandle& handle,
                  RankSizePair **input,
                  size_t n_parts,
                  doubleData_t **rank_sizes,
                  double *components,
                  double *trans_input,
                  double *singular_vals,
                  double *mu,
                  paramsPCA prms,
                  bool verbose) except +

class PCAMG(PCA):

    def __init__(self, **kwargs):
        super(PCAMG, self).__init__(**kwargs)


    def _build_dataFloat(self, arr_interfaces):
        cdef floatData_t ** dataF = < floatData_t ** > \
                                      malloc(sizeof(floatData_t *) \
                                             * len(arr_interfaces))
        cdef uintptr_t input_ptr
        for x_i in range(len(arr_interfaces)):
            x = arr_interfaces[x_i]
            input_ptr = x["data"]
            print("Shape: " + str(x["shape"]))
            dataF[x_i] = < floatData_t * > malloc(sizeof(floatData_t))
            dataF[x_i].ptr = < float * > input_ptr
            dataF[x_i].totalSize = < size_t > (x["shape"][0] * x["shape"][1] * sizeof(float))
            print("Size: " + str((x["shape"][0] * x["shape"][1] * sizeof(float))))

        return <size_t>dataF

    def _build_dataDouble(self, arr_interfaces):
        cdef doubleData_t ** dataD = < doubleData_t ** > \
                                       malloc(sizeof(doubleData_t *) \
                                              * len(arr_interfaces))
        cdef uintptr_t input_ptr
        for x_i in range(len(arr_interfaces)):
            x = arr_interfaces[x_i]
            input_ptr = x["data"]
            print("Shape: " + str(x["shape"]))
            dataD[x_i] = < doubleData_t * > malloc(sizeof(doubleData_t))
            dataD[x_i].ptr = < double * > input_ptr
            dataD[x_i].totalSize = < size_t > (x["shape"][0] * x["shape"][1] *sizeof(double))
        return <size_t>dataD

    def _freeDoubleD(self, data, arr_interfaces):
        cdef uintptr_t data_ptr = data
        cdef doubleData_t **d = <doubleData_t**>data_ptr
        for x_i in range(len(arr_interfaces)):
            free(d[x_i])
        free(d)

    def _freeFloatD(self, data, arr_interfaces):
        cdef uintptr_t data_ptr = data
        cdef floatData_t **d = <floatData_t**>data_ptr
        for x_i in range(len(arr_interfaces)):
            free(d[x_i])
        free(d)


    def fit(self, X, M, N, partsToRanks, _transform=False):
        """
        Fit function for PCA MG. This not meant to be used as
        part of the public API.
        :param X: array of local dataframes / array partitions
        :param M: total number of rows
        :param N: total number of cols
        :param partsToRanks: array of tuples in the format: [(rank,size)]
        :return: self
        """

        print("partsToRanks: " + str(partsToRanks))

        arr_interfaces = []
        for arr in X:
            X_m, input_ptr, n_rows, self.n_cols, self.dtype = \
                input_to_dev_array(arr, check_dtype=[np.float32, np.float64])
            arr_interfaces.append({"obj": X_m,
                                   "data": input_ptr,
                                   "shape": (n_rows, self.n_cols)})

        cpdef paramsPCA params
        params.n_components = self.n_components
        params.n_rows = M
        params.n_cols = N
        params.whiten = self.whiten
        params.n_iterations = self.iterated_power
        params.tol = self.tol
        params.algorithm = self.c_algorithm

        if self.n_components > N:
            raise ValueError('Number of components should not be greater than'
                             'the number of columns in the data')

        trans_input_, \
        self.components_ary, \
        self.explained_variance_, \
        self.explained_variance_ratio_, \
        self.mean_, self.singular_values_, \
        self.noise_variance_ = \
            self._initialize_arrays(params.n_components,
                                    params.n_rows, params.n_cols)

        cdef uintptr_t comp_ptr = get_dev_array_ptr(self.components_ary)

        cdef uintptr_t explained_var_ptr = \
            get_cudf_column_ptr(self.explained_variance_)

        cdef uintptr_t explained_var_ratio_ptr = \
            get_cudf_column_ptr(self.explained_variance_ratio_)

        cdef uintptr_t singular_vals_ptr = \
            get_cudf_column_ptr(self.singular_values_)

        cdef uintptr_t mean_ptr = get_cudf_column_ptr(self.mean_)

        cdef uintptr_t noise_vars_ptr = \
            get_cudf_column_ptr(self.noise_variance_)

        cdef uintptr_t t_input_ptr = get_dev_array_ptr(trans_input_)

        cdef cumlHandle* handle_ = <cumlHandle*><size_t>self.handle.getHandle()

        cdef RankSizePair **rankSizePair = <RankSizePair**> \
                                            malloc(sizeof(RankSizePair**) \
                                                   * len(partsToRanks))
        for idx, rankSize in enumerate(partsToRanks):
            rank, size = rankSize
            rankSizePair[idx] = <RankSizePair*> malloc(sizeof(RankSizePair))
            rankSizePair[idx].rank = <int>rank
            rankSizePair[idx].size = <size_t>size

        n_total_parts = len(partsToRanks)

        cdef uintptr_t data
        if self.dtype == np.float32:
            data = self._build_dataFloat(arr_interfaces)
            fit_transform(handle_[0],
                <RankSizePair**>rankSizePair,
                <size_t> n_total_parts,
                <floatData_t**> <size_t>data,
                <float*> t_input_ptr,
                <float*> comp_ptr,
                <float*> explained_var_ptr,
                <float*> explained_var_ratio_ptr,
                <float*> singular_vals_ptr,
                <float*> mean_ptr,
                <float*> noise_vars_ptr,
                params,
                True)

            print("Syncing handle")
            self.handle.sync()
            print("Freeing data array")

            self._freeFloatD(data, arr_interfaces)

        else:
            data = self._build_dataDouble(arr_interfaces)
            fit_transform(handle_[0],
                <RankSizePair**>rankSizePair,
                <size_t> n_total_parts,
                <doubleData_t**> data,
                <double*> t_input_ptr,
                <double*> comp_ptr,
                <double*> explained_var_ptr,
                <double*> explained_var_ratio_ptr,
                <double*> singular_vals_ptr,
                <double*> mean_ptr,
                <double*> noise_vars_ptr,
                params,
                True)

            print("Syncing handle")

            self.handle.sync()

            print("Freeing data array")
            self._freeDoubleD(data, arr_interfaces)

        print("Freeing rank size pairs")
        for idx, rankSize in enumerate(partsToRanks):
            free(<RankSizePair*>rankSizePair[idx])
        free(<RankSizePair**>rankSizePair)

        # Keeping the additional dataframe components during cuml 0.8.
        # See github issue #749

        print("assigning components: " + str(np.array(self.components_ary)))
        self.components_ = cudf.DataFrame.from_gpu_matrix(self.components_ary)

        if isinstance(X, cudf.DataFrame):
            del X_m

        print("DONE!")
        if _transform:
            return cudf.DataFrame.from_gpu_matrix(trans_input_)
        else:
            print("RETURNING!")
            return self


    