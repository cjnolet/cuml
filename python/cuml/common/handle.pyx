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


import cuml
from libcpp.memory cimport shared_ptr
from libcpp.vector cimport vector

from cuml.common.cuda cimport _Stream, _Error, cudaStreamSynchronize


cdef extern from "cuml/common/rmmAllocatorAdapter.hpp" namespace "ML" nogil:
    cdef cppclass rmmAllocatorAdapter(deviceAllocator):
        pass

cdef class Handle:
    """
    Handle is a lightweight python wrapper around the corresponding C++ class
    of cumlHandle exposed by cuML's C++ interface. Refer to the header file
    cuml/cuml.hpp for interface level details of this struct

    Examples
    --------

    .. code-block:: python

        import cuml
        stream = cuml.cuda.Stream()
        handle = cuml.Handle()
        handle.setStream(stream)
        handle.enableRMM()   # Enable RMM as the device-side allocator

        # call ML algos here

        # final sync of all work launched in the stream of this handle
        # this is same as `cuml.cuda.Stream.sync()` call, but safer in case
        # the default stream inside the `cumlHandle` is being used
        handle.sync()
        del handle  # optional!
    """

    # ML::cumlHandle doesn't have copy operator. So, use pointer for the object
    # python world cannot access to this raw object directly, hence use
    # 'size_t'!
    cdef size_t h

    def __cinit__(self, user_stream=cuml.cuda.Stream(), n_streams=0):
        cdef size_t s = <size_t>user_stream.getStream()
        self.h = <size_t>(new cumlHandle(<_Stream>s, n_streams))

    def __dealloc__(self):
        h_ = <cumlHandle*>self.h
        del h_

    def setStream(self, stream):
        cdef size_t s = <size_t>stream.getStream()
        cdef cumlHandle* h_ = <cumlHandle*>self.h
        h_.setStream(<_Stream>s)

    # TODO: in future, we should just enable RMM by default
    def enableRMM(self):
        """
        Enables to use RMM as the allocator for all device memory allocations
        inside cuML C++ world. Currently, there are only 2 kinds of allocators.
        First, the usual cudaMalloc/Free, which is the default for cumlHandle.
        Second, the allocator based on RMM. So, this function, basically makes
        the cumlHandle use a more efficient allocator, instead of the default.
        """
        cdef shared_ptr[deviceAllocator] rmmAlloc = (
            shared_ptr[deviceAllocator](new rmmAllocatorAdapter()))
        cdef cumlHandle* h_ = <cumlHandle*>self.h
        h_.setDeviceAllocator(rmmAlloc)

    def sync(self):
        """
        Issues a sync on the stream set for this handle.

        Once we make `cuml.cuda.Stream` as a mandatory option for creating
        `cuml.Handle`, this should go away
        """
        cdef cumlHandle* h_ = <cumlHandle*>self.h
        cdef _Stream stream = h_.getStream()
        cdef _Error e = cudaStreamSynchronize(stream)
        if e != 0:
            raise cuml.cuda.CudaRuntimeError("Stream sync")

    def getHandle(self):
        return self.h

    def getNumWorkerStreams(self):
        cdef cumlHandle* h_ = <cumlHandle*>self.h
        return h_.getNumWorkerStreams()

    def getWorkerStreamsAsHandles(self):
        """
        Returns the internal streams as separate single-stream handles
        that can be used to parallelize a set of tasks, giving each
        task their own handle.

        Examples
        --------
        .. code-block:: python

            import cuml
            handle = cuml.Handle()

            handles = handle.getWorkerStreamsAsHandles()

            n_int_handles = len(handles)

            # Wait until user stream completes
            handle.waitOnUserStream()

            outputs = []
            for i in range(n_tasks):
                # call cuml API with sub_handles
                outputs.append(
                    model.predict(X, handle=handles[i%n_int_handles]
                )

            # Wait until all parallel streams complete
            handle.waitOnWorkerStreams()

        :return:
        """
        cdef cumlHandle* h_ = <cumlHandle*>self.h

        cdef vector[_Stream] int_streams = h_.getWorkerStreams()
        handles = []

        cdef cumlHandle *new_handle
        cdef _Stream cur_stream
        for i in range(int_streams.size()):
            cur_stream = int_streams.at(i)
            stream = cuml.cuda.Stream(<size_t>cur_stream)
            handles.append(cuml.Handle(stream, 0))
        return handles

    def waitOnUserStream(self):
        cdef cumlHandle * h_ = < cumlHandle * > self.h
        h_.waitOnUserStream()

    def waitOnWorkerStreams(self):
        cdef cumlHandle * h_ = < cumlHandle * > self.h
        h_.waitOnWorkerStreams()
