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

#include <dlfcn.h>
#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>

#include <stdio.h>

#include <utils.h>

struct comms_ucp_handle {
  void *ucp_handle;

  ucs_status_ptr_t (*send_func)(ucp_ep_h, const void *, size_t, ucp_datatype_t,
                                ucp_tag_t, ucp_send_callback_t);
  ucs_status_ptr_t (*recv_func)(ucp_worker_h, void *, size_t count,
                                ucp_datatype_t datatype, ucp_tag_t, ucp_tag_t,
                                ucp_tag_recv_callback_t);
  void (*print_info_func)(ucp_ep_h, FILE *);
  void (*req_free_func)(void *);
  int (*worker_progress_func)(ucp_worker_h);
};

static const ucp_tag_t default_tag_mask = -1;

static const ucp_tag_t any_rank_tag_mask = 0x0000FFFF;

static const int UCP_ANY_RANK = -1;

/**
 * @brief Asynchronous send callback sets request to completed
 */
static void send_handle(void *request, ucs_status_t status) {
  struct ucp_request *req = (struct ucp_request *)request;
  printf("Send Completed %d\n", UCS_PTR_STATUS(request));
  req->finished = 1;
//  req->status = UCS_PTR_STATUS(request);

 // if(UCS_PTR_IS_ERR(req)) {

  //    printf("SETTING SEND STATUS TO FAILED!\n");
   //   req->failed = 1;
 // }
}

/**
 * @brief Asynchronous recv callback sets request to completed
 */
static void recv_handle(void *request, ucs_status_t status,
                        ucp_tag_recv_info_t *info) {
  struct ucp_request *req = (struct ucp_request *)request;
  printf("Receive Completed %d\n", UCS_PTR_STATUS(req));
  req->finished = 1;
 // req->status = UCS_PTR_STATUS(request);

//  if(UCS_PTR_IS_ERR(req)) {
//       printf("SETTING SEND STATUS TO FAILED!\n");
//      req->failed = 1;
//  }
}

void load_ucp_handle(struct comms_ucp_handle *ucp_handle) {
  ucp_handle->ucp_handle =
    dlopen("libucp.so", RTLD_LAZY | RTLD_NOLOAD | RTLD_NODELETE);
  if (!ucp_handle->ucp_handle) {
    ucp_handle->ucp_handle = dlopen("libucp.so", RTLD_LAZY | RTLD_NODELETE);
    if (!ucp_handle->ucp_handle) {
      printf("Cannot open UCX library: %s\n", dlerror());
      exit(1);
    }
  }
  dlerror();
}

void close_ucp_handle(struct comms_ucp_handle *handle) {
  dlclose(handle->ucp_handle);
}

void assert_dlerror() {
  char *error = dlerror();
  ASSERT(error == NULL, "Error loading function symbol: %s\n", error);
}

void load_send_func(struct comms_ucp_handle *ucp_handle) {
  ucp_handle->send_func = (ucs_status_ptr_t(*)(
    ucp_ep_h, const void *, size_t, ucp_datatype_t, ucp_tag_t,
    ucp_send_callback_t))dlsym(ucp_handle->ucp_handle, "ucp_tag_send_nb");
  assert_dlerror();
}

void load_free_req_func(struct comms_ucp_handle *ucp_handle) {
  ucp_handle->req_free_func =
    (void (*)(void *request))dlsym(ucp_handle->ucp_handle, "ucp_request_free");
  assert_dlerror();
}

void load_print_info_func(struct comms_ucp_handle *ucp_handle) {
  ucp_handle->print_info_func = (void (*)(ucp_ep_h, FILE *))dlsym(
    ucp_handle->ucp_handle, "ucp_ep_print_info");
  assert_dlerror();
}

void load_worker_progress_func(struct comms_ucp_handle *ucp_handle) {
  ucp_handle->worker_progress_func = (int (*)(ucp_worker_h))dlsym(
    ucp_handle->ucp_handle, "ucp_worker_progress");
  assert_dlerror();
}

void load_recv_func(struct comms_ucp_handle *ucp_handle) {
  ucp_handle->recv_func = (ucs_status_ptr_t(*)(
    ucp_worker_h, void *, size_t, ucp_datatype_t, ucp_tag_t, ucp_tag_t,
    ucp_tag_recv_callback_t))dlsym(ucp_handle->ucp_handle, "ucp_tag_recv_nb");
  assert_dlerror();
}

void init_comms_ucp_handle(struct comms_ucp_handle *handle) {
  load_ucp_handle(handle);

  load_send_func(handle);
  load_recv_func(handle);
  load_free_req_func(handle);
  load_print_info_func(handle);
  load_worker_progress_func(handle);
}

/**
 * @brief Frees any memory underlying the given ucp request object
 */
void free_ucp_request(struct comms_ucp_handle *ucp_handle, void *request) {
printf("Inside free_ucp_request\n");
//  ucp_request *req = (struct ucp_request*)request;
//  req->finished = 0;
  //req->failed = 0;
  //req->status = 0;
  //req->other_rank = -1;
//  if(req->needs_release == 1) {
//	  printf("Freeing ucp request\n");
//	req->needs_release = 0;
       (*(ucp_handle->req_free_func))(request);
 // } else {
//	  printf("Manually freeing request: %d\n", req->needs_release);
//	  free(req);
  //}
}

int ucp_progress(struct comms_ucp_handle *ucp_handle, ucp_worker_h worker) {
  return (*(ucp_handle->worker_progress_func))(worker);
}

struct cuml_request *process_ucp_request(struct ucp_request *req, int other_rank) {


        struct cuml_request *cuml_req = (struct cuml_request*)malloc(sizeof(struct cuml_request));


	// The send operation completed immediately
	if(UCS_PTR_STATUS(req) == UCS_OK) {
	 //   printf("Send op completed already!\n");
	  //  req = (struct ucp_request *)malloc(sizeof(struct ucp_request));
	   // req->failed = 0;
//	    req->finished = 1;
	    cuml_req->needs_release = false;
//	    req->needs_release = 0;
	}

	// The send operation failed
	else if(UCS_PTR_IS_ERR(req)) {
	    printf("send op is error!\n");
	    //req->finished = 1;
	    cuml_req->needs_release =false;
//	    req->needs_release = 0;
 //           req->failed = 1;
	}

	// Operation scheduled for send and will be completed by handler.
	else {
	    printf("Op needs release, will go through callback\n");
   //         req->needs_release = 1;
	    //req->failed = 0;
	    cuml_req->needs_release = true;
	    cuml_req->req = req;
	}
       // printf("Inside process request\n");
     //   req->other_rank = other_rank;

       // printf("About to set status\n");
       // req->status = UCS_PTR_STATUS(req);



	return cuml_req;
}

/**
 * @brief Asynchronously send data to the given endpoint using the given tag
 */
struct cuml_request *ucp_isend(struct comms_ucp_handle *ucp_handle,
                              ucp_ep_h ep_ptr, const void *buf, int size,
                              int tag, ucp_tag_t tag_mask, int rank) {
  ucp_tag_t ucp_tag = ((uint32_t)rank << 31) | (uint32_t)tag;

  ucs_status_ptr_t send_result = (*(ucp_handle->send_func))(
    ep_ptr, buf, size, ucp_dt_make_contig(1), ucp_tag, send_handle);

  struct ucp_request *request = (struct ucp_request *)send_result;
  return process_ucp_request(request, rank);

}

/**
 * @bried Asynchronously receive data from given endpoint with the given tag.
 */
struct cuml_request *ucp_irecv(struct comms_ucp_handle *ucp_handle,
                              ucp_worker_h worker, ucp_ep_h ep_ptr, void *buf,
                              int size, int tag, ucp_tag_t tag_mask,
                              int sender_rank) {
  ucp_tag_t ucp_tag = ((uint32_t)sender_rank << 31) | (uint32_t)tag;

  ucs_status_ptr_t recv_result = (*(ucp_handle->recv_func))(
    worker, buf, size, ucp_dt_make_contig(1), ucp_tag, tag_mask, recv_handle);
  struct ucp_request *request = (struct ucp_request *)recv_result;

  return process_ucp_request(request, sender_rank);
}
