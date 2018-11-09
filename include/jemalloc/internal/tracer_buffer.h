// -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*-
// Copyright (c) 2017, gperftools Contributors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef TCMALLOC_TRACER_BUFFER_H_
#define TCMALLOC_TRACER_BUFFER_H_
#include <stdlib.h>
#include <string.h>

#include "internal_logging.h"

namespace tcmalloc {

struct TracerBuffer {
  static const int kMinSizeAfterRefresh = 1 << 20;

  virtual void Refresh() = 0;
  virtual void Finalize() = 0;

  virtual bool IsFullySetup() = 0;

  void AppendData(const char* buf, size_t size) {
    ASSERT(size <= kMinSizeAfterRefresh);

    if (limit - current < size) {
      Refresh();
    }
    ASSERT(limit - current >= size);

    memcpy(current, buf, size);
    current += size;
  }

  static TracerBuffer* GetInstance();

protected:
  virtual ~TracerBuffer();
  TracerBuffer() : current(NULL), limit(NULL) {}

  char* current;
  char* limit;
};

} // namespace tcmalloc

#endif  // TCMALLOC_TRACER_BUFFER_H_
