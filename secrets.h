/*
 * Copyright 2015 Andreas Oberritter
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

#ifndef _secrets_h_
#define _secrets_h_

#include <stdbool.h>

bool secret_find(const char *name, unsigned char *buf, size_t n);
void secrets_search(const unsigned char *m, size_t n, size_t step);

#endif /* _secrets_h_ */
