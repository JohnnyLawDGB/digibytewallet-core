//
//  BRArray.h
//
//  Created by Aaron Voisine on 11/14/15.
//  Copyright (c) 2015 breadwallet LLC.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#ifndef BRArray_h
#define BRArray_h

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

// growable arrays with type checking
//
// example:
//
// char *myArray;                           // array of chars
//
// array_new(myArray, 3);                   // initialize myArray with a capacity of 3 items
// array_add(myArray, 'a');                 // add 'a' to myArray
// array_add_array(myArray, "bcd", 3);      // append 'b', 'c', 'd' (capacity is auto-increased)
// array_set_count(myArray, 5);             // myArray now has 5 items: 'a', 'b', 'c', 'd', '\0'
// array_rm(myArray, 3);                    // remove 'd' from myArray
// array_rm_last(myArray);                  // remove '\0' from end of myArray
// array_insert(myArray, 0, 'x');           // insert 'x' at start of myArray
// array_insert_array(myArray, 1, "yz", 2); // insert 'y', 'z' after 'x'
//
// for (int i = 0; i < array_count(myArray); i++) {
//     printf("%c, ", myArray[i]);          // x, y, z, a, b, c,
// }
//
// array_rm_range(myArray, 3, 3);           // remove 'a', 'b', 'c' from end of myArray
// array_clear(myArray);                    // myArray is now empty
// array_free(myArray);                     // free memory allocated for myArray
//
// NOTE: when new items are added to an array past its current capacity, its memory location may change, so other
// references to it or its members must be updated

#define array_capacity(array) (((size_t *)(array))[-2])

#define array_count(array) (((size_t *)(array))[-1])

// ---- allocation-size policy for the growable-array macros --------------------
//
// This policy is a SAFETY NET only. The real fix for a declared wire count is to
// bound it by the bytes that remain in the message BEFORE these macros are ever
// reached (see the parsers in BRTransaction.c, BRPeer.c, BRGCSFilter.c and
// BRMerkleBlock.c). The macros below make the header self-defending so a size
// that would not fit size_t cannot silently produce a too-small backing store:
//
//   * array_new returns a NULL array when capacity * element-size (plus the two
//     size_t header words) would not fit in size_t.
//   * a growing macro (array_set_capacity / array_set_count / array_add /
//     array_add_array / array_insert / array_insert_array) that cannot fit the
//     requested size, or whose grow the allocator declines, LEAVES THE ARRAY AND
//     ITS COUNT UNCHANGED. It never advances the count past a backing store that
//     was not actually grown -- a no-op grow that still moved the count would
//     leave the count sitting behind the declared number, which is why bounding
//     the count up front, not this net, is the real fix.
//
// Macro names and call shapes are unchanged, so existing callers compile and
// behave identically for the ordinary (small, trusted) sizes they pass.
//
// WIRE_COUNT_BOUNDS_UNFIXED restores the pre-policy macros for the host KAT's
// red arm only; it is never defined by any shipped build.
#ifdef WIRE_COUNT_BOUNDS_UNFIXED

#define array_new(array, capacity) do {\
    size_t _array_cap = (capacity);\
    assert(_array_cap >= 0);\
    (array) = (void *)((size_t *)calloc(1, _array_cap*sizeof(*(array)) + sizeof(size_t)*2) + 2);\
    assert((array) != NULL);\
    array_capacity(array) = _array_cap;\
    array_count(array) = 0;\
} while (0)

#define array_set_capacity(array, capacity) do {\
    size_t _array_cap = (capacity);\
    assert((array) != NULL);\
    assert(_array_cap >= array_count(array));\
    (array) = (void *)((size_t *)realloc((size_t *)(array) - 2, _array_cap*sizeof(*(array)) + sizeof(size_t)*2) + 2);\
    assert((array) != NULL);\
    if (_array_cap > array_capacity(array))\
        memset((array) + array_capacity(array), 0, (_array_cap - array_capacity(array))*sizeof(*(array)));\
    array_capacity(array) = _array_cap;\
} while (0)

#define array_set_count(array, count) do {\
    size_t _array_cnt = (count);\
    assert((array) != NULL);\
    assert(_array_cnt >= 0);\
    if (_array_cnt > array_capacity(array))\
        array_set_capacity(array, _array_cnt);\
    if (_array_cnt < array_count(array))\
        memset((array) + _array_cnt, 0, (array_count(array) - _array_cnt)*sizeof(*(array)));\
    array_count(array) = _array_cnt;\
} while (0)

#define array_add(array, item) do {\
    assert((array) != NULL);\
    if (array_count(array) + 1 > array_capacity(array))\
        array_set_capacity(array, (array_capacity(array) + 1)*3/2);\
    (array)[array_count(array)++] = (item);\
} while (0)

#define array_add_array(array, other_array, count) do {\
    assert((array) != NULL);\
    size_t _array_cnt = (count), _array_i = array_count(array), _array_j = 0;\
    assert((other_array) != NULL || _array_cnt == 0);\
    assert(_array_cnt >= 0);\
    if (_array_i + _array_cnt > array_capacity(array))\
        array_set_capacity(array, (_array_i + _array_cnt)*3/2);\
    while (_array_j < _array_cnt)\
        (array)[_array_i++] = (other_array)[_array_j++];\
    array_count(array) += _array_cnt;\
} while (0)

#else // allocation-size policy in force (the shipped default)

#define array_new(array, capacity) do {\
    size_t _array_cap = (capacity), _array_bytes = 0;\
    void *_array_raw = NULL;\
    if (! __builtin_mul_overflow(_array_cap, sizeof(*(array)), &_array_bytes) &&\
        ! __builtin_add_overflow(_array_bytes, sizeof(size_t)*2, &_array_bytes))\
        _array_raw = calloc(1, _array_bytes);\
    if (_array_raw) {\
        (array) = (void *)((size_t *)_array_raw + 2);\
        array_capacity(array) = _array_cap;\
        array_count(array) = 0;\
    }\
    else (array) = NULL;\
} while (0)

#define array_set_capacity(array, capacity) do {\
    size_t _array_cap = (capacity), _array_bytes = 0;\
    if ((array) != NULL && _array_cap >= array_count(array) &&\
        ! __builtin_mul_overflow(_array_cap, sizeof(*(array)), &_array_bytes) &&\
        ! __builtin_add_overflow(_array_bytes, sizeof(size_t)*2, &_array_bytes)) {\
        void *_array_raw = realloc((size_t *)(array) - 2, _array_bytes);\
        if (_array_raw) {\
            (array) = (void *)((size_t *)_array_raw + 2);\
            if (_array_cap > array_capacity(array))\
                memset((array) + array_capacity(array), 0, (_array_cap - array_capacity(array))*sizeof(*(array)));\
            array_capacity(array) = _array_cap;\
        }\
    }\
} while (0)

#define array_set_count(array, count) do {\
    size_t _array_cnt = (count);\
    if ((array) != NULL) {\
        if (_array_cnt > array_capacity(array)) array_set_capacity(array, _array_cnt);\
        if ((array) != NULL && _array_cnt <= array_capacity(array)) {\
            if (_array_cnt < array_count(array))\
                memset((array) + _array_cnt, 0, (array_count(array) - _array_cnt)*sizeof(*(array)));\
            array_count(array) = _array_cnt;\
        }\
    }\
} while (0)

#define array_add(array, item) do {\
    if ((array) != NULL) {\
        if (array_count(array) + 1 > array_capacity(array))\
            array_set_capacity(array, (array_capacity(array) + 1)*3/2);\
        if ((array) != NULL && array_count(array) + 1 <= array_capacity(array))\
            (array)[array_count(array)++] = (item);\
    }\
} while (0)

#define array_add_array(array, other_array, count) do {\
    size_t _array_cnt = (count), _array_i = 0, _array_j = 0, _array_need = 0;\
    if ((array) != NULL && (other_array) != NULL &&\
        ! __builtin_add_overflow(array_count(array), _array_cnt, &_array_need)) {\
        _array_i = array_count(array);\
        if (_array_need > array_capacity(array)) {\
            size_t _array_newcap = 0;\
            if (__builtin_mul_overflow(_array_need, (size_t)3, &_array_newcap)) _array_newcap = _array_need;\
            else _array_newcap /= 2;\
            array_set_capacity(array, _array_newcap);\
        }\
        if ((array) != NULL && _array_need <= array_capacity(array)) {\
            while (_array_j < _array_cnt)\
                (array)[_array_i++] = (other_array)[_array_j++];\
            array_count(array) += _array_cnt;\
        }\
    }\
} while (0)

#endif // WIRE_COUNT_BOUNDS_UNFIXED

// The inserting macros follow the same policy as the growing macros above: the grow is
// attempted first, and the count moves and the elements shift only once the store is known to
// hold the new total. ARRAY_INSERT_POLICY_UNFIXED keeps the earlier form for the host KAT's
// comparison arm only; it is never defined by a shipped build.
#if defined(WIRE_COUNT_BOUNDS_UNFIXED) || defined(ARRAY_INSERT_POLICY_UNFIXED)

#define array_insert(array, index, item) do {\
    assert((array) != NULL);\
    size_t _array_idx = (index), _array_i = ++array_count(array);\
    assert(_array_idx >= 0 && _array_idx < array_count(array));\
    if (_array_i > array_capacity(array))\
        array_set_capacity(array, (array_capacity(array) + 1)*3/2);\
    while (--_array_i > _array_idx)\
        (array)[_array_i] = (array)[_array_i - 1];\
    (array)[_array_idx] = (item);\
} while (0)

#define array_insert_array(array, index, other_array, count) do {\
    assert((array) != NULL);\
    size_t _array_idx = (index), _array_cnt = (count), _array_i = array_count(array) + _array_cnt, _array_j = 0;\
    assert(_array_idx >= 0 && _array_idx <= array_count(array));\
    assert((other_array) != NULL || _array_cnt == 0);\
    assert(_array_cnt >= 0);\
    if (_array_i > array_capacity(array))\
        array_set_capacity(array, _array_i*3/2);\
    while (_array_i-- > _array_idx + _array_cnt)\
        (array)[_array_i] = (array)[_array_i - _array_cnt];\
    while (_array_j < _array_cnt)\
        (array)[_array_idx + _array_j] = (other_array)[_array_j], _array_j++;\
    array_count(array) += _array_cnt;\
} while (0)

#else

#define array_insert(array, index, item) do {\
    size_t _array_idx = (index), _array_i = 0;\
    if ((array) != NULL && ! __builtin_add_overflow(array_count(array), (size_t)1, &_array_i) &&\
        _array_idx < _array_i) {\
        if (_array_i > array_capacity(array))\
            array_set_capacity(array, (array_capacity(array) + 1)*3/2);\
        if ((array) != NULL && _array_i <= array_capacity(array)) {\
            array_count(array) = _array_i;\
            while (--_array_i > _array_idx)\
                (array)[_array_i] = (array)[_array_i - 1];\
            (array)[_array_idx] = (item);\
        }\
    }\
} while (0)

#define array_insert_array(array, index, other_array, count) do {\
    size_t _array_idx = (index), _array_cnt = (count), _array_i = 0, _array_j = 0;\
    if ((array) != NULL && ((other_array) != NULL || _array_cnt == 0) &&\
        _array_idx <= array_count(array) &&\
        ! __builtin_add_overflow(array_count(array), _array_cnt, &_array_i)) {\
        if (_array_i > array_capacity(array)) {\
            size_t _array_newcap = 0;\
            if (__builtin_mul_overflow(_array_i, (size_t)3, &_array_newcap)) _array_newcap = _array_i;\
            else _array_newcap /= 2;\
            array_set_capacity(array, _array_newcap);\
        }\
        if ((array) != NULL && _array_i <= array_capacity(array)) {\
            while (_array_i-- > _array_idx + _array_cnt)\
                (array)[_array_i] = (array)[_array_i - _array_cnt];\
            while (_array_j < _array_cnt)\
                (array)[_array_idx + _array_j] = (other_array)[_array_j], _array_j++;\
            array_count(array) += _array_cnt;\
        }\
    }\
} while (0)

#endif // inserting macros

#define array_rm(array, index) do {\
    size_t _array_i = (index);\
    assert((array) != NULL);\
    assert(_array_i >= 0 && _array_i < array_count(array));\
    array_count(array)--;\
    while (_array_i < array_count(array))\
        (array)[_array_i] = (array)[_array_i + 1], _array_i++;\
    memset((array) + _array_i, 0, sizeof(*(array)));\
} while (0)

#define array_rm_last(array) do {\
    assert((array) != NULL);\
    if (array_count(array) > 0)\
        memset((array) + --array_count(array), 0, sizeof(*(array)));\
} while(0)

#define array_rm_range(array, index, len) do {\
    size_t _array_i = (index), _array_len = (len);\
    assert((array) != NULL);\
    assert(_array_i >= 0 && _array_i < array_count(array));\
    assert(_array_len >= 0 && _array_i + _array_len <= array_count(array));\
    array_count(array) -= _array_len;\
    while (_array_i < array_count(array))\
        (array)[_array_i] = (array)[_array_i + _array_len], _array_i++;\
    memset((array) + _array_i, 0, _array_len*sizeof(*(array)));\
} while(0)

#define array_clear(array) do {\
    assert((array) != NULL);\
    memset((array), 0, array_count(array)*sizeof(*(array)));\
    array_count(array) = 0;\
} while (0)

#define array_free(array) do {\
    assert((array) != NULL);\
    free((size_t *)(array) - 2);\
} while (0)

#ifdef __cplusplus
}
#endif

#endif // BRArray_h
