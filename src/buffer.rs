//! A byte buffer with a fixed capacity.

use core::borrow::{Borrow, BorrowMut};
use core::hash::{Hash, Hasher};
use core::ops::{Bound, Deref, DerefMut, RangeBounds};
use core::{cmp, fmt, mem, ptr, slice};

macro_rules! panic_oob {
    ($method_name:expr, $index:expr, $len:expr) => {
        panic!(
            concat!(
                "Buffer::",
                $method_name,
                ": index {} is out of bounds in vector of length {}"
            ),
            $index, $len
        )
    };
}

/// A byte buffer with a fixed capacity.
pub struct Buffer {
    ptr: *mut u8,
    size: usize,
    max_size: usize,
}

impl Buffer {
    /// Create new buffer
    pub fn new(ptr: *mut u8, size: usize, max_size: usize) -> Self {
        Buffer {
            ptr,
            size,
            max_size,
        }
    }

    /// Return the number of elements in the `Buffer`.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns whether the `Buffer` is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the capacity of the `Buffer`.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.max_size
    }

    /// Push `element` to the end of the buffer.
    ///
    /// `element` is silently ignored if the buffer is already full.
    pub fn push(&mut self, element: u8) {
        if self.size == self.max_size {
            return;
        }
        let _ = self.try_push(element);
    }

    /// Push `element` to the end of the buffer.
    ///
    /// Return `Ok` if the push succeeds, or return an error if the buffer
    /// is already full.
    pub fn try_push(&mut self, element: u8) -> Result<(), ()> {
        if self.size < self.max_size {
            unsafe {
                let p: *mut _ = self.get_unchecked_ptr(self.size);
                ptr::write(p, element);
                self.set_len(self.size + 1)
            };
            Ok(())
        } else {
            Err(())
        }
    }

    /// Get pointer to where element at `index` would be
    unsafe fn get_unchecked_ptr(&mut self, index: usize) -> *mut u8 {
        self.ptr.add(index)
    }

    /// Insert `element` at position `index`.
    ///
    /// Shift up all elements after `index`.
    ///
    /// It is an error if the index is greater than the length or if the
    /// `Buffer` is full.
    ///
    /// ***Panics*** if `index` is out of bounds.
    pub fn insert(&mut self, index: usize, element: u8) {
        let _ = self.try_insert(index, element);
    }

    /// Insert `element` at position `index`.
    ///
    /// Shift up all elements after `index`; the `index` must be less than
    /// or equal to the length.
    ///
    /// Returns an error if buffer is already at full capacity.
    ///
    /// ***Panics*** `index` is out of bounds.
    pub fn try_insert(&mut self, index: usize, element: u8) -> Result<(), ()> {
        if index > self.size {
            panic_oob!("try_insert", index, self.size)
        }
        if self.size == self.max_size {
            return Err(());
        }
        let len = self.size;

        unsafe {
            {
                let p: *mut _ = self.get_unchecked_ptr(index);
                // Shift everything over to make space. (Duplicating the
                // `index`th element into two consecutive places.)
                ptr::copy(p, p.offset(1), len - index);
                // Write it in, overwriting the first copy of the `index`th
                // element.
                ptr::write(p, element);
            }
            self.set_len(len + 1);
        }
        Ok(())
    }

    /// Remove the last element in the buffer and return it.
    ///
    /// Return `Some(` *element* `)` if the buffer is non-empty, else `None`.
    pub fn pop(&mut self) -> Option<u8> {
        if self.len() == 0 {
            return None;
        }
        unsafe {
            let new_len = self.len() - 1;
            self.set_len(new_len);
            Some(ptr::read(self.get_unchecked_ptr(new_len)))
        }
    }

    /// Remove the element at `index` and swap the last element into its place.
    ///
    /// This operation is O(1).
    ///
    /// Return the *element* if the index is in bounds, else panic.
    ///
    /// ***Panics*** if the `index` is out of bounds.
    pub fn swap_remove(&mut self, index: usize) -> u8 {
        self.swap_pop(index)
            .unwrap_or_else(|| panic_oob!("swap_remove", index, self.len()))
    }

    /// Remove the element at `index` and swap the last element into its place.
    ///
    /// This is a checked version of `.swap_remove`.  
    /// This operation is O(1).
    ///
    /// Return `Some(` *element* `)` if the index is in bounds, else `None`.
    pub fn swap_pop(&mut self, index: usize) -> Option<u8> {
        let len = self.size;
        if index >= len {
            return None;
        }
        self.swap(index, len - 1);
        self.pop()
    }

    /// Remove the element at `index` and shift down the following elements.
    ///
    /// The `index` must be strictly less than the length of the vector.
    ///
    /// ***Panics*** if the `index` is out of bounds.
    pub fn remove(&mut self, index: usize) -> u8 {
        self.pop_at(index)
            .unwrap_or_else(|| panic_oob!("remove", index, self.len()))
    }

    /// Remove the element at `index` and shift down the following elements.
    ///
    /// This is a checked version of `.remove(index)`. Returns `None` if there
    /// is no element at `index`. Otherwise, return the element inside `Some`.
    pub fn pop_at(&mut self, index: usize) -> Option<u8> {
        if index >= self.len() {
            None
        } else {
            self.drain(index..index + 1).next()
        }
    }

    /// Shortens the vector, keeping the first `len` elements and dropping
    /// the rest.
    ///
    /// If `len` is greater than the vector’s current length this has no
    /// effect.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.size {
            self.size = new_len;
        }
    }

    /// Set buffer len
    pub unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(new_len < self.max_size + 1);
        self.size = new_len;
    }
    /// Remove all elements in the vector.
    pub fn clear(&mut self) {
        self.truncate(0)
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all elements `e` such that `f(&mut e)` returns false.
    /// This method operates in place and preserves the order of the retained
    /// elements.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut u8) -> bool,
    {
        let len = self.size;
        let mut del = 0;
        {
            let v = &mut **self;

            for i in 0..len {
                if !f(&mut v[i]) {
                    del += 1;
                } else if del > 0 {
                    v.swap(i - del, i);
                }
            }
        }
        if del > 0 {
            self.drain(len - del..);
        }
    }

    /// Copy and appends all elements in a slice to the `Buffer`.
    ///
    /// # Errors
    ///
    /// This method will return an error if the capacity left (see
    /// [`remaining_capacity`]) is smaller then the length of the provided
    /// slice.
    ///
    /// [`remaining_capacity`]: #method.remaining_capacity
    pub fn try_extend_from_slice(&mut self, other: &[u8]) -> Result<(), ()> {
        let self_len = self.size;
        let other_len = core::cmp::min(other.len(), self.max_size - self.size);

        unsafe {
            let dst = self.ptr.offset(self_len as isize);
            core::ptr::copy_nonoverlapping(other.as_ptr(), dst, other_len);
            self.set_len(self_len + other_len);
        }
        Ok(())
    }

    /// Create a draining iterator that removes the specified range in the vector
    /// and yields the removed items from start to end. The element range is
    /// removed even if the iterator is not consumed until the end.
    ///
    /// Note: It is unspecified how many elements are removed from the vector,
    /// if the `Drain` value is leaked.
    ///
    /// **Panics** if the starting point is greater than the end point or if
    /// the end point is greater than the length of the vector.
    pub fn drain<R>(&mut self, range: R) -> Drain
    where
        R: RangeBounds<usize>,
    {
        // Memory safety
        //
        // When the Drain is first created, it shortens the length of
        // the source vector to make sure no uninitialized or moved-from elements
        // are accessible at all if the Drain's destructor never gets to run.
        //
        // Drain will ptr::read out the values to remove.
        // When finished, remaining tail of the vec is copied back to cover
        // the hole, and the vector length is restored to the new length.
        //
        let len = self.len();
        let start = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(&i) => i,
            Bound::Excluded(&i) => i.saturating_add(1),
        };
        let end = match range.end_bound() {
            Bound::Excluded(&j) => j,
            Bound::Included(&j) => j.saturating_add(1),
            Bound::Unbounded => len,
        };
        self.drain_range(start, end)
    }

    fn drain_range(&mut self, start: usize, end: usize) -> Drain {
        let len = self.len();

        // bounds check happens here (before length is changed!)
        let range_slice: *const _ = &self[start..end];

        // Calling `set_len` creates a fresh and thus unique mutable references, making all
        // older aliases we created invalid. So we cannot call that function.
        self.size = start;

        unsafe {
            Drain {
                tail_start: end,
                tail_len: len - end,
                iter: (*range_slice).iter(),
                vec: self,
            }
        }
    }

    /// Return a slice containing all elements of the vector.
    pub fn as_slice(&self) -> &[u8] {
        self
    }

    /// Return a mutable slice containing all elements of the vector.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self
    }

    /// Return a raw pointer to the vector's buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Return a raw mutable pointer to the vector's buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
}

impl Deref for Buffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len()) }
    }
}

impl DerefMut for Buffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        unsafe { slice::from_raw_parts_mut(self.ptr, len) }
    }
}

/// Iterate the `Buffer` with references to each element.
impl<'a> IntoIterator for &'a Buffer {
    type Item = &'a u8;
    type IntoIter = slice::Iter<'a, u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterate the `Buffer` with mutable references to each element.
impl<'a> IntoIterator for &'a mut Buffer {
    type Item = &'a mut u8;
    type IntoIter = slice::IterMut<'a, u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// Iterate the `Buffer` with each element by value.
///
/// The vector is consumed by this operation.
impl IntoIterator for Buffer {
    type Item = u8;
    type IntoIter = IntoIter;
    fn into_iter(self) -> IntoIter {
        IntoIter { index: 0, v: self }
    }
}

/// By-value iterator for `Buffer`.
pub struct IntoIter {
    index: usize,
    v: Buffer,
}

impl Iterator for IntoIter {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.index == self.v.len() {
            None
        } else {
            unsafe {
                let index = self.index;
                self.index = index + 1;
                Some(ptr::read(self.v.get_unchecked_ptr(index)))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.v.len() - self.index;
        (len, Some(len))
    }
}

impl DoubleEndedIterator for IntoIter {
    fn next_back(&mut self) -> Option<u8> {
        if self.index == self.v.len() {
            None
        } else {
            unsafe {
                let new_len = self.v.len() - 1;
                self.v.set_len(new_len);
                Some(ptr::read(self.v.get_unchecked_ptr(new_len)))
            }
        }
    }
}

impl ExactSizeIterator for IntoIter {}

impl fmt::Debug for IntoIter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(&self.v[self.index..]).finish()
    }
}

/// A draining iterator for `Buffer`.
#[derive(Debug)]
pub struct Drain<'a> {
    /// Index of tail to preserve
    tail_start: usize,
    /// Length of tail
    tail_len: usize,
    /// Current remaining range to remove
    iter: slice::Iter<'a, u8>,
    vec: &'a mut Buffer,
}

unsafe impl<'a> Sync for Drain<'a> {}
unsafe impl<'a> Send for Drain<'a> {}

impl<'a> Iterator for Drain<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|elt| unsafe { ptr::read(elt as *const _) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Drain<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter
            .next_back()
            .map(|elt| unsafe { ptr::read(elt as *const _) })
    }
}

impl<'a> ExactSizeIterator for Drain<'a> {}

impl<'a> Drop for Drain<'a> {
    fn drop(&mut self) {
        // len is currently 0 so panicking while dropping will not cause a double drop.

        // exhaust self first
        while let Some(_) = self.next() {}

        if self.tail_len > 0 {
            unsafe {
                let source_vec = &mut *self.vec;
                // memmove back untouched tail, update to new length
                let start = source_vec.len();
                let tail = self.tail_start;
                let src = source_vec.as_ptr().offset(tail as isize);
                let dst = source_vec.as_mut_ptr().offset(start as isize);
                ptr::copy(src, dst, self.tail_len);
                source_vec.set_len(start + self.tail_len);
            }
        }
    }
}

struct ScopeExitGuard<T, Data, F>
where
    F: FnMut(&Data, &mut T),
{
    value: T,
    data: Data,
    f: F,
}

impl<T, Data, F> Drop for ScopeExitGuard<T, Data, F>
where
    F: FnMut(&Data, &mut T),
{
    fn drop(&mut self) {
        (self.f)(&self.data, &mut self.value)
    }
}

/// Extend the `Buffer` with an iterator.
///
/// Does not extract more items than there is space for. No error
/// occurs if there are more iterator elements.
impl Extend<u8> for Buffer {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        let take = self.capacity() - self.len();
        unsafe {
            let len = self.len();
            let mut ptr = raw_ptr_add(self.as_mut_ptr(), len);
            let end_ptr = raw_ptr_add(ptr, take);
            // Keep the length in a separate variable, write it back on scope
            // exit. To help the compiler with alias analysis and stuff.
            // We update the length to handle panic in the iteration of the
            // user's iterator, without dropping any elements on the floor.
            let mut guard = ScopeExitGuard {
                value: &mut self.size,
                data: len,
                f: move |&len, self_len| {
                    **self_len = len;
                },
            };
            let mut iter = iter.into_iter();
            loop {
                if ptr == end_ptr {
                    break;
                }
                if let Some(elt) = iter.next() {
                    raw_ptr_write(ptr, elt);
                    ptr = raw_ptr_add(ptr, 1);
                    guard.data += 1;
                } else {
                    break;
                }
            }
        }
    }
}

/// Rawptr add but uses arithmetic distance for ZST
unsafe fn raw_ptr_add<T>(ptr: *mut T, offset: usize) -> *mut T {
    if mem::size_of::<T>() == 0 {
        // Special case for ZST
        (ptr as usize).wrapping_add(offset) as _
    } else {
        ptr.offset(offset as isize)
    }
}

unsafe fn raw_ptr_write<T>(ptr: *mut T, value: T) {
    if mem::size_of::<T>() == 0 {
        /* nothing */
    } else {
        ptr::write(ptr, value)
    }
}

impl Hash for Buffer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&**self, state)
    }
}

impl PartialEq for Buffer {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl PartialEq<[u8]> for Buffer {
    fn eq(&self, other: &[u8]) -> bool {
        **self == *other
    }
}

impl Eq for Buffer {}

impl Borrow<[u8]> for Buffer {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl BorrowMut<[u8]> for Buffer {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl PartialOrd for Buffer {
    fn partial_cmp(&self, other: &Buffer) -> Option<cmp::Ordering> {
        (**self).partial_cmp(other)
    }

    fn lt(&self, other: &Self) -> bool {
        (**self).lt(other)
    }

    fn le(&self, other: &Self) -> bool {
        (**self).le(other)
    }

    fn ge(&self, other: &Self) -> bool {
        (**self).ge(other)
    }

    fn gt(&self, other: &Self) -> bool {
        (**self).gt(other)
    }
}

impl Ord for Buffer {
    fn cmp(&self, other: &Buffer) -> cmp::Ordering {
        (**self).cmp(other)
    }
}
