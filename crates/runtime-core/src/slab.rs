//! Generational operation slab — the memory-safety cornerstone of the runtime.
//!
//! Every in-flight io_uring operation owns a slot here. The slot index and a
//! per-slot generation counter are packed into the 64-bit `user_data` we hand the
//! kernel. When a CQE comes back we decode it and verify the generation still
//! matches: a completion for a slot that has since been freed and *reused* carries a
//! stale generation and is rejected, so a late/duplicate CQE can never be mistaken
//! for the current occupant. Combined with the rule that a slot is only freed once
//! its terminal CQE is accounted for, this is what makes dropping an in-flight future
//! safe (see `op` / the I/O futures).
//!
//! `user_data` layout: `(index as u64) << 32 | generation as u64`. Generations start
//! at 1 and are bumped on every (re)use, so a valid key is never `0` — leaving `0`
//! free as a sentinel for untracked internal ops (e.g. a bare nop).

/// A packed, generation-checked handle to a slot in an [`OpSlab`]. This is exactly
/// the value stored in `io_uring_sqe.user_data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpKey(u64);

impl OpKey {
    #[inline]
    fn new(index: u32, generation: u32) -> Self {
        OpKey((index as u64) << 32 | generation as u64)
    }

    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn from_u64(raw: u64) -> Self {
        OpKey(raw)
    }

    #[inline]
    fn index(self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[inline]
    fn generation(self) -> u32 {
        self.0 as u32
    }
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

/// A slab of live operations keyed by generation-checked [`OpKey`]s.
pub struct OpSlab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

impl<T> OpSlab<T> {
    pub fn new() -> Self {
        OpSlab {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        OpSlab {
            slots: Vec::with_capacity(cap),
            free: Vec::with_capacity(cap),
        }
    }

    /// Number of currently-occupied slots.
    pub fn len(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Store `value`, returning its generation-checked key. Reuses a free slot when
    /// available (bumping its generation so stale CQEs for the previous occupant are
    /// rejected), otherwise grows the slab.
    pub fn insert(&mut self, value: T) -> OpKey {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.generation = slot.generation.wrapping_add(1).max(1);
            slot.value = Some(value);
            OpKey::new(index, slot.generation)
        } else {
            let index = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: 1,
                value: Some(value),
            });
            OpKey::new(index, 1)
        }
    }

    /// Borrow the value for `key`, or `None` if the key is stale (slot freed/reused)
    /// or out of range.
    pub fn get_mut(&mut self, key: OpKey) -> Option<&mut T> {
        let slot = self.slots.get_mut(key.index() as usize)?;
        if slot.generation != key.generation() {
            return None;
        }
        slot.value.as_mut()
    }

    /// Remove and return the value for `key`, freeing the slot. Returns `None` for a
    /// stale key. The generation is bumped on free so any completion still in flight
    /// for this key can no longer match.
    pub fn remove(&mut self, key: OpKey) -> Option<T> {
        let slot = self.slots.get_mut(key.index() as usize)?;
        if slot.generation != key.generation() {
            return None;
        }
        let value = slot.value.take();
        if value.is_some() {
            slot.generation = slot.generation.wrapping_add(1).max(1);
            self.free.push(key.index());
        }
        value
    }

    /// Whether `key` currently refers to a live slot.
    pub fn contains(&self, key: OpKey) -> bool {
        self.slots
            .get(key.index() as usize)
            .is_some_and(|slot| slot.generation == key.generation() && slot.value.is_some())
    }
}

impl<T> Default for OpSlab<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_never_zero_so_zero_is_a_free_sentinel() {
        let mut slab: OpSlab<u32> = OpSlab::new();
        let key = slab.insert(7);
        assert_ne!(key.as_u64(), 0, "index 0 gen 1 must not encode to the 0 sentinel");
    }

    #[test]
    fn insert_get_remove_roundtrips() {
        let mut slab: OpSlab<&str> = OpSlab::new();
        let a = slab.insert("a");
        let b = slab.insert("b");
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.get_mut(a).copied(), Some("a"));
        assert_eq!(slab.get_mut(b).copied(), Some("b"));
        assert_eq!(slab.remove(a), Some("a"));
        assert_eq!(slab.len(), 1);
        assert!(slab.get_mut(a).is_none(), "removed key must not resolve");
    }

    /// The marquee slab invariant: after a slot is freed and reused, a completion
    /// carrying the OLD key is rejected, while the NEW occupant resolves.
    #[test]
    fn generation_reuse_rejects_stale_cqe() {
        let mut slab: OpSlab<u64> = OpSlab::new();
        let stale = slab.insert(100);
        assert_eq!(slab.remove(stale), Some(100));

        // Reuses the same slot index, but with a bumped generation.
        let fresh = slab.insert(200);
        assert_eq!(fresh.as_u64() >> 32, stale.as_u64() >> 32, "same slot index reused");
        assert_ne!(fresh.as_u64(), stale.as_u64(), "generation must differ");

        // A CQE for the stale key must not touch the fresh occupant.
        assert!(slab.get_mut(stale).is_none(), "stale key resolved to reused slot");
        assert!(slab.remove(stale).is_none(), "stale key removed the fresh op");
        assert_eq!(slab.get_mut(fresh).copied(), Some(200), "fresh key must still resolve");
    }

    #[test]
    fn double_remove_is_rejected() {
        let mut slab: OpSlab<u8> = OpSlab::new();
        let k = slab.insert(1);
        assert_eq!(slab.remove(k), Some(1));
        assert!(slab.remove(k).is_none(), "second remove of the same key must be a no-op");
    }

    #[test]
    fn out_of_range_key_is_rejected() {
        let mut slab: OpSlab<u8> = OpSlab::new();
        let bogus = OpKey::from_u64((999u64 << 32) | 1);
        assert!(slab.get_mut(bogus).is_none());
        assert!(slab.remove(bogus).is_none());
    }
}
