//! Intrusive FIFO queue with O(1) push/pop.
//!
//! Nodes embed a [`QueueLink`] and implement [`QueueNode`]. The `Tag` type parameter
//! enables a single node to participate in multiple queues simultaneously by using
//! different tags for each link.
//!
//! # Safety
//!
//! This is an intrusive data structure using raw pointers. Callers must ensure:
//! - Nodes outlive any queue they're pushed to
//! - Nodes are not moved while in a queue
//! - [`Queue::reset`] callers manually reset node links via [`QueueLink::reset`]

use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::NonNull;

// Compile-time: verify u32 fits in usize
const _: () = assert!(
    size_of::<usize>() >= size_of::<u32>(),
    "Platform must have at least 32-bit addressing"
);

/// Intrusive link embedded in queue nodes.
///
/// Use different `Tag` types to allow a node to be in multiple queues.
#[derive(Debug)]
pub struct QueueLink<T, Tag> {
    next: Option<NonNull<T>>,
    /// Tracks whether this node is currently in a queue.
    /// Required because tail nodes have `next = None`, which would otherwise
    /// be indistinguishable from an unlinked node.
    linked: bool,
    _tag: PhantomData<Tag>,
}

impl<T, Tag> QueueLink<T, Tag> {
    pub const fn new() -> Self {
        Self {
            next: None,
            linked: false,
            _tag: PhantomData,
        }
    }

    /// Returns `true` if this node is not in any queue.
    #[inline]
    pub fn is_unlinked(&self) -> bool {
        !self.linked
    }

    /// Manually reset this link after [`Queue::reset`].
    ///
    /// `Queue::reset` does not clear node links for performance. Call this
    /// on each node before reuse if the queue was reset rather than drained.
    ///
    /// # Safety Note
    /// Calling this on a node still in an active (non-reset) queue will corrupt
    /// the queue. Only call after `Queue::reset()` or on unlinked nodes.
    pub fn reset(&mut self) {
        self.next = None;
        self.linked = false;

        assert!(self.is_unlinked());
    }

    /// Internal: clear link state when popped.
    #[inline]
    pub(crate) fn unlink(&mut self) {
        self.next = None;
        self.linked = false;

        assert!(self.is_unlinked());
    }
}

impl<T, Tag> Default for QueueLink<T, Tag> {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for types that can be stored in a [`Queue`].
///
/// Implementors must provide access to an embedded [`QueueLink`] field.
pub trait QueueNode<Tag>: Sized {
    fn queue_link(&mut self) -> &mut QueueLink<Self, Tag>;
    fn queue_link_ref(&self) -> &QueueLink<Self, Tag>;
}

/// Intrusive FIFO queue.
///
/// Uses `u32` length for 32/64-bit portability. Panics on overflow (> 4B nodes).
#[derive(Debug)]
pub struct Queue<T, Tag>
where
    T: QueueNode<Tag>,
{
    head: Option<NonNull<T>>,
    tail: Option<NonNull<T>>,
    len: u32,
    _tag: PhantomData<Tag>,
}

impl<T, Tag> Default for Queue<T, Tag>
where
    T: QueueNode<Tag>,
{
    fn default() -> Self {
        Self::init()
    }
}

impl<T, Tag> Queue<T, Tag>
where
    T: QueueNode<Tag>,
{
    pub fn init() -> Self {
        Self {
            head: None,
            tail: None,
            len: 0,
            _tag: PhantomData,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        let empty = self.head.is_none();

        assert!(empty == (self.tail.is_none()));
        assert!(empty == (self.len == 0));

        empty
    }

    #[inline]
    pub fn len(&self) -> u32 {
        assert!((self.len == 0) == self.tail.is_none());
        assert!((self.len == 0) == self.head.is_none());

        self.len
    }

    /// Returns the head node without removing it.
    #[inline]
    pub fn peek(&self) -> Option<NonNull<T>> {
        self.head
    }

    /// Transfer all nodes to a new queue, leaving `self` empty.
    pub fn take_all(&mut self) -> Self {
        let old_len = self.len;
        let old_head = self.head;

        let taken = core::mem::take(self);

        assert!(self.is_empty());
        assert!(self.len == 0);
        assert!(self.head.is_none());
        assert!(self.tail.is_none());

        assert!(taken.len() == old_len);
        assert!(taken.head == old_head);

        taken
    }

    /// Reset to empty without draining nodes.
    ///
    /// # Warning
    /// Does **not** clear node links. Caller must call [`QueueLink::reset`] on
    /// each node before reuse, or nodes will panic on re-push.
    pub fn reset(&mut self) {
        *self = Self::init();

        assert!(self.is_empty());

        assert!(self.len == 0);
    }

    /// Add a node to the back of the queue.
    ///
    /// # Panics
    /// - If `node` is already in a queue (linked)
    /// - If queue length would overflow `u32::MAX`
    pub fn push(&mut self, node: &mut T) {
        let old_len = self.len;

        assert!(
            node.queue_link_ref().is_unlinked(),
            "pushing already-linked node"
        );
        assert!(old_len < u32::MAX, "queue length overflow");

        let node_ptr = NonNull::from(&mut *node);
        let link = node.queue_link();
        link.next = None;
        link.linked = true;

        match self.tail {
            None => {
                assert!(self.head.is_none());
                assert!(self.len == 0);

                self.head = Some(node_ptr);
                self.tail = Some(node_ptr);
            }
            Some(mut tail_ptr) => {
                assert!(self.head.is_some());
                assert!(self.len > 0);

                unsafe {
                    let tail = tail_ptr.as_mut();
                    // Tail's next should be None (it's the end of the queue)
                    assert!(tail.queue_link_ref().next.is_none());

                    tail.queue_link().next = Some(node_ptr);
                }
                self.tail = Some(node_ptr);
            }
        }

        self.len += 1;

        assert!(self.len == old_len + 1);
        assert!(self.tail == Some(node_ptr));
        assert!(!self.is_empty());
    }

    /// Remove and return the front node, or `None` if empty.
    ///
    /// The returned node is unlinked and safe to re-push.
    pub fn pop(&mut self) -> Option<NonNull<T>> {
        let mut head_ptr = self.head?;
        let old_len = self.len;

        assert!(old_len > 0);

        let next = unsafe { head_ptr.as_ref().queue_link_ref().next };
        self.head = next;

        if self.head.is_none() {
            // Queue is now empty.
            self.tail = None;
        }

        // Decrement length before calling any methods that check invariants
        self.len -= 1;

        // Clear the node's link state
        unsafe { head_ptr.as_mut().queue_link().unlink() }

        assert!(self.len == old_len - 1);
        assert!(self.is_empty() == (self.len == 0));
        assert!((self.head.is_none()) == (self.tail.is_none()));

        Some(head_ptr)
    }

    /// O(n) search for `node`. Intended for debugging/assertions.
    pub fn contains(&self, node: &T) -> bool {
        let target = node as *const T;
        let mut current = self.head;

        let mut visited: u32 = 0;

        while let Some(ptr) = current {
            // Safety check: detect infinite loops
            visited += 1;
            assert!(visited <= self.len, "cycle detected in queue");

            if core::ptr::eq(ptr.as_ptr(), target) {
                return true;
            }

            // SAFETY: ptr is valid (part of our queue)
            current = unsafe { ptr.as_ref().queue_link_ref().next };
        }

        false
    }

    /// Panic if internal invariants are violated. Debug builds only.
    #[cfg(debug_assertions)]
    pub fn check_invariants(&self) {
        // Empty queue checks
        if self.len == 0 {
            assert!(self.head.is_none(), "len=0 but head is Some");
            assert!(self.tail.is_none(), "len=0 but tail is Some");
            return;
        }

        // Non-empty queue checks
        assert!(self.head.is_some(), "len>0 but head is None");
        assert!(self.tail.is_some(), "len>0 but tail is None");

        // Walk the list and count
        let mut count: u32 = 0;
        let mut current = self.head;
        let mut last: Option<NonNull<T>> = None;

        while let Some(ptr) = current {
            count += 1;
            assert!(count <= self.len, "more nodes than len indicates");

            last = current;

            // SAFETY: ptr is valid
            current = unsafe { ptr.as_ref().queue_link_ref().next };
        }

        // Count matches len
        assert!(
            count == self.len,
            "counted {} nodes but len is {}",
            count,
            self.len
        );

        // Last node is tail
        assert!(last == self.tail, "last node is not tail");

        // Tail's next is None
        if let Some(tail) = self.tail {
            // SAFETY: tail is valid
            let tail_next = unsafe { tail.as_ref().queue_link_ref().next };
            assert!(tail_next.is_none(), "tail's next is not None");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    enum QTag {}

    impl std::fmt::Debug for QTag {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "QTag")
        }
    }

    #[derive(Debug)]
    struct Node {
        value: u32,
        link: QueueLink<Node, QTag>,
    }

    impl Node {
        fn new(value: u32) -> Self {
            Self {
                value,
                link: QueueLink::new(),
            }
        }
    }

    impl QueueNode<QTag> for Node {
        fn queue_link(&mut self) -> &mut QueueLink<Self, QTag> {
            &mut self.link
        }
        fn queue_link_ref(&self) -> &QueueLink<Self, QTag> {
            &self.link
        }
    }

    #[test]
    fn init() {
        let q: Queue<Node, QTag> = Queue::init();

        assert!(q.is_empty());
        assert!(q.is_empty());
        assert!(q.peek().is_none());
    }

    #[test]
    fn peek_returns_head_in_multi_element_queue() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        q.push(&mut a);
        q.push(&mut b);
        q.push(&mut c);

        // Peek should return head (value 1), not tail (value 3)
        let peeked = q.peek().unwrap();
        assert!(unsafe { peeked.as_ref().value } == 1);

        // Verify it's actually the head by checking pop returns same node
        let popped = q.pop().unwrap();
        assert!(peeked == popped);
    }

    #[test]
    #[should_panic(expected = "pushing already-linked node")]
    fn push_linked_panics() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);

        q.push(&mut a);
        q.push(&mut a); // Should panic - already linked
    }

    // ==================== Boundary Condition Tests ====================

    #[test]
    fn peek_empty() {
        let q: Queue<Node, QTag> = Queue::init();
        assert!(q.peek().is_none());
    }

    #[test]
    fn contains_empty() {
        let q: Queue<Node, QTag> = Queue::init();
        let a = Node::new(1);
        assert!(!q.contains(&a));
    }

    #[test]
    fn default() {
        let q: Queue<Node, QTag> = Queue::default();
        assert!(q.is_empty());
        assert!(q.is_empty());
    }

    // ==================== QueueLink Direct API Tests ====================

    #[test]
    fn link_default() {
        let link1: QueueLink<Node, QTag> = QueueLink::new();
        let link2: QueueLink<Node, QTag> = QueueLink::default();
        assert!(link1.is_unlinked());
        assert!(link2.is_unlinked());
    }

    #[test]
    fn link_reset() {
        let mut link: QueueLink<Node, QTag> = QueueLink::new();
        link.reset();
        assert!(link.is_unlinked());
        link.reset(); // Should work multiple times
        assert!(link.is_unlinked());
    }

    // ==================== State Transition Tests ====================

    #[test]
    fn pop_until_empty() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        q.push(&mut a);
        q.push(&mut b);
        q.push(&mut c);

        // len=3, head=Some, tail=Some
        assert!(q.len() == 3);
        assert!(!q.is_empty());

        q.pop();
        // len=2, head=Some, tail=Some
        assert!(q.len() == 2);
        assert!(!q.is_empty());

        q.pop();
        // len=1, head=Some, tail=Some, head==tail
        assert!(q.len() == 1);
        assert!(!q.is_empty());

        q.pop();
        // len=0, head=None, tail=None
        assert!(q.is_empty());
        assert!(q.is_empty());
    }

    #[test]
    fn head_is_tail() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);

        q.push(&mut a);

        assert!(q.head == q.tail);
        assert!(q.len() == 1);
    }

    // ==================== Re-push After Pop Tests ====================

    // ==================== Double-Push Detection Tests ====================

    #[test]
    #[should_panic(expected = "pushing already-linked node")]
    fn push_tail_panics() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        q.push(&mut a);
        q.push(&mut b); // b is now tail (next = None)
        q.push(&mut b); // Should panic - b is still linked even though next is None
    }

    #[test]
    #[should_panic(expected = "pushing already-linked node")]
    fn push_head_panics() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        q.push(&mut a); // a is head
        q.push(&mut b);
        q.push(&mut a); // Should panic - a is head with next pointing to b
    }

    #[test]
    #[should_panic(expected = "pushing already-linked node")]
    fn push_middle_panics() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        q.push(&mut a);
        q.push(&mut b); // b is middle
        q.push(&mut c);
        q.push(&mut b); // Should panic
    }

    #[test]
    #[should_panic(expected = "pushing already-linked node")]
    fn push_to_different_queue_same_tag_panics() {
        let mut q1: Queue<Node, QTag> = Queue::init();
        let mut q2: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);

        q1.push(&mut a);
        q2.push(&mut a); // Should panic - same tag, already linked
    }

    #[test]
    #[should_panic(expected = "pushing already-linked node")]
    fn reset_then_repush_without_link_reset_panics() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);

        q.push(&mut a);
        q.reset(); // Queue empty, but a.link still marked as linked

        q.push(&mut a); // Should panic - link not reset
    }

    #[test]
    #[should_panic(expected = "cycle detected in queue")]
    fn contains_detects_cycle() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        q.push(&mut a);
        q.push(&mut b);

        // Manually create a cycle: b.next -> a (instead of None)
        // This is intentionally creating invalid state for testing
        let a_ptr = NonNull::from(&mut a);
        b.link.next = Some(a_ptr);
        let _ = &b; // Keep b alive; the cycle is traversed via queue's internal pointers

        let c = Node::new(999);
        // contains will traverse: a -> b -> a -> b -> ... and should panic
        let _ = q.contains(&c);
    }

    // ==================== Contains Edge Cases ====================

    #[test]
    fn contains_single() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);

        q.push(&mut a);
        assert!(q.contains(&a));
    }

    #[test]
    fn contains_traversal() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        q.push(&mut a);
        q.push(&mut b);
        q.push(&mut c);

        assert!(q.contains(&a)); // head
        assert!(q.contains(&b)); // middle
        assert!(q.contains(&c)); // tail
    }

    #[test]
    fn contains_popped() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        q.push(&mut a);
        q.push(&mut b);

        let _popped = q.pop();

        assert!(!q.contains(&a)); // Was popped
        assert!(q.contains(&b)); // Still in queue
    }

    // ==================== Multiple Operations Sequences ====================

    #[test]
    fn take_all_twice() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);

        q.push(&mut a);
        let taken1 = q.take_all();
        let taken2 = q.take_all(); // Should work on empty queue

        assert!(taken1.len() == 1);
        assert!(taken2.is_empty());
    }

    #[test]
    fn push_after_take_all() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        q.push(&mut a);
        let mut taken = q.take_all();

        // Pop from taken to unlink a
        taken.pop();

        // Original queue should work normally
        q.push(&mut b);
        assert!(q.len() == 1);
        assert!(unsafe { q.pop().unwrap().as_ref().value } == 2);
    }

    #[test]
    fn reset_partial() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);
        let mut c = Node::new(3);

        q.push(&mut a);
        q.push(&mut b);
        q.push(&mut c);
        q.pop(); // Pop a

        assert!(q.len() == 2);
        q.reset();
        assert!(q.is_empty());
        assert!(q.is_empty());
    }

    #[test]
    fn alternating() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut nodes: [Node; 10] = core::array::from_fn(|i| Node::new(i as u32));

        for (i, node) in nodes.iter_mut().enumerate() {
            q.push(node);
            assert!(q.len() == 1);

            let ptr = q.pop().unwrap();
            assert!(unsafe { ptr.as_ref().value } == i as u32);
            assert!(q.is_empty());
        }
    }

    // ==================== Large Queue Tests ====================

    #[test]
    fn large_queue() {
        let mut q: Queue<Node, QTag> = Queue::init();
        const COUNT: usize = 1000;
        let mut nodes: Vec<Node> = (0..COUNT).map(|i| Node::new(i as u32)).collect();

        // Push all
        for node in &mut nodes {
            q.push(node);
        }
        assert!(q.len() == COUNT as u32);

        // Pop all and verify order
        for i in 0..COUNT {
            let ptr = q.pop().unwrap();
            assert!(unsafe { ptr.as_ref().value } == i as u32);
        }
        assert!(q.is_empty());
    }

    #[test]
    fn contains_large() {
        let mut q: Queue<Node, QTag> = Queue::init();
        const COUNT: usize = 100;
        let mut nodes: Vec<Node> = (0..COUNT).map(|i| Node::new(i as u32)).collect();
        let not_in_queue = Node::new(999);

        for node in &mut nodes {
            q.push(node);
        }

        // Check first, middle, last
        assert!(q.contains(&nodes[0]));
        assert!(q.contains(&nodes[COUNT / 2]));
        assert!(q.contains(&nodes[COUNT - 1]));
        assert!(!q.contains(&not_in_queue));
    }

    // ==================== Reset Warning Tests ====================

    #[test]
    fn reset_links_intact() {
        let mut q: Queue<Node, QTag> = Queue::init();
        let mut a = Node::new(1);
        let mut b = Node::new(2);

        q.push(&mut a);
        q.push(&mut b);

        // a.link.next should point to b
        assert!(!a.link.is_unlinked()); // a is linked

        q.reset();

        // Queue is empty
        assert!(q.is_empty());

        // WARNING: Node links are NOT cleared by reset()
        // This is documented behavior - nodes still think they're linked
        assert!(!a.link.is_unlinked());
        assert!(!b.link.is_unlinked());

        // Caller must manually reset links if needed
        a.link.reset();
        b.link.reset();
        assert!(a.link.is_unlinked());
        assert!(b.link.is_unlinked());
    }

    // ==================== Multiple Tag Types ====================

    #[test]
    fn multiple_tags() {
        #[derive(Debug)]
        enum Tag1 {}
        #[derive(Debug)]
        enum Tag2 {}

        #[derive(Debug)]
        struct DualNode {
            value: u32,
            link1: QueueLink<DualNode, Tag1>,
            link2: QueueLink<DualNode, Tag2>,
        }

        impl QueueNode<Tag1> for DualNode {
            fn queue_link(&mut self) -> &mut QueueLink<Self, Tag1> {
                &mut self.link1
            }
            fn queue_link_ref(&self) -> &QueueLink<Self, Tag1> {
                &self.link1
            }
        }

        impl QueueNode<Tag2> for DualNode {
            fn queue_link(&mut self) -> &mut QueueLink<Self, Tag2> {
                &mut self.link2
            }
            fn queue_link_ref(&self) -> &QueueLink<Self, Tag2> {
                &self.link2
            }
        }

        let mut q1: Queue<DualNode, Tag1> = Queue::init();
        let mut q2: Queue<DualNode, Tag2> = Queue::init();
        let mut node = DualNode {
            value: 42,
            link1: QueueLink::new(),
            link2: QueueLink::new(),
        };

        // Same node can be in two queues with different tags
        q1.push(&mut node);
        q2.push(&mut node);

        assert!(q1.len() == 1);
        assert!(q2.len() == 1);
        assert!(q1.contains(&node));
        assert!(q2.contains(&node));

        // Pop from both
        let ptr1 = q1.pop().unwrap();
        let ptr2 = q2.pop().unwrap();

        assert!(unsafe { ptr1.as_ref().value } == 42);
        assert!(unsafe { ptr2.as_ref().value } == 42);
        assert!(node.link1.is_unlinked());
        assert!(node.link2.is_unlinked());
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;

    const PROPTEST_CASES: u32 = 16;

    enum PTag {}

    impl core::fmt::Debug for PTag {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "PTag")
        }
    }

    #[derive(Debug)]
    struct PNode {
        value: u32,
        link: QueueLink<PNode, PTag>,
    }

    impl PNode {
        fn new(value: u32) -> Self {
            Self {
                value,
                link: QueueLink::new(),
            }
        }
    }

    impl QueueNode<PTag> for PNode {
        fn queue_link(&mut self) -> &mut QueueLink<Self, PTag> {
            &mut self.link
        }
        fn queue_link_ref(&self) -> &QueueLink<Self, PTag> {
            &self.link
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Op {
        Push(usize), // Index into node pool
        Pop,
        Reset,
        TakeAll,
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        /// FIFO ordering is preserved regardless of queue size.
        #[test]
        fn fifo(values in prop::collection::vec(any::<u32>(), 0..100)) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = values.iter().map(|&v| PNode::new(v)).collect();

            for node in &mut nodes {
                q.push(node);
            }

            for expected in &values {
                let popped = q.pop().unwrap();
                prop_assert_eq!(unsafe { popped.as_ref().value }, *expected);
            }

            prop_assert!(q.is_empty());
        }

        /// Length is always accurate after any sequence of operations.
        #[test]
        fn len(ops in prop::collection::vec(prop::bool::ANY, 0..200)) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = (0..200).map(PNode::new).collect();
            let mut expected_len: u32 = 0;
            let mut push_idx = 0;

            for &should_push in &ops {
                if should_push && push_idx < nodes.len() {
                    q.push(&mut nodes[push_idx]);
                    push_idx += 1;
                    expected_len += 1;
                } else if !should_push && expected_len > 0 {
                    q.pop();
                    expected_len -= 1;
                }

                prop_assert_eq!(q.len(), expected_len);
            }
        }

        /// Contains returns true for pushed nodes, false for others.
        #[test]
        fn contains(
            push_count in 1..50usize,
            check_idx in 0..50usize,
        ) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = (0..50).map(PNode::new).collect();

            // Push first push_count nodes
            for node in nodes.iter_mut().take(push_count) {
                q.push(node);
            }

            let check_idx = check_idx % 50;

            if check_idx < push_count {
                prop_assert!(q.contains(&nodes[check_idx]));
            } else {
                prop_assert!(!q.contains(&nodes[check_idx]));
            }
        }

        /// Peek is stable - returns same value without removing.
        #[test]
        fn peek(values in prop::collection::vec(any::<u32>(), 1..100)) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = values.iter().map(|&v| PNode::new(v)).collect();

            for node in &mut nodes {
                q.push(node);
            }

            let peek1 = q.peek();
            let peek2 = q.peek();
            let peek3 = q.peek();

            prop_assert_eq!(peek1, peek2);
            prop_assert_eq!(peek2, peek3);
            prop_assert_eq!(q.len(), values.len() as u32);
        }

        /// Invariants hold after any valid operation sequence.
        #[test]
        #[cfg(debug_assertions)]
        fn invariants(ops in prop::collection::vec(prop::bool::ANY, 0..200)) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = (0..200).map(PNode::new).collect();
            let mut push_idx = 0;

            for &should_push in &ops {
                if should_push && push_idx < nodes.len() {
                    q.push(&mut nodes[push_idx]);
                    push_idx += 1;
                } else if !q.is_empty() {
                    q.pop();
                }

                q.check_invariants(); // Should never panic
            }
        }

        /// Popped nodes are always unlinked.
        #[test]
        fn pop_unlinks(count in 1..100usize) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = (0..count).map(|i| PNode::new(i as u32)).collect();

            for node in &mut nodes {
                q.push(node);
            }

            for _ in 0..count {
                let ptr = q.pop().unwrap();
                let is_unlinked = unsafe { ptr.as_ref().link.is_unlinked() };
                prop_assert!(is_unlinked, "popped node should be unlinked");
            }
        }

        /// Empty checks are consistent with length.
        #[test]
        fn empty(ops in prop::collection::vec(prop::bool::ANY, 0..100)) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = (0..100).map(PNode::new).collect();
            let mut push_idx = 0;

            for &should_push in &ops {
                if should_push && push_idx < nodes.len() {
                    q.push(&mut nodes[push_idx]);
                    push_idx += 1;
                } else if !q.is_empty() {
                    q.pop();
                }

                prop_assert_eq!(q.is_empty(), q.is_empty());
            }
        }

        /// Take_all transfers exactly all elements.
        #[test]
        fn take_all(count in 0..50usize) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<PNode> = (0..count).map(|i| PNode::new(i as u32)).collect();

            for node in &mut nodes {
                q.push(node);
            }

            let original_len = q.len();
            let taken = q.take_all();

            prop_assert!(q.is_empty());
            prop_assert_eq!(taken.len(), original_len);
        }

        /// Nodes can be re-pushed after being popped.
        #[test]
        fn repush(iterations in 1..20usize) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut node = PNode::new(42);

            for _ in 0..iterations {
                prop_assert!(node.link.is_unlinked());
                q.push(&mut node);
                prop_assert!(!node.link.is_unlinked());
                prop_assert_eq!(q.len(), 1);

                let ptr = q.pop().unwrap();
                prop_assert_eq!(unsafe { ptr.as_ref().value }, 42);
                prop_assert!(node.link.is_unlinked());
            }
        }

        /// Model matches implementation statefully
        #[test]
        fn model(
            ops in prop::collection::vec(prop_oneof![
                (0usize..10).prop_map(Op::Push),
                Just(Op::Pop),
                Just(Op::Reset),
                Just(Op::TakeAll),
            ], 1..200)
        ) {
            let mut q: Queue<PNode, PTag> = Queue::init();
            let mut nodes: Vec<Box<PNode>> = (0..10).map(|i| Box::new(PNode::new(i as u32))).collect();
            // Track which nodes are currently in the queue to avoid double-push panics
            // and to know which ones to reset.
            let mut in_queue = [false; 10];
            let mut shadow = VecDeque::new();

            for op in ops {
                match op {
                    Op::Push(idx) => {
                        let idx = idx % nodes.len();
                        if !in_queue[idx] {
                            q.push(&mut nodes[idx]);
                            shadow.push_back(nodes[idx].value);
                            in_queue[idx] = true;
                        }
                    }
                    Op::Pop => {
                        let res = q.pop();
                        if let Some(ptr) = res {
                            let val = unsafe { ptr.as_ref().value };
                            // Find which node this was (by value, since value == index)
                            let idx = val as usize;
                            prop_assert!(in_queue[idx]);
                            in_queue[idx] = false;

                            let shadow_val = shadow.pop_front();
                            prop_assert_eq!(Some(val), shadow_val);
                        } else {
                            prop_assert!(shadow.is_empty());
                        }
                    }
                    Op::Reset => {
                        q.reset();
                        shadow.clear();
                        // Mimic user cleanup: reset links for all nodes that were in queue
                        for i in 0..nodes.len() {
                            if in_queue[i] {
                                nodes[i].link.reset();
                                in_queue[i] = false;
                            }
                        }
                    }
                    Op::TakeAll => {
                        let mut taken = q.take_all();
                        let mut taken_vals = Vec::new();
                        while let Some(ptr) = taken.pop() {
                             let val = unsafe { ptr.as_ref().value };
                             taken_vals.push(val);
                             // The node is now unlinked because taken.pop() unlinks it
                             let idx = val as usize;
                             in_queue[idx] = false;
                        }

                        // Compare taken_vals with shadow
                        prop_assert_eq!(taken_vals.len(), shadow.len());
                        for (a, b) in taken_vals.iter().zip(shadow.iter()) {
                             prop_assert_eq!(a, b);
                        }

                        shadow.clear();
                        prop_assert!(q.is_empty());
                    }
                }

                // Invariant checks
                prop_assert_eq!(q.len() as usize, shadow.len());
                prop_assert_eq!(q.is_empty(), shadow.is_empty());
            }
        }
    }
}
