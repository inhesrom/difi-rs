mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{bytes, class_id, header};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[test]
fn valid_parse_path_allocates_zero_times() {
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    let input = bytes(&[
        header(0x1, 0, 0x1, 0x2, 0, 8),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        0,
        0x0102_0304,
    ]);

    ALLOCATIONS.store(0, Ordering::SeqCst);
    let packet = difi::parse_packet_exact(&input).expect("valid data packet");
    let allocations = ALLOCATIONS.load(Ordering::SeqCst);

    assert!(matches!(packet, difi::Packet::SignalData(_)));
    assert_eq!(allocations, 0);
}
