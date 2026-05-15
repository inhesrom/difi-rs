mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{bytes, class_id, header};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

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
    let _guard = ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    // Exclude one-time runtime/test harness setup from the measured call.
    let _ = difi::parse_packet_exact(&input).expect("warm up parse");
    ALLOCATIONS.store(0, Ordering::SeqCst);
    let packet = difi::parse_packet_exact(&input).expect("valid data packet");
    let allocations = ALLOCATIONS.load(Ordering::SeqCst);

    assert!(matches!(packet, difi::Packet::SignalData(_)));
    assert_eq!(allocations, 0);
}

#[cfg(feature = "write")]
#[test]
fn valid_write_path_allocates_zero_times() {
    let _guard = ALLOCATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let packet = difi::parse_packet_exact(&input).expect("valid data packet");
    let mut out = [0_u8; 32];
    // Exclude one-time runtime/test harness setup from the measured call.
    let _ = difi::writer::write_packet(&packet, &mut out).expect("warm up write data packet");

    ALLOCATIONS.store(0, Ordering::SeqCst);
    let written = difi::writer::write_packet(&packet, &mut out).expect("write data packet");
    let allocations = ALLOCATIONS.load(Ordering::SeqCst);

    assert_eq!(written, input.len());
    assert_eq!(out.as_slice(), input.as_slice());
    assert_eq!(allocations, 0);
}
