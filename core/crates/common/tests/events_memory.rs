//! The memory a full blocked log holds, measured with a counting allocator. This file has a
//! single test so no other test allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use tollgate_common::events::{BlockEvent, EventKind, EventLog};

/// Bytes currently allocated through the global allocator.
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(new_size, Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[test]
fn a_full_log_of_long_urls_keeps_only_the_truncated_bytes() {
    let log = EventLog::new();
    let before = LIVE.load(Ordering::Relaxed);
    for i in 0..EventLog::CAPACITY {
        // Requests with long query strings: 64 KiB each, well within an HTTP/1 request line.
        let url = format!("https://ads.example/{i}?{}", "q".repeat(64 * 1024));
        log.record(BlockEvent {
            unix_secs: i as u64,
            kind: EventKind::Request,
            host: "ads.example".to_owned(),
            url: Some(url),
            source_host: Some("news.example".to_owned()),
        });
    }
    let held = LIVE.load(Ordering::Relaxed).saturating_sub(before);
    // Each event holds at most MAX_URL_BYTES of URL, two short hosts and its slot in the
    // ring buffer; 2 KiB per event leaves room for allocator rounding.
    let bound = EventLog::CAPACITY * 2 * 1024;
    assert!(
        held <= bound,
        "the log holds {held} bytes, more than {bound}"
    );
    assert_eq!(log.recent(1)[0].url.as_ref().unwrap().len(), 512);
}
