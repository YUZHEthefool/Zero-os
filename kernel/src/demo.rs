//! 内核功能演示模块
//! 用于展示和测试各个子系统的功能

use mm::memory::{FrameAllocator, MemoryStats};

/// 演示改进后的内存管理系统
pub fn demo_memory_management() {
    println!("\n=== Memory Management Demo ===\n");
    
    // 创建帧分配器
    let mut allocator = FrameAllocator::new();
    
    // 演示1: 分配单个页面
    println!("1. Allocating single page...");
    if let Some(frame) = allocator.allocate_frame() {
        println!("   ✓ Allocated frame at: 0x{:x}", frame.start_address());
        
        // 释放页面
        allocator.deallocate_frame(frame);
        println!("   ✓ Frame deallocated");
    }
    
    // 演示2: 分配连续页面
    println!("\n2. Allocating 8 contiguous pages...");
    if let Some(frames) = allocator.allocate_contiguous_frames(8) {
        println!("   ✓ Allocated 8 frames starting at: 0x{:x}", frames.start_address());
        
        // 获取并显示统计信息
        let stats = allocator.stats();
        println!("   Memory usage after allocation:");
        println!("     - Used pages: {}", stats.used_physical_pages);
        println!("     - Free pages: {}", stats.free_physical_pages);
        
        // 释放连续页面
        allocator.deallocate_contiguous_frames(frames, 8);
        println!("   ✓ Frames deallocated");
    }
    
    // 演示3: 测试碎片整理
    println!("\n3. Testing fragmentation handling...");
    let mut allocated_frames = alloc::vec::Vec::new();
    
    // 分配多个不同大小的块
    for i in 0..5 {
        let size = 1 << i; // 1, 2, 4, 8, 16 pages
        if let Some(frame) = allocator.allocate_contiguous_frames(size) {
            println!("   ✓ Allocated {} pages at 0x{:x}", size, frame.start_address());
            allocated_frames.push((frame, size));
        }
    }
    
    // 显示碎片情况
    let stats = allocator.stats();
    println!("   Fragmentation: {}%", stats.fragmentation_percent);
    
    // 释放所有块
    println!("\n4. Releasing all allocated memory...");
    for (frame, size) in allocated_frames {
        allocator.deallocate_contiguous_frames(frame, size);
        println!("   ✓ Released {} pages", size);
    }
    
    // 最终统计
    println!("\n5. Final memory statistics:");
    let final_stats = allocator.stats();
    final_stats.print();
    
    println!("\n✓ Memory management demo completed!\n");
}

/// 演示堆分配
pub fn demo_heap_allocation() {
    use alloc::{vec, string::String, boxed::Box};
    
    println!("\n=== Heap Allocation Demo ===\n");
    
    // 演示Vec
    println!("1. Creating dynamic vector...");
    let mut v = vec![1, 2, 3, 4, 5];
    v.push(6);
    println!("   ✓ Vector created: {:?}", v);
    
    // 演示String
    println!("\n2. Creating dynamic string...");
    let mut s = String::from("Hello, ");
    s.push_str("Zero-OS!");
    println!("   ✓ String created: {}", s);
    
    // 演示Box
    println!("\n3. Creating boxed value...");
    let boxed_value = Box::new(42);
    println!("   ✓ Boxed value: {}", boxed_value);
    
    // 演示大量分配
    println!("\n4. Stress testing heap...");
    let mut vectors = alloc::vec::Vec::new();
    for i in 0..10 {
        let v = vec![i; 100]; // 每个Vec包含100个元素
        vectors.push(v);
    }
    println!("   ✓ Created {} vectors with 100 elements each", vectors.len());
    
    // 获取堆统计
    let stats = FrameAllocator::new().stats();
    println!("\n5. Heap statistics:");
    println!("   - Heap used: {} KB / {} KB", 
        stats.heap_used_bytes / 1024,
        stats.heap_total_bytes / 1024);
    
    println!("\n✓ Heap allocation demo completed!\n");
}

/// 运行所有演示
pub fn run_all_demos() {
    demo_memory_management();
    demo_heap_allocation();
}