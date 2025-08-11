Virtual Memory Management Module (Paging + Segmentation)

📌 Project Overview

This project implements a simplified Virtual Memory Management System that combines paging and segmentation concepts.  

It simulates:

- Memory allocation
  
- Address translation

- Page fault handling (LRU replacement)

- Performance evaluation

- Fragmentation analysis

- Logging of memory operations

The implementation is written in **C++** and runs on both **Linux** and **Windows**.

---

## 🛠 Features
- **Segmentation**
  - Supports Code, Data, Stack, and Heap segments
  - Configurable size and write permissions
- **Paging**
  - Fixed **4KB** page size
  - 64MB simulated physical memory
  - Page table per segment
- **Page Fault Handling**
  - **Least Recently Used (LRU)** replacement policy
- **Logging**
  - Tracks allocations, faults, and accesses
  - Logs saved to `memory_log.txt`
- **Fragmentation Analysis**
  - Calculates internal and external fragmentation
- **Performance Testing**
  - Memory access simulation
  - Memory pressure testing with latency measurement

---

## 📂 Project Structure

memory_manager.cpp # Main source code

memory_log.txt # Log file (generated during execution)

README.md # Project documentation


---

## 🚀 How to Compile & Run

### On Linux
```bash
# Compile
g++ -std=c++11 memory_manager.cpp -o memory_manager

# Run
./memory_manager -l


On Windows (MinGW)
# Compile
g++ -std=c++11 memory_manager.cpp -o memory_manager.exe

# Run
.\memory_manager.exe -l


Command-line options:

-s <iterations> → Set simulation iterations (default: 1000)

-p <iterations> → Set pressure test iterations (default: 10000)

-l → Enable logging

-h → Display help

🖥 Example Run

=== Virtual Memory Management with Logging ===

1. Allocate Segment
2. Map Page
3. Write to Memory (Paged)
4. Read from Memory (Paged)
5. Exit
6. Unmap Page
7. Delete Segment
Enter your choice: 2
Enter Page Number (0-15): 2
Enter Frame Number (0-15): 2
Enter Access Right (0=no, 1=read, 2=write, 3=read/write): 3
Mapped page 2 to frame 2 with access 3



📊 Performance & Analysis
Internal Fragmentation: Tracks unused space within allocated pages.

External Fragmentation: Tracks contiguous free space availability.

Latency: Measures total access time under simulated workloads.


📜 License
This project is licensed under the MIT License – feel free to modify and share.

Author: Favour Adebisi Momoluwa
Date: 2025-07-23
