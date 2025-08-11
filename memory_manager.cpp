#include <cstdint>
#include <algorithm>
#include <vector>
#include <string>
#include <iostream>
#include <random>
#include <chrono>
#include <list>
#include <stdexcept>
#include <fstream>

// Page Table Entry
struct PageTableEntry {
    uint32_t frame_address; // Physical frame address (base of 4KB page)
    bool present;           // Page is in memory
    bool writable;          // Write permission
    bool executable;        // Execute permission
};

// Segment Table Entry
struct Segment {
    uint32_t base_address;  // Virtual base address
    uint32_t limit;         // Size of segment
    std::string type;       // "code", "data", "stack", "heap"
    bool writable;          // Write permission
    std::vector<PageTableEntry> page_table; // Pages within segment
};

// Memory Manager
class MemoryManager {
private:
    static const uint32_t PAGE_SIZE = 4096; // 4KB pages
    static const uint32_t PHYSICAL_MEMORY_SIZE = 64 * 1024 * 1024; // 64MB
    std::vector<uint8_t> physical_memory; // Simulated physical memory
    std::vector<Segment> segment_table;    // Segment table
    std::vector<bool> frame_bitmap;        // Track free/used frames
    std::list<uint32_t> lru_list;         // LRU list for page replacement
    static const uint32_t MAX_FRAMES = PHYSICAL_MEMORY_SIZE / PAGE_SIZE;
    std::ofstream log_file; // Non-static log file member

public:
    MemoryManager() : physical_memory(PHYSICAL_MEMORY_SIZE), 
                      frame_bitmap(PHYSICAL_MEMORY_SIZE / PAGE_SIZE, false), 
                      log_file() {}

    // Get segment and frame data for analysis
    const std::vector<Segment>& get_segment_table() const { return segment_table; }
    const std::vector<bool>& get_frame_bitmap() const { return frame_bitmap; }

    // Static accessor for PAGE_SIZE
    static uint32_t get_page_size() { return PAGE_SIZE; }

    // Initialize a new segment
    void create_segment(std::string type, uint32_t size, bool writable) {
        Segment seg;
        seg.base_address = segment_table.empty() ? 0 : 
                          segment_table.back().base_address + segment_table.back().limit;
        seg.limit = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1); // Align to page size
        seg.type = type;
        seg.writable = writable;
        seg.page_table.resize(seg.limit / PAGE_SIZE);
        segment_table.push_back(seg);
        allocate_pages(seg);
        if (log_file.is_open()) {
            log_file << "Created segment: type=" << type << ", base=" << seg.base_address 
                     << ", limit=" << seg.limit << ", writable=" << writable << "\n";
        }
    }

    // Allocate physical frames to a segment's pages
    void allocate_pages(Segment& seg) {
        for (size_t i = 0; i < seg.page_table.size(); ++i) {
            bool allocated = false;
            for (size_t j = 0; j < frame_bitmap.size(); ++j) {
                if (!frame_bitmap[j]) {
                    seg.page_table[i].frame_address = j * PAGE_SIZE;
                    seg.page_table[i].present = true;
                    seg.page_table[i].writable = seg.writable;
                    seg.page_table[i].executable = (seg.type == "code");
                    frame_bitmap[j] = true;
                    lru_list.push_front(j * PAGE_SIZE);
                    allocated = true;
                    if (log_file.is_open()) {
                        log_file << "Allocated page " << i << " to frame " << (j * PAGE_SIZE) << "\n";
                    }
                    break;
                }
            }
            if (!allocated) {
                handle_page_fault(seg, i);
            }
        }
    }

    // Handle page fault with LRU replacement
    void handle_page_fault(Segment& seg, uint32_t page_index) {
        if (log_file.is_open()) {
            log_file << "Page fault at segment " << seg.type << ", page " << page_index << "\n";
        }
        if (frame_bitmap.size() - std::count(frame_bitmap.begin(), frame_bitmap.end(), true) == 0) {
            uint32_t frame_to_evict = lru_list.back();
            lru_list.pop_back();
            frame_bitmap[frame_to_evict / PAGE_SIZE] = false;
            for (auto& s : segment_table) {
                for (auto& pte : s.page_table) {
                    if (pte.frame_address == frame_to_evict && pte.present) {
                        pte.present = false;
                        if (log_file.is_open()) {
                            log_file << "Evicted frame " << frame_to_evict << " from page " << &pte - &s.page_table[0] << "\n";
                        }
                        break;
                    }
                }
            }
        }
        for (size_t i = 0; i < frame_bitmap.size(); ++i) {
            if (!frame_bitmap[i]) {
                seg.page_table[page_index].frame_address = i * PAGE_SIZE;
                seg.page_table[page_index].present = true;
                seg.page_table[page_index].writable = seg.writable;
                seg.page_table[page_index].executable = (seg.type == "code");
                frame_bitmap[i] = true;
                lru_list.push_front(i * PAGE_SIZE);
                if (log_file.is_open()) {
                    log_file << "Allocated new frame " << (i * PAGE_SIZE) << " to page " << page_index << "\n";
                }
                break;
            }
        }
    }

    // Translate virtual address to physical address
    uint32_t translate_address(uint32_t virtual_address) {
        for (auto& seg : segment_table) {
            if (virtual_address >= seg.base_address && 
                virtual_address < seg.base_address + seg.limit) {
                uint32_t offset = virtual_address - seg.base_address;
                uint32_t page_index = offset / PAGE_SIZE;
                uint32_t page_offset = offset % PAGE_SIZE;
                if (log_file.is_open()) {
                    log_file << "Translating virtual " << virtual_address << ": segment=" << seg.type 
                             << ", page=" << page_index << ", offset=" << page_offset << "\n";
                }
                if (!seg.page_table[page_index].present) {
                    handle_page_fault(seg, page_index);
                }
                lru_list.remove(seg.page_table[page_index].frame_address);
                lru_list.push_front(seg.page_table[page_index].frame_address);
                return seg.page_table[page_index].frame_address + page_offset;
            }
        }
        throw std::runtime_error("Invalid virtual address");
    }

    // Read from memory with logging
    uint8_t read_memory(uint32_t virtual_address) {
        uint32_t physical_address = translate_address(virtual_address);
        if (log_file.is_open()) {
            log_file << "Read at virtual address " << virtual_address << " (physical: " 
                     << physical_address << ") = " << (int)physical_memory[physical_address] << "\n";
        }
        return physical_memory[physical_address];
    }

    // Write to memory with logging
    void write_memory(uint32_t virtual_address, uint8_t value) {
        uint32_t physical_address = translate_address(virtual_address);
        for (const auto& seg : segment_table) {
            if (virtual_address >= seg.base_address && 
                virtual_address < seg.base_address + seg.limit) {
                if (!seg.writable) {
                    throw std::runtime_error("Write to read-only segment");
                }
                physical_memory[physical_address] = value;
                if (log_file.is_open()) {
                    log_file << "Wrote " << (int)value << " at virtual address " << virtual_address 
                             << " (physical: " << physical_address << ")\n";
                }
                return;
            }
        }
    }

    // Public methods to control logging
    void open_log(const std::string& filename, bool append = false) {
        if (!log_file.is_open()) {
            log_file.open(filename.c_str(), append ? std::ios::app : std::ios::out);
        }
    }

    void write_log(const std::string& message) {
        if (log_file.is_open()) {
            log_file << message;
        }
    }

    void close_log() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }
};

// Simulate memory access with page-targeted testing
void simulate_memory_access(MemoryManager& mm, int iterations, bool log_enabled) {
    if (mm.get_segment_table().empty()) {
        std::cerr << "No segments defined. Please create at least one segment.\n";
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> seg_dist(0, mm.get_segment_table().size() - 1);
    std::uniform_int_distribution<uint32_t> page_dist(0, 10); // Limit to first 10 pages per segment

    int page_faults = 0;
    if (log_enabled) {
        mm.open_log("memory_log.txt");
    }

    for (int i = 0; i < iterations; ++i) {
        const auto& seg = mm.get_segment_table()[seg_dist(gen)];
        uint32_t page_index = page_dist(gen);
        if (page_index >= seg.page_table.size()) continue; // Skip if out of range
        uint32_t addr = seg.base_address + (page_index * MemoryManager::get_page_size()) + (gen() % MemoryManager::get_page_size());

        try {
            if (i % 2 == 0) {
                std::cout << "Read from page " << page_index << " in " << seg.type << " (addr " << addr << "): " 
                          << (int)mm.read_memory(addr) << std::endl;
            } else {
                mm.write_memory(addr, static_cast<uint8_t>(i % 256));
                std::cout << "Wrote " << (int)(i % 256) << " to page " << page_index << " in " << seg.type 
                          << " (addr " << addr << ")" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error at address " << addr << ": " << e.what() << std::endl;
            page_faults++;
        }
    }
    if (log_enabled) {
        mm.write_log("Simulation Page Faults: " + std::to_string(page_faults) + "\n");
        mm.close_log();
    }
    std::cout << "Simulation Page Faults: " << page_faults << std::endl;
}

// Test under memory pressure
void test_memory_pressure(MemoryManager& mm, int iterations, bool log_enabled) {
    if (mm.get_segment_table().empty()) {
        std::cerr << "No segments defined. Please create at least one segment.\n";
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> seg_dist(0, mm.get_segment_table().size() - 1);
    std::uniform_int_distribution<uint32_t> addr_dist(0, 80 * 1024 * 1024);

    int page_faults = 0;
    if (log_enabled) {
        mm.open_log("memory_log.txt", true); // Append mode
    }

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        const auto& seg = mm.get_segment_table()[seg_dist(gen)];
        uint32_t addr = seg.base_address + (addr_dist(gen) % seg.limit);
        try {
            mm.read_memory(addr);
        } catch (const std::exception& e) {
            page_faults++;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (log_enabled) {
        mm.write_log("Memory Pressure Page Faults: " + std::to_string(page_faults) + "\n");
        mm.write_log("Access Latency: " + std::to_string(duration) + " ms\n");
        mm.close_log();
    }
    std::cout << "Memory Pressure Page Faults: " << page_faults << std::endl;
    std::cout << "Access Latency: " << duration << " ms" << std::endl;
}

// Analyze fragmentation
void analyze_fragmentation(const MemoryManager& mm) {
    static const uint32_t PAGE_SIZE = 4096;
    uint32_t internal_fragmentation = 0;
    uint32_t free_frames = 0;
    uint32_t max_contiguous = 0, current_contiguous = 0;

    for (const auto& seg : mm.get_segment_table()) {
        for (const auto& pte : seg.page_table) {
            if (pte.present) {
                internal_fragmentation += PAGE_SIZE - 1024;
            }
        }
    }

    for (bool used : mm.get_frame_bitmap()) {
        if (!used) {
            free_frames++;
            current_contiguous++;
            max_contiguous = std::max(max_contiguous, current_contiguous);
        } else {
            current_contiguous = 0;
        }
    }

    std::cout << "Internal Fragmentation: " << internal_fragmentation / 1024 << " KB\n";
    std::cout << "External Fragmentation: " << free_frames * PAGE_SIZE / 1024 << " KB\n";
    std::cout << "Largest Contiguous Free Block: " << max_contiguous * PAGE_SIZE / 1024 << " KB\n";
}

// Main function
int main(int argc, char* argv[]) {
    MemoryManager mm;
    int sim_iterations = 1000;
    int pressure_iterations = 10000;
    bool log_enabled = false;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-s" && i + 1 < argc) sim_iterations = std::stoi(argv[++i]);
        else if (arg == "-p" && i + 1 < argc) pressure_iterations = std::stoi(argv[++i]);
        else if (arg == "-l") log_enabled = true;
        else if (arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  -s <iterations>  Set simulation iterations (default: 1000)\n"
                      << "  -p <iterations>  Set pressure test iterations (default: 10000)\n"
                      << "  -l              Enable logging to memory_log.txt\n"
                      << "  -h              Display this help\n";
            return 0;
        }
    }

    // User input for segments
    char add_more;
    do {
        std::string type;
        uint32_t size;
        bool writable;

        std::cout << "Enter segment type (code/data/stack/heap): ";
        std::cin >> type;
        std::cout << "Enter segment size (in bytes): ";
        std::cin >> size;
        std::cout << "Is it writable? (1 for yes, 0 for no): ";
        std::cin >> writable;

        mm.create_segment(type, size, writable);

        std::cout << "Add another segment? (y/n): ";
        std::cin >> add_more;
    } while (add_more == 'y' || add_more == 'Y');

    // User input for iterations (override command-line if provided)
    std::cout << "Enter number of simulation iterations (or press Enter for " << sim_iterations << "): ";
    std::string input;
    std::getline(std::cin >> std::ws, input);
    if (!input.empty()) sim_iterations = std::stoi(input);

    std::cout << "Enter number of pressure test iterations (or press Enter for " << pressure_iterations << "): ";
    std::getline(std::cin >> std::ws, input);
    if (!input.empty()) pressure_iterations = std::stoi(input);

    std::cout << "Running Memory Access Simulation (" << sim_iterations << " iterations)...\n";
    simulate_memory_access(mm, sim_iterations, log_enabled);
    std::cout << "\nRunning Memory Pressure Test (" << pressure_iterations << " iterations)...\n";
    test_memory_pressure(mm, pressure_iterations, log_enabled);
    std::cout << "\nAnalyzing Fragmentation...\n";
    analyze_fragmentation(mm);

    return 0;
}