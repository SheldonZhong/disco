#include <iostream>
#include <fstream>
#include <list>
#include <unordered_map>
#include <cassert>
#include <cstdint>
#include <filesystem>

#include <getopt.h>

template<typename LBNType>
class LRU
{
    using LRUEntry = LBNType;
    using LRUList = std::list<LRUEntry>;
    using LRUIter = typename LRUList::iterator;
    using LRUMap = std::unordered_map<LBNType, LRUIter>;
private:
    LRUList list;
    LRUMap map;
    const size_t cache_capacity;
    size_t miss_count;
    size_t hit_count;
public:
    LRU(const size_t cache_capacity) :
        cache_capacity(cache_capacity), miss_count(0), hit_count(0)
    {
    }
    // return true on hit, false on miss
    bool Access(const LBNType lbn)
    {
        auto entry = map.find(lbn);
        if (entry == map.end())
        {
            // miss
            //std::cout << "miss " << lbn << std::endl;
            list.emplace_front(lbn);
            // insert the iter to the first element to the hash map
            // the iter is always valid when the list node moves
            auto ret = map.emplace(lbn, list.begin());
            assert(ret.second);
            // evict
            if (map.size() > cache_capacity)
            {
                //std::cout << "evict " << list.back() << std::endl;
                map.erase(list.back());
                list.pop_back();
            }
            miss_count++;
            return false;
        }
        else
        {
            //std::cout << "hit " << lbn << std::endl;
            // hit, move the entry to the front of the list
            list.splice(list.begin(), list, entry->second);
            hit_count++;
            return true;
        }
    }

    void report() {
      std::cout << "Capacity: " << cache_capacity
                << " miss count: " << miss_count
                << " hit count: " << hit_count
                << " total access: " << (miss_count + hit_count)
                << " miss ratio: " << (double)miss_count / (double)(miss_count + hit_count)
                << std::endl;
    }

    void report_csv(std::string filename) {
      // header
      // filename, cache_capacity, miss_count, hit_count, total_access
      std::cout << filename << ","
                << cache_capacity << ","
                << miss_count << ","
                << hit_count << ","
                << (miss_count + hit_count)
                << std::endl;
    }
};

int
main(int argc, char ** argv)
{
  if (argc < 1) {
    std::cout << "Usage " << argv[0] << " -c <cache capacity> -f <trace filename> [-v: csv]" << std::endl;
    return 0;
  }

  std::ifstream tracef;
  std::string filename = "";
  int cap = -1;
  bool csv = false;

  int opt;
  while ((opt = getopt(argc, argv, "c:f:v")) != -1) {
    switch (opt) {
      case 'c':
        cap = atoi(optarg);
        break;
      case 'f':
        filename = optarg;
        break;
      case 'v':
        csv = true;
        break;
      default:
        std::cout << "unknown argument" << std::endl;
        exit(1);
        break;
    }
  }

  if (cap < 0) {
    std::cout << "Capacity not given" << std::endl;
    exit(1);
  }
  LRU<uint32_t> lru(cap);

  tracef.open(filename);
  if (tracef.is_open()) {
    std::string line;
    while (std::getline(tracef, line)) {
      uint32_t num = stoul(line);
      lru.Access(num);
    }
    tracef.close();
  } else {
    std::cout << "trace file not given" << std::endl;
    exit(1);
  }

  if (csv) {
    lru.report_csv(std::filesystem::path(filename).filename());
  } else {
    lru.report();
  }
  return 0;
}
