#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <iostream>
#include <inttypes.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <stdlib.h>
#include <optional>
#include <filesystem>
#include <exception>
//#include <semaphore.h>
//#include <btrfs/ioctl.h>

#include <boost/utility/string_ref.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/program_options.hpp>
#include <rocksdb/db.h>
#include <openssl/md5.h>
#include <libmount/libmount.h>

namespace fs = std::filesystem;
namespace asio = boost::asio;
namespace po = boost::program_options;

class Realpath {
  private:
  char *p = nullptr;
  public:
  ~Realpath() {
    if (p) {
      free(p);
    }
  }
  Realpath(const char *path) {
    p = realpath(path, NULL);
    if (!p) {
      throw new std::runtime_error("realpath failed");
    }
  }
  operator boost::string_ref() const {
    return boost::string_ref(p, strlen(p));
  }
  operator fs::path() const {
    return fs::path(p);
  }
};

class Digest
{
public:
  static constexpr size_t length = MD5_DIGEST_LENGTH;
  uint8_t digest[length];

private:
  Digest(uint8_t value[length]) {
      memcpy(digest, value, length);
  }

public:

  Digest(uint8_t *buffer, size_t length) {
    MD5(buffer, length, digest);
  }

  static Digest fromBinary(const std::string &string) {
    if (string.length() != length) {
      throw std::runtime_error("digest is wrong length");
    }
    return Digest((uint8_t*)string.c_str());
  }

  class Ctx {
    private:
      MD5_CTX ctx;
    public:
      Ctx() {
        MD5_Init(&ctx);
      }
      void update(uint8_t *buffer, size_t length) {
        MD5_Update(&ctx, buffer, length);
      }
      Digest digest() {
        uint8_t value[length];
        MD5_Final(value, &ctx);
        return Digest(value);
      }
  };

  bool operator== (const Digest &other) const {
    return memcmp(digest, other.digest, length) == 0;
  }

  std::string hex() const {
    char buf[2 * MD5_DIGEST_LENGTH + 1];
    for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
      sprintf(buf+(2*i), "%02x", (int)digest[i]);
    }
    return std::string(buf);
  }

};

std::optional<Digest> fiemap_hash(int fd) {
  constexpr int count = 72;
  constexpr size_t size = sizeof(struct fiemap) + count * sizeof(struct fiemap_extent);
  constexpr size_t page = 4096;
  static_assert(size <= page && page - size < sizeof(struct fiemap_extent));

  uint8_t buffer[size];
  auto fiemap = (struct fiemap*) buffer;
  *fiemap = (struct fiemap) {
    .fm_start = 0,
    .fm_length = FIEMAP_MAX_OFFSET,
    .fm_extent_count = count,
  };

  constexpr typeof(fiemap_extent::fe_flags) ok_flags =
    FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_SHARED | FIEMAP_EXTENT_NOT_ALIGNED;

  Digest::Ctx ctx;
  while (true) {
    int r = ioctl(fd, FS_IOC_FIEMAP, buffer);
    if (r < 0) {
      throw std::runtime_error("fiemap failed");
    }
    if (fiemap->fm_mapped_extents == 0) {
      throw std::runtime_error("fiemap returned no extents");
    }
    for (int i = 0; i < fiemap->fm_mapped_extents; i++) {
      struct fiemap_extent &extent = fiemap->fm_extents[i];
      if (extent.fe_flags & (~ok_flags)) {
        return std::nullopt;
      }
      struct __attribute__((packed)) {
        uint64_t physical;
        uint64_t logical;
        uint64_t length;
      } packed_extent = {extent.fe_physical, extent.fe_logical, extent.fe_length};
      ctx.update((uint8_t*)&packed_extent, sizeof(packed_extent));
      if (extent.fe_flags & FIEMAP_EXTENT_LAST) {
        return ctx.digest();
      } else {
        fiemap->fm_start = extent.fe_logical + extent.fe_length;
      }
    }
  }
}

class FDStat
{
protected:
  int fd = -1;
  struct stat statbuf;

public:
  FDStat(const char *path) {
    fd = open(path, O_RDONLY);
    if (fd < 0) { 
      throw std::runtime_error("open failed");
    }
    int r = fstat(fd, &statbuf);
    if (r != 0) { 
      throw std::runtime_error("stat failed");
    }
  }

  FDStat(FDStat &&other) {
    fd = other.fd;
    statbuf = other.statbuf;
    other.fd = -1;
  }

  ~FDStat() {
    if (fd >= 0) {
      close(fd);
    }
  }
  const struct stat &stat() const {
    return statbuf;
  }

  int fileno() {
    return fd;
  }
};

class FileContents : public FDStat
{
protected:
  uint8_t buffer[0x1000];
  uint8_t *pointer = nullptr;

  void getbuf() {
    if (statbuf.st_size <= sizeof(buffer)) { 
      size_t to_read = statbuf.st_size;
      uint8_t *p = buffer;
      while (to_read > 0) {
        ssize_t rd = read(fd, p, to_read);
        if (rd <= 0) { 
          throw std::runtime_error("read failed");
        }
        to_read -= rd; 
        p += rd; 
      }
      pointer = buffer;
    } else { 
      void *p = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
      if (p == MAP_FAILED) { 
        throw std::runtime_error("mmap failed");
      }
      pointer = (uint8_t*) p;
    }
  }

public:

  FileContents(FDStat &&fdstat) : FDStat(std::move(fdstat)) {
    getbuf();
  }

  FileContents(const char *path) : FDStat(path) {
    getbuf();
  }

  ~FileContents() { 
    if (pointer != buffer && pointer != nullptr) { 
      munmap(pointer, statbuf.st_size);
    }
  }

  uint8_t *contents() { return pointer; }

  size_t size() { return statbuf.st_size; }
};

void raise_for_status(rocksdb::Status status) {
  if (!status.ok()) {
    throw std::runtime_error(status.getState());
  }
}

rocksdb::Slice slice(Digest &d) {
  return rocksdb::Slice((const char*)d.digest, d.length);
}

rocksdb::Slice slice(boost::string_ref s) {
  return rocksdb::Slice(s.data(), s.length());
}

struct Stats {
  long couldnt_use_fiemap = 0;
  long num_files = 0;
  long found_in_db = 0;
  long found_by_fiemap = 0;
};

class Manifest {
  public:

  rocksdb::DB *db = nullptr;
  rocksdb::ColumnFamilyHandle *by_fiemap_cf = nullptr;
  struct libmnt_table *mounts = nullptr;
  asio::thread_pool pool;
  int limit_count, initial_limit_count;
  bool needs_newline = false;
  asio::io_service io;
  std::atomic<bool> interrupted = false;
  bool finished_scan = false;
  Stats stats;
  int term_width;

  typedef BOOST_ASIO_HANDLER_TYPE(asio::yield_context, void(void)) SemHandler;
  typedef asio::executor_work_guard<asio::io_service::executor_type> Guard;
  std::optional<SemHandler> sem_handler;
  std::optional<Guard> sem_handler_guard;

  asio::signal_set sigusr1{io, SIGUSR1}, sigwinch{io, SIGWINCH};

  ~Manifest() {
    pool.join();
    if (by_fiemap_cf) {
      delete by_fiemap_cf;
    }
    if (db) {
      delete db;
    }
    if (mounts) {
      mnt_unref_table(mounts);
    }
  }

  Manifest(const std::string &db_path)
    : pool(std::thread::hardware_concurrency())
  {
    get_width();

    initial_limit_count = limit_count = std::thread::hardware_concurrency() * 3;

    mounts = mnt_new_table_from_file("/proc/self/mountinfo");
    if (!mounts) {
      throw std::runtime_error("couldn't read mount table");
    }
    // auto cache = mnt_new_cache();
    // mnt_table_set_cache(mounts, cache);
    // mnt_unref_cache(cache);

    auto colopts = rocksdb::ColumnFamilyOptions();
    auto opts = rocksdb::Options();
    opts.create_if_missing = true;
    opts.create_missing_column_families = true;

    std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
    descriptors.push_back(
      rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, colopts));
    descriptors.push_back(
      rocksdb::ColumnFamilyDescriptor("by_fiemap_v2", colopts));
    std::vector<rocksdb::ColumnFamilyHandle*> handles;

    auto status = rocksdb::DB::Open(opts, db_path, descriptors, &handles, &db);
    raise_for_status(status);

    assert(handles.size() == 2);
    delete handles[0];
    by_fiemap_cf = handles[1];
  }

  bool ismount(const fs::path &path) {
    return mnt_table_find_target(mounts, path.c_str(), MNT_ITER_BACKWARD) != nullptr;
  }

  void visitDir(const fs::path &path, asio::yield_context &yield) {
    for (auto &entry : fs::directory_iterator(path)) {
      if (interrupted) {
        break;
      }
      if (entry.is_symlink()) {
        continue;
      }
      if (entry.is_directory() && !ismount(entry.path())) {
        if (ismount(entry.path())) {
          newline_if_needed();
          printf("skipping mount point %s\n", entry.path().c_str());
        }
        visitDir(entry.path(), yield);
      }
      if (entry.is_regular_file()) {
        semwait(yield);
        std::string entry_path = entry.path().string();
        Guard guard(io.get_executor());
        asio::post(pool, [=,guard{std::move(guard)}]() mutable {
          FileResults result = {.interrupted = true};
          if (!interrupted) {
            try {
              result = visitFile(entry_path);
            } catch (std::exception &e) {
              result.exception = std::current_exception();
            }
          }
          asio::post(io, [=,guard{std::move(guard)}]() mutable {
            if (result.exception) {
              std::rethrow_exception(result.exception);
            }
            if (!result.interrupted) {
              stats.num_files++;
              stats.found_by_fiemap += result.found_by_fiemap;
              stats.found_in_db += result.already_in_table;
              stats.couldnt_use_fiemap += result.cant_use_fiemap;
              if (result.cant_use_fiemap) {
                newline_if_needed();
                printf("can't use fiemap for %s\n", entry_path.c_str());
              }
              print_status(entry_path);
            }
            sempost();
            if (finished_scan && limit_count == initial_limit_count) {
              io.stop();
            }
          });
        });
      }
    }
  }

  void print_status(boost::string_ref path) {
    clearline();
    if (path.length() + 5 > term_width) {
      path = path.substr(path.length() + 5 - term_width);
    }
    printf("... %s", path.data());
    fflush(stdout);
  }

  void semwait(asio::yield_context yield) {
    if (limit_count == 0) {
      sem_handler_guard.emplace(io.get_executor());
      assert(!sem_handler.has_value());
      // suspend the coroutine
      asio::async_completion<asio::yield_context, void(void)> completion(yield);
      sem_handler.emplace(std::move(completion.completion_handler));
      completion.result.get();
      // coroutine has been resumed
    }
    assert (limit_count > 0);
    limit_count--;
  }

  void sempost() {
    limit_count++;
    if (limit_count == 1) {
      if (sem_handler.has_value()) {
        SemHandler h = std::move(sem_handler.value());
        sem_handler = std::nullopt;
        sem_handler_guard = std::nullopt;
        // resume the coroutine
        h();
      }
    }
  }


  void handle_sigusr1(const boost::system::error_code &ec, int signal) {
    assert(!ec);
    print_status();
    sigusr1.async_wait(boost::bind(&Manifest::handle_sigusr1, this, _1, _2));
  }

  void handle_sigwinch(const boost::system::error_code &ec, int signal) {
    assert(!ec);
    newline_if_needed();
    get_width();
    sigwinch.async_wait(boost::bind(&Manifest::handle_sigwinch, this, _1, _2));
  }

  void scanDir(const fs::path &path) {
    asio::signal_set sigint(io, SIGINT);
    sigint.async_wait([=](const boost::system::error_code &ec, int signal){
      assert(!ec);
      interrupted = true;
      newline_if_needed();
      printf("interrupted.\n");
      io.stop();
      pool.stop();
    });
    sigusr1.async_wait(boost::bind(&Manifest::handle_sigusr1, this, _1, _2));
    sigwinch.async_wait(boost::bind(&Manifest::handle_sigwinch, this, _1, _2));
    asio::spawn(io, [&](asio::yield_context yield) {
      visitDir(path, yield);
      finished_scan = true;
    });
    io.run();
    pool.join();
    newline_if_needed();

    //not allowed to delete this after closing the database
    delete by_fiemap_cf;
    by_fiemap_cf = nullptr;
    auto status = db->Close();
    raise_for_status(status);

    if (!interrupted) {
      printf("done!\n");
    } else{
      printf("finished cleanup\n");
    }

    print_status();
  }

  void print_status() {
    newline_if_needed();
    printf("total files = %ld\n", stats.num_files);
    printf("found by fiemap = %ld\n", stats.found_by_fiemap);
    printf("couldn't use fiemap = %ld\n", stats.couldnt_use_fiemap);
    printf("files already in database = %ld\n", stats.found_in_db);
    printf("files added to database = %ld\n", stats.num_files - stats.found_in_db);
  }

  void get_width() {
    struct winsize w;
    int r = ioctl(1, TIOCGWINSZ, &w);
    if (r < 0) {
      throw std::runtime_error("couldn't get terminal width");
    }
    term_width = w.ws_col;
  }

  void newline_if_needed() {
    if (needs_newline) {
      printf("\n");
      needs_newline = false;
    }
  }

  void clearline() {
    printf("\r\33[2K");
    needs_newline = true;
  }

  struct FileResults {
    bool interrupted = false;
    bool cant_use_fiemap = false;
    bool found_by_fiemap = false;
    bool already_in_table = false;
    std::exception_ptr exception = nullptr;
  };

  FileResults visitFile(boost::string_ref path)
  {
    FileResults result;

    {
      std::string value;
      auto status = db->Get(rocksdb::ReadOptions(), slice(path), &value);
      if (status.ok()) {
        result.already_in_table = true;
        return result;
      }
    }

    auto fdstat = FDStat(path.data());
    std::optional<Digest> fiemap_key;

    if (fdstat.stat().st_size > 4096) {
      fiemap_key = fiemap_hash(fdstat.fileno());
      if (fiemap_key.has_value()) {
        std::string value;
        auto status = db->Get(rocksdb::ReadOptions(), by_fiemap_cf, slice(fiemap_key.value()), &value);
        if (!status.IsNotFound()) {
          raise_for_status(status);
        }
        if (status.ok()) {
          result.found_by_fiemap = true;
          db->Put(rocksdb::WriteOptions(), slice(path), slice(value));
          return result;
        }
      } else {
        result.cant_use_fiemap = true;
      }
    }

    auto f = FileContents(std::move(fdstat));
    auto digest = Digest(f.contents(), f.size());

    auto status = db->Put(rocksdb::WriteOptions(), slice(path), slice(digest));
    raise_for_status(status);

    if (fiemap_key.has_value()) {
      status = db->Put(rocksdb::WriteOptions(), by_fiemap_cf, slice(fiemap_key.value()), slice(digest));
      raise_for_status(status);
    }

    return result;
  }
};


int main(int argc, char**argv) { 

  try { 
    po::options_description opts("options");

    opts.add_options()
      ("help,h", "print help")
      ("db", po::value<std::string>(), "database path")
      ("root", po::value<std::string>(), "directory to scan");

    po::positional_options_description posopts;

    po::variables_map vm;
    po::store(po::command_line_parser(argc,argv).options(opts).positional(posopts).run(), vm);

    if (vm.count("help") || !vm.count("db") || !vm.count("root")) {
      std::cout << opts << std::endl;
      return 1;
    }

    auto dbpath = vm["db"].as<std::string>();
    auto rootpath = vm["root"].as<std::string>();

    Manifest manifest(dbpath);
    manifest.scanDir(Realpath(rootpath.c_str()));

  } catch (std::exception &e) { 
    std::cout << e.what() << std::endl;
    return 1;
  }

  return 0;
}
