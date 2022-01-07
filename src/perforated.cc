#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/mman.h>
#include <string.h>
#include <string>
#include <vector>
#include <random>
#include <poll.h>
#include <chrono>
#include <optional>

const char *usage =
"Usage: perforated [-hd] -l ADDRESS -p PATHS\
\
Perforated exposes the latency of various filesystem operations as a Prometheus\
HTTP endpoint (at ADDRESS).  It does this by waiting for incoming connections,\
selecting a random file from the paths in PATHS, performing an fstatat,\
selecting a second random file from the paths in PATHS, opening that file,\
reading the first 4096 bytes and finally returning the duration of these three\
operations in nanoseconds to its clients.\
\
ADDRESS is of the form IP_ADDRESS:PORT (e.g. 127.0.0.1:9999). PATHS is a file\
containing null-terminated absolute paths of the files used for sampling. You\
construct that file using 'find /directory -type f ! -size 0 | tr '\\n' '\\0'."
;

int main(int argc, char *argv[]){

    bool daemonize = false;
    bool help = false;
    std::string address;
    std::string pathfile;
    std::string tags;

    int opt = -1;
    while((opt = getopt(argc, argv, "dhl:p:t:")) != -1){
        switch(opt) {
            case 'd':
                daemonize = true;
                break;
            case 'h':
                help = true;
                break;
            case 'l':
                address = optarg;
                break;
            case 'p':
                pathfile = optarg;
                break;
            case 't':
                tags = optarg;
                break;
        }
    }

    if(help){
        std::cerr << usage << std::endl;
        exit(EXIT_SUCCESS);
    }

    if(address.empty() || pathfile.empty()){
        std::cerr << usage << std::endl;
        exit(EXIT_FAILURE);
    }

    const int incoming_fd = [](const auto &address){
        const auto colon_pos = address.find(':');
        if(colon_pos == std::string::npos){
            std::cerr << usage << std::endl;
            exit(EXIT_FAILURE);
        }

        const auto addr = address.substr(0, colon_pos);
        const auto port = address.substr(colon_pos + 1);

        struct addrinfo *r = nullptr;

        const int addrinfo_status = getaddrinfo(addr.c_str(), port.c_str(), nullptr, &r);
        if(addrinfo_status != 0){
            std::cerr << "Fatal: Could not listen at: " << address << std::endl;
            exit(EXIT_FAILURE);
        }

        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if(fd < 0){
            std::cerr << "Fatal: Could not open socket" << std::endl;
            exit(EXIT_FAILURE);
        }

        const int yes = 1;
        const auto sa = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        const auto sb = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int));

        if((sa != 0) || (sb != 0)){
            std::cerr << "Fatal: Failed to set socket options" << std::endl;
            exit(EXIT_FAILURE);
        }

        const bool bound = [](const struct addrinfo *r, const int &fd){
            for(auto s = r; s != nullptr; s = s->ai_next){
                const int b = bind(fd, s->ai_addr, s->ai_addrlen);
                if (b == 0) {
                    return true;
                }
                else{
                    continue;
                }
            }
            return false;
        }(r, fd);

        if(!bound){
            std::cerr << "Fatal: Could not bind to socket" << std::endl;
            exit(EXIT_FAILURE);
        }

        const int listening = listen(fd, SOMAXCONN);
        if(listening < 0){
            std::cerr << "Fatal: Could not listen on socket" << std::endl;
            exit(EXIT_FAILURE);
        }

        freeaddrinfo(r);
        return fd;
    }(address);

    const auto [paths, paths_length] = [](const auto &pathfile) -> std::pair<char *, size_t> {
        const int paths_fd = open(pathfile.c_str(), O_RDONLY);
        if(paths_fd < 0){
            std::cerr << "Fatal: Could not open paths file" << std::endl;
            exit(EXIT_FAILURE);
        }

        struct stat statbuf;
        const int s = fstat(paths_fd, &statbuf);
        if(s < 0){
            std::cerr << "Fatal: Could not stat paths file" << std::endl;
            exit(EXIT_FAILURE);
        }

        char *paths = static_cast<char *>(mmap(nullptr, statbuf.st_size, PROT_READ, MAP_PRIVATE, paths_fd, 0));
        if(!paths){
            std::cerr << "Fatal: Could not mmap" << std::endl;
            exit(EXIT_FAILURE);
        }

        return std::make_pair(paths, statbuf.st_size);
    }(pathfile);

    const std::vector<char *> index = [](const auto paths, const auto paths_length){
        std::vector<char *> index;
        for(char *i = paths; i < paths + paths_length; ){
            index.push_back(i);
            i = strchrnul(i, '\0') + 1;
        }
        return index;
    }(paths, paths_length);

    if(index.size() == 0){
        std::cerr << "Fatal: Index is too small, paths file is malformed or empty" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, index.size() - 1);

    if(daemonize){
        const auto d = daemon(0, 0);
        if(d != 0){
            std::cerr << "Fatal: Failed to daemonize" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    while(true){
        struct pollfd pfd;
        pfd.fd = incoming_fd;
        pfd.events = POLLRDNORM;

        const auto p = poll(&pfd, 1, -1);
        if(p < 0){
            std::cerr << "Fatal: Error polling" << std::endl;
            exit(EXIT_FAILURE);
        }

        if(pfd.revents & POLLRDNORM){
            const auto [open_duration, read_duration] = [](const auto &index, auto &distrib, auto &gen){
                while(true){
                    const auto rand_index = distrib(gen);
                    const auto rand_path = index[rand_index];

                    const auto start_open = std::chrono::high_resolution_clock::now();
                    const auto fd = open(rand_path, O_RDONLY);
                    const auto open_duration = std::chrono::high_resolution_clock::now() - start_open;

                    if(fd < 0){
                        continue;
                    }

                    char buff[4096];
                    const auto start_read = std::chrono::high_resolution_clock::now();
                    const auto bytes_read = read(fd, buff, sizeof(buff));
                    const auto read_duration = std::chrono::high_resolution_clock::now() - start_read;

                    close(fd);

                    if(bytes_read <= 0){
                        continue;
                    }

                    return std::make_pair(open_duration, read_duration);
                }
            }(index, distrib, gen);

            const auto stat_duration = [](const auto &index, auto &distrib, auto &gen){
                while(true){
                    const auto rand_index = distrib(gen);
                    const auto rand_path = index[rand_index];

                    const size_t dir_path_length = [](const auto &rand_path) -> size_t {
                        size_t dir_path_length = 0;
                        for(size_t i = 0; i < 4096; i++){
                            if(*(rand_path + i) == '\0'){
                                return dir_path_length;
                            }
                            else if(*(rand_path + i) == '/'){
                                dir_path_length = i + 1;
                            }
                        }
                        return 0;
                    }(rand_path);

                    if(dir_path_length <= 0 || dir_path_length >= 4096){
                        continue;
                    }

                    char dir_path[4096];
                    memcpy(dir_path, rand_path, dir_path_length);
                    dir_path[dir_path_length] = '\0';

                    std::optional<std::chrono::nanoseconds> stat_duration;

                    const auto dir = opendir(dir_path);
                    if(dir){
                        const auto fd = dirfd(dir);
                        if(fd >= 0){
                            struct stat statbuf;
                            const auto start_stat = std::chrono::high_resolution_clock::now();
                            const auto s = fstatat(fd, rand_path + dir_path_length, &statbuf, AT_SYMLINK_NOFOLLOW);
                            const auto end_stat = std::chrono::high_resolution_clock::now();
                            if(s == 0){
                                stat_duration = end_stat - start_stat;
                            }
                        }
                    }
                    closedir(dir); //also closes 'fd'

                    if(stat_duration.has_value()){
                        return stat_duration.value();
                    }
                }
            }(index, distrib, gen);

            const std::vector<int> clients = [](const auto incoming_fd){
                std::vector<int> clients;
                while(true){
                    const auto client = accept4(incoming_fd, nullptr, nullptr, SOCK_NONBLOCK);
                    if(client < 0){
                        if(errno == EAGAIN || errno == EWOULDBLOCK){
                            break;
                        }
                        else{
                            std::cerr << "Fatal: Could not accept incoming connection: " << errno << std::endl;
                            exit(EXIT_FAILURE);
                        }
                    }

                    clients.push_back(client);
                }
                return clients;
            }(incoming_fd);

            const std::string data =
                "# HELP perforated_open_latency Time in nanoseconds to open a file\n"
                "# TYPE perforated_open_latency gauge\n"
                "perforated_open_latency" + tags + " " + std::to_string(open_duration.count()) + "\n"
                "# HELP perforated_read_latency Time in nanoseconds to read 4096 bytes\n"
                "# TYPE perforated_read_latency gauge\n"
                "perforated_read_latency" + tags + " " + std::to_string(read_duration.count()) + "\n"
                "# HELP perforated_fstatat_latency Time in nanoseconds to fstatat a file\n"
                "# TYPE perforated_fstatat_latency gauge\n"
                "perforated_fstatat_latency" + tags + " " + std::to_string(stat_duration.count()) + "\n"
                ;

            const std::string response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain; version=0.0.4\r\n"
                "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

            for(const auto &c: clients){
                const auto w = write(c, response.c_str(), response.size());
                (void)w;
                close(c);
            }
        }
        else{
            break;
        }
    }

    exit(EXIT_SUCCESS);
}
