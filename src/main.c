#include "config.h"
#include "client.h"
#include "server.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

/* Global shutdown flag */
volatile sig_atomic_t g_shutdown = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --mode <client|server> --config <path.json>\n"
        "\n"
        "Options:\n"
        "  -m, --mode    Operating mode: 'client' or 'server'\n"
        "  -c, --config  Path to JSON configuration file\n"
        "  -h, --help    Show this help message\n"
        "\n"
        "Examples:\n"
        "  sudo %s --mode client --config client.json\n"
        "  sudo %s --mode server --config server.json\n"
        "\n"
        "Note: Requires root privileges or CAP_NET_RAW capability.\n",
        prog, prog, prog);
}

int main(int argc, char *argv[])
{
    const char *mode_str   = NULL;
    const char *config_path = NULL;

    static struct option long_opts[] = {
        {"mode",   required_argument, 0, 'm'},
        {"config", required_argument, 0, 'c'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:c:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'm': mode_str    = optarg; break;
            case 'c': config_path = optarg; break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!mode_str || !config_path) {
        LOG_ERROR("both --mode and --config are required");
        print_usage(argv[0]);
        return 1;
    }

    int mode;
    if (strcmp(mode_str, "client") == 0) {
        mode = MODE_CLIENT;
    } else if (strcmp(mode_str, "server") == 0) {
        mode = MODE_SERVER;
    } else {
        LOG_ERROR("invalid mode '%s': must be 'client' or 'server'", mode_str);
        return 1;
    }

    /* Check for root privileges */
    if (getuid() != 0 && geteuid() != 0) {
        LOG_WARN("not running as root — raw socket operations may fail");
    }

    /* Install signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Load configuration */
    config_t cfg;
    if (config_load(&cfg, config_path, mode) < 0) {
        LOG_ERROR("failed to load configuration from '%s'", config_path);
        return 1;
    }

    config_dump(&cfg);
    LOG_INFO("injspoof starting in %s mode", mode_str);

    int result;
    if (mode == MODE_CLIENT) {
        result = client_run(&cfg);
    } else {
        result = server_run(&cfg);
    }

    LOG_INFO("injspoof exited with code %d", result);
    return result;
}
