/**
 * @file ui.c
 * @author saul
 * @brief UI rendering for progress updates/stats/etc
 * @TODO investigate multiline style
 */
#include "ui.h"
#include <stdlib.h>
#include <string.h>
#include <winbase.h>
#include <windows.h>

/* state (yuck) for thread */
static HANDLE ui_thread_handle = NULL;
static int running             = 0;

/**
 * @brief Function called by the UI thread - prints the progress bar
 */
static DWORD WINAPI ui_thread_func(LPVOID arg) {
    ui_context* ctx = (ui_context*)arg;
    char layout[512]; // use a builder buffer instead of printing everything
    int progress_bar_width    = 20;
    unsigned long max_packets = ctx->max_packets;
    const char* loader[]      = { "|", "/", "-", "\\", "|", "/", "-", "\\" };
    int loader_elems          = 8;
    int loader_i              = 0;

    fprintf(stderr, "   _____ _   _ _____ ______ ______ _      ______\n");
    fprintf(stderr, "  / ____| \\ | |_   _|  ____|  ____| |    |  ____|\n");
    fprintf(stderr, " | (___ |  \\| | | | | |__  | |__  | |    | |__   \n");
    fprintf(stderr, "  \\___ \\| . ` | | | |  __| |  __| | |    |  __|  \n");
    fprintf(stderr, "  ____) | |\\  |_| |_| |    | |    | |____| |____ \n");
    fprintf(stderr, " |_____/|_| \\_|_____|_|    |_|    |______|______|\n\n");

    while (running && (ctx->max_packets == 0 || ctx->packets_counted <= ctx->max_packets)) {
        unsigned long packet_count = ctx->packets_counted;
        unsigned long len          = 0;

        /* Respond to completion flag by displaying 100% status */
        if (ctx->listen_complete && ctx->max_packets > 0) {
            packet_count = ctx->max_packets;
        }

        len += sprintf(layout + len, "\r %s Total packets: %8lu",
        (loader[loader_i++ % loader_elems]), packet_count);
        /* Calculate percentage done */
        if (max_packets > 0) {
            unsigned long percent = (packet_count * 10000) / max_packets /
            100; // weird percentage calc to avoid truncation to 0%
            len += sprintf(layout + len, " (%2lu%%) [", percent);

            /* Progress bar */
            int pos = progress_bar_width * ctx->packets_counted / ctx->max_packets;
            for (int i = 0; i < progress_bar_width; ++i) {
                layout[len++] = i < pos ? '=' : (i == pos ? '>' : ' ');
            }

            /* Stats */
            layout[len++] = ']';
            len += sprintf(layout + len, " ETH: %4lu | IPv4: %4lu | TCP: %4lu |",
            ctx->num_eth, ctx->num_ip, ctx->num_tcp);
            layout[len] = '\0'; // non literal, make sure to null terminate
        }

        fprintf(stderr, "%s", layout);
        fflush(stderr);
        Sleep(100);
    }
    fprintf(stderr, "\n");
    return 0;
}

/**
 * @brief Zeroes UI context
 */
void init_ui(ui_context* ctx) {
    ctx->packets_counted = 0;
    ctx->active          = 0;
}


/**
 * @brief sets UI flags and creates thread
 */
void start_ui(ui_context* ctx) {
    if (ctx->output_file != stdout) {
        running     = 1;
        ctx->active = 1;

        fprintf(stderr, "Starting packet capture... \n");
        ui_thread_handle = CreateThread(NULL, 0, ui_thread_func, ctx, 0, NULL);

        if (ui_thread_handle == NULL) {
            fprintf(stderr, "Couldn't create thread: %lu\n", GetLastError());
        }
    }
}

/**
 * @brief Wait on UI thread indefinitely then close & free handle
 */
void stop_ui(void) {
    if (running && ui_thread_handle != NULL) {
        running = 0;

        WaitForSingleObject(ui_thread_handle, INFINITE);
        CloseHandle(ui_thread_handle);
        ui_thread_handle = NULL;
        fprintf(stderr, "\nSniffling complete.\n");
    }
}

void update_ui_stats(ui_context* ctx) {
    ctx->packets_counted++;
}

void toggle_cursor(boolean show_cursor) {
    HANDLE console_handle = GetStdHandle(STD_ERROR_HANDLE);
    CONSOLE_CURSOR_INFO i;
    i.dwSize   = 100;
    i.bVisible = show_cursor == TRUE ? TRUE : FALSE;
    SetConsoleCursorInfo(console_handle, &i);
}
