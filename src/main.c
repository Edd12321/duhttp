#define _POSIX_C_SOURCE 200809L
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define PORT_NUM        8080         /* What port to bind to? */
#define BACKLOG         10           /* How many clients can wait? */
#define POOL_SIZE       256          /* How big should the thread pool be? */
#define REQ_LIMIT       20           /* How big can a request be? */
#define NO_COND         0            /* Should we check anything when logging? */
#define LOG_FP          stderr       /* Where to print out log info? */
#define HEADERS_MAX     8192         /* How much space can the request-line + headers occupy max? */
#define QUERY_MAX       256          /* How much space can the query string occupy max? */
#define CONTENT_MAX     8192
#define WWW_DIR         "www"        /* Where are static things stored? */
#define CGI_DIR         "/cgi-bin"   /* Where are CGI scripts stored? */
#define INDEX_FILE      "index.html" /* What file to serve by default? */
#ifndef PATH_MAX
#define PATH_MAX     4096   /* How big can a path be? */
#endif
#define log_txt(ret, type, ...)                       \
    if (ret < 0 || !type) {                           \
        time_t now = time(NULL);                      \
        char *s = ctime(&now); s[strlen(s)-1] = '\0'; \
        fprintf(LOG_FP, "[%s] ", s);                  \
        fprintf(LOG_FP, "[" #type "] " __VA_ARGS__);  \
        fputc('\n', LOG_FP);                          \
        if (type)                                     \
            exit(EXIT_FAILURE);                       \
    }
/* Simulates C++ iterators */
#define of ,
#define in ,
#define _foreach(it, type, v) \
    type *it; \
    for (size_t __c = 0; __c < sizeof v / sizeof *v && (it = &v[__c], true); ++__c)
#define foreach(...) _foreach(__VA_ARGS__)

pthread_t pool[POOL_SIZE];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

char cwd[PATH_MAX];

/* Ugly logging hack */
enum log_type {
	INFO,
	ERROR,
	WARN
};

struct node {
	int info;
	struct node *last, *next;
} *tail = NULL, *head = NULL;

struct mime_type {
	char *ext, *type;
} mime_types[] = {
	{ "txt",  "text/plain" },
	{ "html", "text/html" },
	{ "css",  "text/css" },
	{ "js",   "text/javascript" },
	{ "json", "application/json" },
	{ "pdf",  "application/pdf" },
	{ "zip",  "application/zip" },
	{ "mp4",  "video/mp4" },
	{ "webm", "video/webm" },
};

static void send_status(int fd, int status)
{
	static struct code {
		int number;
		const char *str;
	} codes[] = {
		{ 200, "OK" },
		{ 201, "Created" },
		{ 202, "Accepted" },
		{ 204, "No Content" },
		{ 300, "Multiple Choices" },
		{ 301, "Moved Permanently" },
		{ 302, "Moved Temporarily" },
		{ 304, "Not Modified" },
		{ 400, "Bad Request" },
		{ 401, "Unauthorized" },
		{ 403, "Forbidden" },
		{ 404, "Not Found" },
		{ 500, "Internal Server Error" },
		{ 501, "Not Implemented" },
		{ 502, "Bad Gateway" },
		{ 503, "Service Unavailable" },
	};

	const char *str;
	foreach (k of struct code in codes) {
		if (k->number == status) {
			str = k->str;
			break;
		}
	}
	char buf[128];
	log_txt(NO_COND, INFO, "Client received status: '%d %s'", status, str);
	sprintf(buf, "HTTP/1.0 %d %s\r\n", status, str);
	send(fd, buf, strlen(buf), 0);
}

char *sanitize_uri(char *uri)
{
	if (*uri != '/')
		return NULL;
	char *new_buf = malloc(PATH_MAX);
	strcpy(new_buf, cwd);
	strcat(new_buf, "/");
	strcat(new_buf, WWW_DIR);
	char *p = uri, *q = new_buf + strlen(new_buf);
	for (; *p; ++p) {
		if ((*p == '/')
		&&  (*(p+1) == '.' && *(p+2) == '.')
		&&  (*(p+3) == '/' || *(p+3) == '\0')) {
			p += 2;
			continue;
		}
		*q++ = *p;
	}
	*q = '\0';
	return new_buf;
}

/* [...] sender help functions */
#define send_str(x) send(fd, x, strlen(x), 0)
static inline void send_file(int fd, char *filename)
{
	int file = open(filename, O_RDONLY);

	struct stat st;
	fstat(file, &st);
	char *buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, file, 0);
	{
		char str[256];
		sprintf(str, "Content-Length: %ld\r\n", st.st_size);
		send_str(str);
		
		char *ext = strchr(basename(filename), '.');
		if (ext && *++ext) {
			foreach (k of struct mime_type in mime_types) {
				if (!strcmp(ext, k->ext)) {
					sprintf(str, "Content-Type: %s\r\n", k->type);
					send_str(str);
					goto _skip_default_mimetype;
				}
			}
		}
		send_str("Content-Type: application/octet-stream\r\n");
	}
_skip_default_mimetype:
	send_str("\r\n");
	send(fd, buf, st.st_size, 0);
	close(file);
}

static inline void serve(int fd)
{
	char buf[HEADERS_MAX + 1];
	size_t len = recv(fd, buf, sizeof buf - 1, 0);
	buf[len] = '\0';

	char *track;
	/* Request line */
	char *method = strtok_r(buf, " ", &track);
	char *uri = strtok_r(NULL, " ", &track);
	char *query = strchr(uri, '?');
	if (query != NULL)
		*query++ = '\0';
	char *http_ver = strtok_r(NULL, "\r\n", &track);
	log_txt(NO_COND, INFO, "Connection accepted!\n"
                           "Method:                 '%s'\n"
	                       "URI:                    '%s'\n"
	                       "Query string:           '%s'\n"
	                       "HTTP version:           '%s'",
		method, uri, query, http_ver);
	/* Handle client headers */
	struct {
		size_t Content_Length;
		char *Content_Type;
		char *Authorization;
	} headers = {0};
	char *key, *value;
	size_t headers_len = http_ver - buf + strlen(http_ver) - 1;
	while ((key = strtok_r(NULL, "\n", &track))) {
		size_t len = strlen(key);
		if (len && key[len-1] == '\r') {
			key[len-1] = '\0';
			if (!*key)
				break;
			headers_len += len + 2;
		} else {
			send_status(fd, 400);
			return;
		}
		value = strstr(key, ": ");
		*value = '\0', value += 2;
		log_txt(NO_COND, INFO, "Header: '%s'='%s'", key, value);
		if (!strcmp(key, "Content-Length"))
			headers.Content_Length = atoi(value);
		if (!strcmp(key, "Content-Type"))
			headers.Content_Type = value;
		if (!strcmp(key, "Authorization"))
			headers.Authorization = value;
	}

	char *content = NULL;
	if (headers.Content_Length) {
		if (headers.Content_Length > CONTENT_MAX) {
			send_status(fd, 501);
			return;
		}
		char *part1 = buf + headers_len;
		size_t len1 = strlen(part1);
		ssize_t remaining_len = headers.Content_Length - len1;

		content = malloc(headers.Content_Length);
		strcpy(content, part1);
		if (remaining_len > 0)
			recv(fd, content + len1, remaining_len, 0);
	}
	if (!strcmp(method, "GET")) {
		bool cgi = strstr(uri, CGI_DIR) == uri;
		char *clean_uri = sanitize_uri(uri);
		struct stat st;
		stat(clean_uri, &st);
		if (S_ISDIR(st.st_mode)) {
			chdir(clean_uri);
			if (access(INDEX_FILE, F_OK) != 0)
				send_status(fd, 404);
			else {
				send_status(fd, 200);
				send_file(fd, INDEX_FILE);
			}
			chdir(cwd);
		} else {
			if (!cgi) {
				if (access(clean_uri, F_OK) != 0)
					send_status(fd, 404);
				else {
					send_status(fd, 200);
					send_file(fd, clean_uri);
				}
			} else {
				send_status(fd, 200);
				/**
				 * TODO: Set envvars
				 */
				pid_t pid;
				int pd[2];

				pipe(pd);
				if ((pid = fork()) == 0) {
					dup2(pd[1], STDOUT_FILENO);
					close(pd[0]);
					close(pd[1]);
					execl(clean_uri, clean_uri, NULL);
					_exit(0);
				} else {
					close(pd[1]);
					char c;
					while (read(pd[0], &c, 1) >= 1)
						send(fd, &c, 1, 0);
					close(pd[0]);

					int status;
					waitpid(pid, &status, 0);
				}
			}
		}
		free(clean_uri);
		free(content);
		return;
	}
	if (!strcmp(method, "HEAD")) {
		free(content);
		send_status(fd, 200);
		return;
	}
	if (!strcmp(method, "POST")) {
		free(content);
		send_status(fd, 200);
		return;
	}
	free(content);
	send_status(fd, 400);
}

void enqueue(int info)
{
	if (head == NULL) {
		tail = head = malloc(sizeof(struct node));
		head->last = head->next = NULL;
		head->info = info;
	} else {
		tail->last = malloc(sizeof(struct node));
		tail->last->last = NULL;
		tail->last->next = tail;
		tail->last->info = info;
		tail = tail->last;
	}
}

int dequeue()
{
	if (head == NULL)
		return 0;
	int ret = head->info;
	if (head->last) {
		head = head->last;
		free(head->next);
		head->next = NULL;
	} else {
		free(head);
		head = NULL;
	}
	return ret;
}

void *conn_handler()
{
	for (;;) {
		pthread_mutex_lock(&mutex);
		int ret = dequeue();
		if (!ret) {
			pthread_cond_wait(&cond, &mutex);
			ret = dequeue();
		}
		serve(ret);
		close(ret);
		pthread_mutex_unlock(&mutex);
	}
	return NULL;
}

int main()
{
	getcwd(cwd, sizeof cwd);

	int sv_sock = socket(AF_INET, SOCK_STREAM, 0);
	int cl_sock;
	setsockopt(sv_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	struct sockaddr_in sv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT_NUM),
		.sin_addr = {.s_addr = htonl(INADDR_ANY)},
		.sin_zero = {0}
	};

	log_txt(NO_COND,
		INFO, "Started server on port %d", PORT_NUM);
	log_txt(bind(sv_sock, (struct sockaddr*) &sv_addr, sizeof sv_addr),
		ERROR, "Could not bind socket to address");
	log_txt(listen(sv_sock, BACKLOG),
		ERROR, "Could not listen");
	
	foreach (i of pthread_t in pool)
		log_txt(pthread_create(i, NULL, conn_handler, NULL),
			WARN, "Could not create thread #%ld", i-pool);

	for (;;) {
		log_txt((cl_sock = accept(sv_sock, NULL, NULL)),
			WARN, "Could not accept connection (socket %d)", cl_sock);
		log_txt(NO_COND,
			INFO, "Accepting connection (socket %d)", cl_sock);
		pthread_mutex_lock(&mutex);
		enqueue(cl_sock);
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);
	}
}
