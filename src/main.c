#define _XOPEN_SOURCE 500
#define _POSIX_C_SOURCE 200809L
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define PORT_NUM        8080         /* What port to bind to? */
#define BACKLOG         10           /* How many clients can wait? */
#define POOL_SIZE       256          /* How big should the thread pool be? */
#define DEFAULT_MIME    0            /* Send application/octet-stream, or let the browser figure it out */
#define NO_COND         0            /* Should we check anything when logging? */
#define LOG_FP          stderr       /* Where to print out log info? */
#define HEADERS_MAX     8192         /* How much space can the request-line + headers occupy max? */
#define QUERY_MAX       256          /* How much space can the query string occupy max? */
#define CONTENT_MAX     8192         /* Max allowed client content */
#define CGI_DIR         "/cgi-bin"   /* Where are CGI scripts stored? */
#define INDEX_FILE      "index.html" /* What file to serve by default? */
#define PROTOCOL        "HTTP/1.0"   /* HTTP Protocol version */
#ifndef PATH_MAX
#define PATH_MAX        4096         /* How big can a path be? */
#endif
#define log_txt(ret, type, ...)                       \
    if (ret < 0 || !type) {                           \
        time_t now = time(NULL);                      \
        char *s = ctime_r(&now, (char[26]){0});       \
        s[strlen(s)-1] = '\0';                        \
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

struct setting {
	int port_num;
	int backlog;
	size_t headers_max;
	size_t content_max;

	char *root_dir;
	char *cgi_dir;
} settings;

struct node {
	int info;
	struct node *last, *next;
} *tail = NULL, *head = NULL;

struct mime_type {
	char *ext, *type;
};

struct mime_type mimetypes_ext[] = {
	{ "txt zrc",                "text/plain" },
	{ "html htm xhtml",         "text/html" },
	{ "md",                     "text/markdown" },
	{ "c h cpp hpp cc cxx c++", "text/x-c" },
	{ "css",                    "text/css" },
	{ "js",                     "text/javascript" },
	{ "json",                   "application/json" },
	{ "pdf",                    "application/pdf" },
	{ "zip",                    "application/zip" },
	{ "jar",                    "application/java-archive" },
	{ "wad",                    "application/x-doom" },
	{ "mp4",                    "video/mp4" },
	{ "webm",                   "video/webm" },
	{ "png",                    "image/png" },
	{ "gif",                    "image/gif" },
	{ "ico",                    "image/vnc.microsoft.icon" },
	{ "jpg jpeg",               "image/jpeg" },
	{ "svg",                    "image/svg+xml" },
};
struct mime_type mimetypes_name[] = {
	{ "README LICENSE Makefile .gitignore", "text/plain" },
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
	sprintf(buf, PROTOCOL " %d %s\r\n", status, str);
	send(fd, buf, strlen(buf), 0);
}

char *sanitize_uri(char *uri)
{
	if (*uri != '/')
		return NULL;
	char *new_buf = malloc(PATH_MAX);
	strcpy(new_buf, settings.root_dir);
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
#define max(x, y) ((x) > (y) ? (x) : (y))
static inline void send_file(int fd, char *filename)
{
	int file = open(filename, O_RDONLY);

	struct stat st;
	fstat(file, &st);
	
	char str[256];
	sprintf(str, "Content-Length: %ld\r\n", st.st_size);
	send_str(str);
	
#define send_mime(x, T) {                                      \
    foreach (k of struct mime_type in T) {                     \
        char *track;                                           \
        char *cpy = strdup(k->ext);                            \
        char *ptr = strtok_r(cpy, " ", &track);                \
        do {                                                   \
            if (!strcmp(x, ptr)) {                             \
                free(cpy);                                     \
                sprintf(str, "Content-Type: %s\r\n", k->type); \
                send_str(str);                                 \
                goto _skip_default_mimetype;                   \
            }                                                  \
        } while ((ptr = strtok_r(NULL, " ", &track)) != NULL); \
        free(cpy);                                             \
    }                                                          \
}
	char *ext = strchr(basename(filename), '.');
	if (ext && *++ext)
		send_mime(ext, mimetypes_ext);
	send_mime(basename(filename), mimetypes_name);
#if DEFAULT_MIME 
	send_str("Content-Type: application/octet-stream\r\n");
#endif
_skip_default_mimetype:
	send_str("\r\n");
	sendfile(fd, file, 0, st.st_size);
	close(file);
}

static inline void send_dir_listing(int fd, char *uri_display, char *path)
{
	char str[max(settings.headers_max, PATH_MAX)];
	sprintf(str, "Content-Type: text/html\r\n\r\n"
	             "<!DOCTYPE HTML>\n"
	             "<html>\n"
	             "<head><title>Index of %1$s</title></head>\n"
	             "<body>\n"
	             	"\t<h1>Index of %1$s</h1>\n"
	             	"\t<table>\n"
	            		"\t\t<tr>\n"
	             			"\t\t\t<th>Name</th>\n"
	             			"\t\t\t<th>Last modified</th>\n"
	             			"\t\t\t<th>Size</th>\n"
	             		"\t\t</tr>\n"
	             		"\t\t<tr>\n"
	             			"\t\t\t<td colspan=\"3\"><hr /></td>\n"
	             		"\t\t</tr>\n"
		,uri_display);
	send_str(str);
	
	DIR *d;
	struct dirent *dir;
	if ((d = opendir(path))) {
		while ((dir = readdir(d)) != NULL) {
			struct stat st;
			stat(dir->d_name, &st);
			
			/* Last modified */
			char date[64];
			strftime(date, sizeof date, "%Y-%m-%d %H:%M", localtime(&st.st_mtime));
			/* Real path */
			char link[PATH_MAX];
			strcpy(link, path);
			if (link[strlen(link)-1] != '/')
				strcat(link, "/");
			strcat(link, dir->d_name);
			const char *dp_path = strstr(link, settings.root_dir);
			dp_path = dp_path ? dp_path + strlen(settings.root_dir) : dir->d_name;
			if (!*dp_path)
				dp_path = "/";

			sprintf(str, "\t\t<tr>\n"
			             	"\t\t\t<td><a href=\"%s\">%s</a></td>\n"
			             	"\t\t\t<td>%s</td>\n"
			             	"\t\t\t<td>%ldB</td>\n"
			             "\t\t</tr>\n"
				, dp_path, dir->d_name, date, st.st_size);
			send_str(str);
		}
		closedir(d);
	}
	send_str("</table></body></html>");
}

static inline void serve(int fd)
{
	char buf[settings.headers_max + 1];
	ssize_t len = recv(fd, buf, sizeof buf - 1, 0);
	len = len < 0 ? 0 : len;
	buf[len] = '\0';

	char *track;
	/* Request line */
	char *method = strtok_r(buf, " ", &track);
	char *uri = !method ? NULL : strtok_r(NULL, " ", &track);
	char *query = !uri ? NULL : strchr(uri, '?');
	char *http_ver = !uri ? NULL : strtok_r(NULL, "\r\n", &track);
	if (query != NULL)
		*query++ = '\0';

	if (!method || !uri || !http_ver) {
		send_status(fd, 400);
		return;
	}
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
		if (!value) {
			send_status(fd, 400);
			return;
		}
		*value = '\0', value += 2;
		log_txt(NO_COND, INFO, "Header: '%s'='%s'", key, value);
		if (!strcmp(key, "Content-Length"))
			headers.Content_Length = atoll(value);
		if (!strcmp(key, "Content-Type"))
			headers.Content_Type = value;
		if (!strcmp(key, "Authorization"))
			headers.Authorization = value;
	}

	/* Content and URI processing */
	char *content = NULL;
	if (headers.Content_Length) {
		if (headers.Content_Length > settings.content_max) {
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
	
	/* Do we execute a script or return a file? */
	bool cgi = strstr(uri, settings.cgi_dir) == uri;
	/* Do we have to send content back to the client? */
	bool get = true;
	
	char *clean_uri = sanitize_uri(uri);
	if (clean_uri == NULL) {
		send_status(fd, 400);
		goto _clean_up;
	}

	if (!strcmp(method, "GET")) {
_get_req:;
		struct stat st;
		stat(clean_uri, &st);
		/* Directory listing/index file */
		if (S_ISDIR(st.st_mode)) {
			pid_t pid = fork();
			if (!pid) {
				chdir(clean_uri);
				if (access(INDEX_FILE, F_OK) != 0) {
					send_status(fd, 200);
					if (get) send_dir_listing(fd, uri, clean_uri);
				} else {
					send_status(fd, 200);
					if (get) send_file(fd, INDEX_FILE);
				}
				chdir(cwd);
				_exit(0);
			}
		/* Explicit file */
		} else {
			if (access(clean_uri, F_OK) != 0) {
				send_status(fd, 404);
				goto _clean_up;
			}
			if (!cgi || !(st.st_mode & S_IXUSR)) {
				send_status(fd, 200);
				if (get) send_file(fd, clean_uri);
				goto _clean_up;
			}
			pid_t pid;
			int out_pipe[2], content_pipe[2];

			pipe(out_pipe);
			pipe(content_pipe);
			if ((pid = fork()) == 0) {
				signal(SIGPIPE, SIG_DFL);
				dup2(out_pipe[1], STDOUT_FILENO);
				dup2(content_pipe[0], STDIN_FILENO);
				close(out_pipe[1]);
				close(out_pipe[0]);
				close(content_pipe[0]);
				close(content_pipe[1]);
				/*
				 * TODO: Set more envvars
				 */
#define set_var(x, y) \
    if (y != NULL) setenv(#x, y, 1);
#define set_int(x, y) {           \
    char buf[32];                 \
    sprintf(buf, "%ld", (long)y); \
    setenv(#x, buf, 1);           \
}
				set_int(CONTENT_LENGTH,  headers.Content_Length);
				set_var(CONTENT_TYPE,    headers.Content_Type);
				set_var(QUERY_STRING,    query);
				set_var(REQUEST_METHOD,  method);
				set_var(SCRIPT_NAME,     uri);
				set_var(DOCUMENT_ROOT,   settings.root_dir);
				set_var(SERVER_PROTOCOL, PROTOCOL);
				set_int(SERVER_PORT,     PORT_NUM);
				char path[PATH_MAX];
				realpath(clean_uri, path);
				chdir(dirname(clean_uri));
				execl(path, path, NULL);
				_exit(0);
			} else {
				send_status(fd, 200);
				close(content_pipe[0]);
				if (content)
					write(content_pipe[1], content, strlen(content));
				close(content_pipe[1]);
				close(out_pipe[1]);
				char c;
				if (get)
					while (read(out_pipe[0], &c, 1) >= 1)
						send(fd, &c, 1, 0);
				close(out_pipe[0]);

				int status;
				waitpid(pid, &status, 0);
			}
		}
	} else if (!strcmp(method, "HEAD")) {
		get = false;
		goto _get_req;
	} else if (!strcmp(method, "POST")) {
		/* It only recently dawned on me that my GET is actually a POST
		 * But it works so who cares. Rookie mistake */
		goto _get_req;
	} else {
		send_status(fd, 400);
	}
_clean_up:
	free(clean_uri);
	free(content);
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
		while (!ret) {
			pthread_cond_wait(&cond, &mutex);
			ret = dequeue();
		}
		pthread_mutex_unlock(&mutex);
		serve(ret);
		close(ret);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	signal(SIGPIPE, SIG_IGN);
	getcwd(cwd, sizeof cwd);
	/* Default values */
	settings = (struct setting) {
		.port_num    = PORT_NUM,
		.backlog     = BACKLOG,
		.headers_max = HEADERS_MAX,
		.content_max = CONTENT_MAX,
		.root_dir    = cwd,
		.cgi_dir     = CGI_DIR
	};
	int opt;
	while ((opt = getopt(argc, argv, "p:d:b:c:m:h:")) != -1) {
		switch (opt) {
			case 'p':
				settings.port_num = atoi(optarg);
				break;
			case 'b':
				settings.backlog = atoi(optarg);
				break;
			case 'm':
				settings.content_max = atoll(optarg);
				break;
			case 'h':
				settings.headers_max = atoll(optarg);
				break;
			case 'd':
				settings.root_dir = optarg;
				break;
			case 'c':
				settings.cgi_dir = optarg;
				break;
			case '?':
				fprintf(stderr, "usage: %s\n"
					"\t[-p <port>]\n"
					"\t[-b <backlog>]\n"
					"\t[-m <content-max>]\n"
					"\t[-h <headers-max>]\n"
					"\t[-d <root-dir>]\n"
					"\t[-c <cgi-dir>]\n",
					argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	char actual_root[PATH_MAX];
	realpath(settings.root_dir, actual_root);
	settings.root_dir = actual_root;

	int sv_sock = socket(AF_INET, SOCK_STREAM, 0);
	int cl_sock;
	setsockopt(sv_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	struct sockaddr_in sv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(settings.port_num),
		.sin_addr = {.s_addr = htonl(INADDR_ANY)},
		.sin_zero = {0}
	};

	log_txt(NO_COND,
		INFO, "Started server on port %d", settings.port_num);
	log_txt(bind(sv_sock, (struct sockaddr*) &sv_addr, sizeof sv_addr),
		ERROR, "Could not bind socket to address");
	log_txt(listen(sv_sock, settings.backlog),
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
