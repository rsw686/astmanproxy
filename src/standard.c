/*	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>

	This program is free software, distributed under the terms of
	the GNU General Public License.

	standard.c
	Standard I/O Handler
*/

#include "astmanproxy.h"

extern struct mansession *sessions;

/* Return a fully formed message block to session_do for processing */
int _read(struct mansession *s, struct message *m) {
	char line[MAX_LEN];
	size_t command_len;
	int res;
	
	m->headers[m->hdrcount] = NULL;

	for (;;) {		
		memset(line, 0, sizeof line);
		res = get_input(s, line);

		if (res > 0) {
			// Assemble the command response as a single header
			if(m->in_command && !(strstr(line, "ActionID:") || strstr(line, "Privilege:"))) {
				if(m->headers[m->hdrcount] == NULL) {
					if(! (m->headers[m->hdrcount] = malloc(sizeof(char) * MAX_LEN)))
						break;
			
					memset(m->headers[m->hdrcount], 0, sizeof(char) * MAX_LEN);
					strncpy(m->headers[m->hdrcount], line, sizeof line);
				} else {
					command_len = strlen(m->headers[m->hdrcount]) + strlen(line) + 3;
					
					if(command_len <= MAX_COMMAND_LEN) {
						if(! (m->headers[m->hdrcount] = realloc(m->headers[m->hdrcount], command_len)))
							break;
						
						strcat(m->headers[m->hdrcount], "\r\n");
						strcat(m->headers[m->hdrcount], line);
					} else {
						if (debug) debugmsg("Exceeded max command length getting line");
					}
				}
				
				if (strstr(line, "--END COMMAND--")) {
					if (debug) debugmsg("Found END COMMAND");
					m->in_command = 0;
					
					if (m->hdrcount < MAX_HEADERS - 1) { 
						m->hdrcount++;
					}
				}
			} else {	
				if(! (m->headers[m->hdrcount] = malloc(sizeof(char) * MAX_LEN)))
					break;
		
				memset(m->headers[m->hdrcount], 0, sizeof(char) * MAX_LEN);
				strncpy(m->headers[m->hdrcount], line, sizeof line);
				
				if (*(m->headers[m->hdrcount]) == '\0' ) {
					break;
				} else if (m->hdrcount < MAX_HEADERS - 1) { 
					m->hdrcount++;
					m->headers[m->hdrcount] = NULL;
				} else  {
					if (debug) debugmsg("Exceeded max headers getting line");
				}
			}
		} else if (res < 0) {
			if (debug) debugmsg("Read error %d getting line", res);
			break;
		}
		
		if (strstr(line, "Response: Follows")) {
			if (debug) debugmsg("Found Response Follows");
			m->in_command = 1;
		}
	}
	if (debug>2) debugmsg("Returning standard block of %d lines, res %d", m->hdrcount, res);

	return res;
}

int _write(struct mansession *s, struct message *m) {
	int i;
	char w_buf[1500];	// Usual size of an ethernet frame
	int at;

	// Combine headers into a buffer for more effective network use.
	// This can have HUGE benefits under load.
	at = 0;
	pthread_mutex_lock(&s->lock);

	if (debug>2) debugmsg("Transmitting standard block of %d lines, fd %d", m->hdrcount, s->fd);

	for (i=0; i<m->hdrcount; i++) {
		if( ! strlen(m->headers[i]) )
			continue;
		if( at > 1480 || at + strlen(m->headers[i]) > 1480 ) {
			ast_carefulwrite(s->fd, w_buf, at, s->writetimeout);
			at = 0;
		}
		if( strlen(m->headers[i]) > 1480 ) {
			ast_carefulwrite(s->fd, m->headers[i], strlen(m->headers[i]) , s->writetimeout);
			ast_carefulwrite(s->fd, "\r\n", 2, s->writetimeout);
		} else {
			memcpy( &w_buf[at], m->headers[i], strlen(m->headers[i]) );
			memcpy( &w_buf[at+strlen(m->headers[i])], "\r\n", 2 );
			at += strlen(m->headers[i]) + 2;
		}
	}
	memcpy( &w_buf[at], "\r\n", 2 );
	at += 2;
	ast_carefulwrite(s->fd, w_buf, at, s->writetimeout);
	pthread_mutex_unlock(&s->lock);

	return 0;
}

int _onconnect(struct mansession *s, struct message *m) {

	char banner[100];

	if( strlen( pc.forcebanner ) ) {
		sprintf(banner, "%s\r\n", pc.forcebanner);
	} else {
		sprintf(banner, "%s/%s\r\n", PROXY_BANNER, PROXY_VERSION);
	}
	pthread_mutex_lock(&s->lock);
	ast_carefulwrite(s->fd, banner, strlen(banner), s->writetimeout);
	pthread_mutex_unlock(&s->lock);

	return 0;
}

