/* 	Asterisk Manager Proxy
	Copyright (c) 2005-2008 David C. Troy <dave@popvox.com>
	
	This program is free software, distributed under the terms of
	the GNU General Public License.

	astmanproxy.c
	contains the proxy server core, initialization, thread launching,
	loops, and exit routines
*/

#include "astmanproxy.h"

extern int LoadHandlers( void );
extern void ReadConfig( void );
extern void ReadPerms( void );
extern FILE *OpenLogfile( void );
extern int SetProcUID( void );

extern void *proxyaction_do(char *proxyaction, struct message *m, struct mansession *s);
extern void *ProxyLogin(struct mansession *s, struct message *m);
extern void *ProxyLogoff(struct mansession *s, struct message *m);
extern void *ProxyFullyBooted(struct mansession *s);
extern int  ValidateAction(struct message *m, struct mansession *s, int inbound);
extern int  AddToStack(struct message *m, struct mansession *s, int withbody);
extern void DelFromStack(struct message *m, struct mansession *s);
extern void FreeStack(struct mansession *s);
extern void ResendFromStack(char* uniqueid, struct mansession *s, struct message *m, struct message *m2);

int ConnectAsterisk(struct mansession *s);

struct proxyconfig pc;
struct mansession *sessions = NULL;
struct iohandler *iohandlers = NULL;

pthread_rwlock_t sessionlock;
pthread_mutex_t serverlock;
pthread_mutex_t userslock;
pthread_mutex_t loglock;
pthread_mutex_t debuglock;
static int asock = -1;
FILE *proxylog;
int debug = 0;
int foreground = 0;

void hup(int sig) {
	if (proxylog) {
		fflush(proxylog);
		fclose(proxylog);
	}
	proxylog = OpenLogfile();
	logmsg("Received HUP -- reopened log");
	ReadPerms();
	logmsg("Received HUP -- reread permissions");
}

void leave(int sig) {
	struct mansession *c;
	struct message sm, cm;
	struct iohandler *io;
	struct ast_server *srv;
	char iabuf[INET_ADDRSTRLEN];
	void *res;
	struct timespec ts;


	/* Message to send to servers */
	memset(&sm, 0, sizeof(struct message));
	AddHeader(&sm, "Action: Logoff");

	/* Message to send to clients */
	memset(&cm, 0, sizeof(struct message));
	AddHeader(&cm, PROXY_SHUTDOWN);

	if (debug)
	debugmsg("Notifying and closing sessions");
	pthread_rwlock_wrlock(&sessionlock);
	while (sessions) {
		c = sessions;
		sessions = sessions->next;

		if( c->t ) {
			ts.tv_sec = 1;	/* Timed join prevents us blocking */
			ts.tv_nsec = 0;
			pthread_cancel( c->t );
			pthread_timedjoin_np( c->t, &res, &ts );
		}
		if (c->server) {
			if (debug)
				debugmsg("asterisk@%s: closing server session", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
			c->output->write(c, &sm);
			logmsg("Shutdown, closed server %s", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
		} else {
			if (debug)
				debugmsg("client@%s: closing client session", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
			c->output->write(c, &cm);
			logmsg("Shutdown, closed client %s", ast_inet_ntoa(iabuf, sizeof(iabuf), c->sin.sin_addr));
		}
		close_sock(c->fd);	/* close tcp & ssl socket */
		FreeStack(c);
		pthread_mutex_destroy(&c->lock);
		free(c);
	}
	pthread_rwlock_unlock(&sessionlock);
	
	FreeHeaders(&sm);
	FreeHeaders(&cm);

	/* unload server list */
	while (pc.serverlist) {
		srv = pc.serverlist;
		pc.serverlist = srv->next;
		if (debug)
			debugmsg("asterisk@%s: forgetting", srv->ast_host);
		free(srv);
	}

	if (debug)
	debugmsg("Closing listener socket");
	close_sock(asock);		/* close tcp & ssl socket */

	/* unload io handlers */
	while (iohandlers) {
		io = iohandlers;
		iohandlers = iohandlers->next;
		if (debug)
			debugmsg("unloading: %s", io->formatname);
		dlclose(io->dlhandle);
		free(io);
	}

	if(debug)
	debugmsg("Done!\n");
	logmsg("Proxy stopped; shutting down.");

	fclose(proxylog);
	pthread_rwlock_destroy(&sessionlock);
	pthread_mutex_destroy(&loglock);
	pthread_mutex_destroy(&debuglock);
	exit(sig);
}

void Version( void )
{
	printf("astmanproxy: Version %s, (C) David C. Troy 2005-2008\n", PROXY_VERSION);
	return;
}

void Usage( void )
{
	printf("Usage: astmanproxy [-d|-h|-v]\n");
	printf(" -d : Start in Debug Mode\n");
	printf(" -f : Run in foreground. Don't fork\n");
	printf(" -g : Enable core dumps\n");
	printf(" -h : Displays this message\n");
	printf(" -v : Displays version information\n");
	printf("Start with no options to run as daemon\n");
	return;
}

void destroy_session(struct mansession *s)
{
	struct mansession *cur, *prev = NULL;
	char iabuf[INET_ADDRSTRLEN];

	pthread_rwlock_wrlock(&sessionlock);
	cur = sessions;
	while(cur) {
		if (cur == s)
			break;
		prev = cur;
		cur = cur->next;
	}
	if (cur) {
		if (prev)
			prev->next = cur->next;
		else
			sessions = cur->next;
		debugmsg("Connection closed: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
		close_sock(s->fd);	/* close tcp/ssl socket */
		FreeStack(s);
		pthread_mutex_destroy(&s->lock);
		free(s);
	} else if (debug)
		debugmsg("Trying to delete non-existent session %p?\n", s);
	pthread_rwlock_unlock(&sessionlock);

	/* If there are no servers and no clients, why are we here? */
	if (!sessions) {
		logmsg("Cannot connect to any servers! Leaving!");
		leave(0);
	}
}

int WriteClients(struct message *m) {
	struct mansession *c;
	char *actionid;
	char *uniqueid;
	char *event;
	int valret, autofilter;


	// We stash New Channel events in case they are filtered and need to be
	// re-played at a later time. Hangup events also clean the list
	// after being sent.
	event = astman_get_header(m, "Event");
	int is_nc = 0;
	if( !strcasecmp( event, "Newchannel" ) ) {
		AddToStack(m, m->session, 1);
		is_nc = 1;	// Make sure we don't resend it from Stack.
	} else if( !strcasecmp( event, "Newstate" ) ) {
		AddToStack(m, m->session, 2);
		is_nc = 1;      // Make sure we don't resend it from Stack.
	}

	pthread_rwlock_rdlock(&sessionlock);
	c = sessions;
	while (c) {
		if ( c->server || m->hdrcount<2 ) {
			if( debug > 4 && c->server )
				debugmsg("Not sending server message back to a server");
			if( debug > 4 && m->hdrcount<2 )
				debugmsg("Skipping short message of %d lines.", m->hdrcount);
			c = c->next;
			continue;
		}
		autofilter = -1; // Default to not enabled...
		if( debug > 8 )
			debugmsg("Autofilter = %d, ActionID = %s", c->autofilter, c->actionid);
		if (c->autofilter && c->actionid) {
			if( debug > 5 )
				debugmsg("Checking ActionID filtering");
			actionid = astman_get_header(m, ACTION_ID);
			if ( c->autofilter == 1 && !strcmp(actionid, c->actionid) )
	// Original AutoFilter
				autofilter = 1;
			else if ( c->autofilter == 2 && *actionid == '\0' )
	// No actionID, so filter does not apply.
				autofilter = -1;
			else if ( c->autofilter == 2 && !strncmp(actionid, c->actionid, strlen(c->actionid)) ) {
	// New AutoFilter, actionid like "ast123-XX"
				memmove( actionid, actionid+strlen(c->actionid), strlen(actionid)+1-strlen(c->actionid));
				autofilter = 1;
			} else if (debug > 5) {
				autofilter = 0;
				debugmsg("ActionID Filtered (blocked) a message to a client");
			}
		}

                if ( pc.authrequired && !c->authenticated ) {
                        debugmsg("Validate Filtered a message to a not-logged-in client");
                } else if ( (valret=ValidateAction(m, c, 1)) || autofilter == 1 ) {
// If VALRET > 1, then we may want to send a retrospective NewChannel before
// writing out this event...
// Send the retrospective Newchannel from the cache (m->session->cache) to this client (c)...
 			if( debug > 4 && valret )
				debugmsg("Validate allowed a message to a client, ret=%d", valret);
 			if( (valret & ATS_UNIQUE) && m->session && !is_nc ) {
				struct message m_temp;
				struct message m_temp2;
				m_temp.hdrcount=0;
				m_temp.in_command=0;
				m_temp.session=m->session;
				m_temp2.hdrcount=0;
				m_temp2.in_command=0;
				m_temp2.session=m->session;
				uniqueid = astman_get_header(m, "UniqueID");
				ResendFromStack(uniqueid, m->session, &m_temp, &m_temp2);
				c->output->write(c, &m_temp);
				if( m_temp2.hdrcount )
					c->output->write(c, &m_temp2);
 			}
 			if( (valret & ATS_SRCUNIQUE) && m->session ) {
				struct message m_temp;
				struct message m_temp2;
				m_temp.hdrcount=0;
				m_temp.in_command=0;
				m_temp.session=m->session;
				m_temp2.hdrcount=0;
				m_temp2.in_command=0;
				m_temp2.session=m->session;
				uniqueid = astman_get_header(m, "SrcUniqueID");
				if( *uniqueid == '\0' )
					uniqueid = astman_get_header(m, "Uniqueid1");
				ResendFromStack(uniqueid, m->session, &m_temp, &m_temp2);
				c->output->write(c, &m_temp);
				if( m_temp2.hdrcount )
					c->output->write(c, &m_temp2);
 			}
 			if( (valret & ATS_DSTUNIQUE) && m->session ) {
				struct message m_temp;
				struct message m_temp2;
				m_temp.hdrcount=0;
				m_temp.in_command=0;
				m_temp.session=m->session;
				m_temp2.hdrcount=0;
				m_temp2.in_command=0;
				m_temp2.session=m->session;
				uniqueid = astman_get_header(m, "DestUniqueID");
				if( *uniqueid == '\0' )
					uniqueid = astman_get_header(m, "Uniqueid2");
				ResendFromStack(uniqueid, m->session, &m_temp, &m_temp2);
				c->output->write(c, &m_temp);
				if( m_temp2.hdrcount )
					c->output->write(c, &m_temp2);
 			}
			if( autofilter != 0 )
				c->output->write(c, m);

			if (c->inputcomplete) {
				if ( c->untilevent == '\0' || !strncasecmp( event, c->untilevent, MAX_LEN ) ) {
					pthread_mutex_lock(&c->lock);
					c->outputcomplete = 1;
					pthread_mutex_unlock(&c->lock);
					if( debug > 2 )
						debugmsg("Set output complete flag. untilevent = %s, event = %s", c->untilevent, event);
				}
			}
		} else if ( !c->server && m->hdrcount>1 && !valret && debug > 5)
			debugmsg("Validate Filtered a message to a client");
		c = c->next;
	}
	pthread_rwlock_unlock(&sessionlock);
	if( !strcasecmp( event, "Hangup" ) ) {
		DelFromStack(m, m->session);
	}
	return 1;
}

int WriteAsterisk(struct message *m) {
	char *dest;
	struct mansession *u, *s, *first;

	first = NULL;
	dest = NULL;

	u = m->session;

	if( u->user.server[0] != '\0' )
		dest = u->user.server;
	else
		dest = astman_get_header(m, "Server");

	if (debug && *dest) debugmsg("set destination: %s", dest);
	pthread_rwlock_rdlock(&sessionlock);
	s = sessions;
	while ( s ) {
		if ( s->server && (s->connected > 0) ) {
			if ( !first )
				first = s;
			if (*dest && !strcasecmp(dest, s->server->ast_host) )
				break;
		}
		s = s->next;
	}
	if (!s)
		s = first;	

	pthread_rwlock_unlock(&sessionlock);

	/* Check for no servers and empty block -- Don't pester Asterisk if it is one*/
	if (!s || !s->server || (!m->hdrcount && !m->headers[0][0]) )
		return 1;

	debugmsg("writing block to %s", s->server->ast_host);
	s->output->write(s, m);
	return 1;
}

void *setactionid(char *actionid, struct message *m, struct mansession *s)
{
	pthread_mutex_lock(&s->lock);
	if( s->autofilter < 2 ) {	// Either save ActionID
		strncpy(s->actionid, actionid, MAX_LEN);
	} else if( strlen(s->actionid) + strlen(actionid) < MAX_LEN ) {	// Or modify it
		memmove(actionid+strlen(s->actionid), actionid, strlen(actionid)+strlen(s->actionid));
		strncpy(actionid, s->actionid, strlen(s->actionid));
	}
	pthread_mutex_unlock(&s->lock);

	return 0;
}

/* Handles proxy client sessions; closely based on session_do from asterisk's manager.c */
void *session_do(struct mansession *s)
{
	struct message m;
	int res, i;
	char iabuf[INET_ADDRSTRLEN];
	char *proxyaction, *actionid, *action, *key;

	if (s->input->onconnect)
		s->input->onconnect(s, &m);
	if (s->autofilter == 2) {
		pthread_mutex_lock(&s->lock);
		snprintf(s->actionid, MAX_LEN - 20, "amp%d-", s->fd);
		if (debug > 3)
			debugmsg("Setting actionID root to %s for new connection", s->actionid);
		pthread_mutex_unlock(&s->lock);
	}

	// Signal settings are not always inherited by threads, so ensure we ignore this one
	// as it is handled through error returns
	(void) signal(SIGPIPE, SIG_IGN);
	for (;;) {
		/* Get a complete message block from input handler */
		memset( &m, 0, sizeof(struct message) );
		if (debug > 3)
			debugmsg("calling %s_read...", s->input->formatname);
		res = s->input->read(s, &m);
		if (debug > 3)
			debugmsg("%s_read result = %d", s->input->formatname, res);
		m.session = s;

		if (res > 0) {
			if (debug) {
				for(i=0; i<m.hdrcount; i++) {
					debugmsg("client@%s got: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), m.headers[i]);
				}
			}
		
			/* Check for anything that requires proxy-side processing */
			if (pc.key[0] != '\0' && !s->authenticated) {
			key = astman_get_header(&m, "ProxyKey");
			if (!strcmp(key, pc.key) ) {
				pthread_mutex_lock(&s->lock);
				s->authenticated = 1;
				pthread_mutex_unlock(&s->lock);
			} else
				break;
			}

			proxyaction = astman_get_header(&m, "ProxyAction");
			actionid = astman_get_header(&m, ACTION_ID);
			action = astman_get_header(&m, "Action");
			if ( !strcasecmp(action, "Login") ) {
				s->authenticated = 0;
				ProxyLogin(s, &m);
				ProxyFullyBooted(s);
			} else if ( !strcasecmp(action, "Logoff") )
				ProxyLogoff(s, &m);
			else if ( !strcasecmp(action, "Challenge") )
				ProxyChallenge(s, &m);
			else if ( !(*proxyaction == '\0') )
				proxyaction_do(proxyaction, &m, s);
			else if ( ValidateAction(&m, s, 0) ) {
				if ( !(*actionid == '\0') )
					setactionid(actionid, &m, s);
				if ( !WriteAsterisk(&m) )
					break;
			} else {
				SendError(s, "Action Filtered", actionid);
			}
		} else if (res < 0)
			break;

		FreeHeaders(&m);
	}

	FreeHeaders(&m);
	destroy_session(s);
	if (debug)
		debugmsg("--- exiting session_do thread ---");
	pthread_exit(NULL);
	return NULL;
}

void CleanupAsterisk( void * arg )
{
	FreeHeaders(arg);
	free(arg);
}

void *HandleAsterisk(struct mansession *s)
{
	struct message *m;
	int res,i;
	char iabuf[INET_ADDRSTRLEN];

	if (ConnectAsterisk(s))
		goto leave;
	if (! (m = malloc(sizeof(struct message))) )
		goto leave;
	memset(m, 0, sizeof(struct message) );
	
	pthread_cleanup_push(&CleanupAsterisk, m);

	// Signal settings are not always inherited by threads, so ensure we ignore this one
	(void) signal(SIGPIPE, SIG_IGN);
	for (;;) {
		if (debug)
			debugmsg("asterisk@%s: attempting read...", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
		m->hdrcount = 0;
		m->in_command = 0;
		m->session = (void*)0;
		res = s->input->read(s, m);
		m->session = s;

		if (res > 0) {
			if (debug) {
				for(i=0; i<m->hdrcount; i++) {
					debugmsg("asterisk@%s got: %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), m->headers[i]);
				}
			}

			if (!s->connected) {
				if ( !strcmp("Authentication accepted", astman_get_header(m, "Message")) ) {
					s->connected = 1;
					if (debug)
					debugmsg("asterisk@%s: connected successfully!", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr) );
				}
				if ( !strcmp("Authentication failed", astman_get_header(m, "Message")) ) {
					s->connected = -1;
				}
			}

			m->session = s;
			AddHeader(m, "Server: %s", m->session->server->ast_host);

			if (!WriteClients(m))
				break;
		} else if (res < 0) {
			/* TODO: do we need to do more than this here? or something different? */
			if ( debug )
				debugmsg("asterisk@%s: Not connected", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
			if ( ConnectAsterisk(s) )
				break;
		}
		
		FreeHeaders(m);
	}
	FreeHeaders(m);
	free(m);
	   
	pthread_cleanup_pop(1);

leave:
	if (debug)
		debugmsg("asterisk@%s: Giving up and exiting thread", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr) );
	destroy_session(s);
	pthread_exit(NULL);
	return NULL;
}

int ConnectAsterisk(struct mansession *s) {
	char iabuf[INET_ADDRSTRLEN];
	int r = 1, res = 0;
	struct message m;

	/* Don't try to do this if auth has already failed! */
	if (s->connected < 0 )
		return 1;
	else
		s->connected = 0;

	if (debug)
	debugmsg("asterisk@%s: Connecting (u=%s, p=%s, ssl=%s)", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr),
		 s->server->ast_user, s->server->ast_pass, s->server->use_ssl ? "on" : "off");

	/* Construct auth message just once */
	memset( &m, 0, sizeof(struct message) );
	AddHeader(&m, "Action: Login");
	AddHeader(&m, "Username: %s", s->server->ast_user);
	AddHeader(&m, "Secret: %s", s->server->ast_pass);
	AddHeader(&m, "Events: %s", s->server->ast_events);

	s->inlen = 0;
	s->inoffset = 0;
	s->inbuf[0] = '\0';

	for ( ;; ) {
		if ( ast_connect(s) == -1 ) {
			if (debug)
				debugmsg("asterisk@%s: Connect failed, Retrying (%d) %s [%d]",
			ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), r, strerror(errno), errno );
			if (pc.maxretries && (++r>pc.maxretries) ) {
				res = 1;
				break;
			} else
				sleep(pc.retryinterval);
		} else {
			/* Send login */
			s->output->write(s, &m);
			res = 0;
			break;
		}
	}
	FreeHeaders(&m);

	return res;
}

int StartServer(struct ast_server *srv) {

	struct mansession *s;
	struct hostent *ast_hostent;

	char iabuf[INET_ADDRSTRLEN];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	ast_hostent = gethostbyname(srv->ast_host);
	if (!ast_hostent) {
		logmsg("Cannot resolve host %s, cannot add!", srv->ast_host);
		debugmsg("Cannot resolve host %s, cannot add!", srv->ast_host);
		return 1;
	}

	s = malloc(sizeof(struct mansession));
	if ( !s ) {
		logmsg("Failed to allocate server session: %s\n", strerror(errno));
		debugmsg("Failed to allocate server session: %s\n", strerror(errno));
		return 1;
	}

	memset(s, 0, sizeof(struct mansession));
	SetIOHandlers(s, "standard", "standard");
	s->server = srv;
	s->writetimeout = pc.asteriskwritetimeout;

	bzero((char *) &s->sin,sizeof(s->sin));
	s->sin.sin_family = AF_INET;
	memcpy( &s->sin.sin_addr.s_addr, ast_hostent->h_addr, ast_hostent->h_length );
	s->sin.sin_port = htons(atoi(s->server->ast_port));
	s->fd = socket(AF_INET, SOCK_STREAM, 0);

	pthread_rwlock_wrlock(&sessionlock);
	s->next = sessions;
	sessions = s;
	pthread_rwlock_unlock(&sessionlock);

	logmsg("Allocated Asterisk server session for %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
	if (debug) {
		debugmsg("asterisk@%s: Allocated server session", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
		debugmsg("Set %s input format to %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), s->input->formatname);
		debugmsg("Set %s output format to %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), s->output->formatname);
	}

	if (pthread_create(&s->t, &attr, (void *)HandleAsterisk, s))
		destroy_session(s);
	else
		debugmsg("launched ast %s thread!", s->server->ast_host);

	pthread_attr_destroy(&attr);
	return 0;
}

int LaunchAsteriskThreads() {

	struct ast_server *srv;

	srv = pc.serverlist;
	while (srv) {
		StartServer(srv);
		srv = srv->next;
	}
	return 0;
}

int SetIOHandlers(struct mansession *s, char *ifmt, char *ofmt)
{
	int res = 0;
	struct iohandler *io;

	io = iohandlers;
	pthread_mutex_lock(&s->lock);
	while (io) {
		if ( !strcasecmp(io->formatname, ifmt) )
			s->input = io;

		if ( !strcasecmp(io->formatname, ofmt) )
			s->output = io;

		io = io->next;
	}

	/* set default handlers if non match was found */
	if (!s->output) {
		s->output = iohandlers;
		res = 1;
	}

	if (!s->input) {
		s->input = iohandlers;
		res = 1;
	}
	pthread_mutex_unlock(&s->lock);

	return res;
}

static void *accept_thread()
{
	int as;
	struct sockaddr_in sin;
	socklen_t sinlen;
	struct mansession *s;
	struct protoent *p;
	int arg = 1;
	int flags;
	pthread_attr_t attr;
	char iabuf[INET_ADDRSTRLEN];
	int is_encrypted;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	for (;;) {
		sinlen = sizeof(sin);
		as = accept(asock, (struct sockaddr *)&sin, &sinlen);
		if (as < 0) {
			logmsg("Accept returned -1: %s\n", strerror(errno));
			continue;
		}
		p = (struct protoent *)getprotobyname("tcp");
		if( p ) {
			if( setsockopt(as, p->p_proto, TCP_NODELAY, (char *)&arg, sizeof(arg) ) < 0 ) {
				logmsg("Failed to set listener tcp connection to TCP_NODELAY mode: %s\n", strerror(errno));
			}
		}

		/* SSL stuff below */
		is_encrypted = is_encrypt_request(pc.sslclhellotimeout, as);
		debugmsg("is_encrypted: %d", is_encrypted);
		if (is_encrypted > 0) {
			if (!pc.acceptencryptedconnection) {
				if( debug )
					debugmsg("Accepting encrypted connection disabled, closing the connection \n");
				close_sock(as);
				continue;
			} else {
				if((as = saccept(as)) >= 0 ) {
					if( debug )
						debugmsg("Can't accept the ssl connection, since SSL init has failed for certificate reason\n");
					close_sock(as);
					continue;
				}
			}
		} else if (is_encrypted == -1) {
			logmsg("SSL version 2 is unsecure, we don't support it\n");
			close_sock(as);
			continue;
		}
		if ( (! pc.acceptunencryptedconnection) && (as >= 0)) {
			logmsg("Unencrypted connections are not accepted and we received an unencrypted connection request\n");
			close_sock(as);
			continue;
		}
		/* SSL stuff end */

		s = malloc(sizeof(struct mansession));
		if ( !s ) {
			logmsg("Failed to allocate listener session: %s\n", strerror(errno));
			continue;
		}
		memset(s, 0, sizeof(struct mansession));
		memcpy(&s->sin, &sin, sizeof(sin));

		/* For safety, make sure socket is non-blocking */
		flags = fcntl(get_real_fd(as), F_GETFL);
		fcntl(get_real_fd(as), F_SETFL, flags | O_NONBLOCK);

		pthread_mutex_init(&s->lock, NULL);
		s->fd = as;
		SetIOHandlers(s, pc.inputformat, pc.outputformat);
		s->autofilter = pc.autofilter;
		s->writetimeout = pc.clientwritetimeout;
		s->server = NULL;

		pthread_rwlock_wrlock(&sessionlock);
		s->next = sessions;
		sessions = s;
		pthread_rwlock_unlock(&sessionlock);

		logmsg("Connection received from %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
		if (debug) {
			debugmsg("Connection received from %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr));
			debugmsg("Set %s input format to %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), s->input->formatname);
			debugmsg("Set %s output format to %s", ast_inet_ntoa(iabuf, sizeof(iabuf), s->sin.sin_addr), s->output->formatname);
		}

		if (pthread_create(&s->t, &attr, (void *)session_do, s))
			destroy_session(s);
	}
	pthread_attr_destroy(&attr);
	return NULL;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in serv_sock_addr, client_sock_addr; 
	int cli_addrlen;
	struct linger lingerstruct;	/* for socket reuse */
	int flag;				/* for socket reuse */
	pid_t pid;
	char i;
	struct rlimit l;
	int core = 0;

	/* Figure out if we are in debug mode, handle other switches */
	while (( i = getopt( argc, argv, "dhvfg" ) ) != EOF )
	{
		switch( i ) {
			case 'f':
 				foreground=1;
				break;
			case 'd':
				debug++;
				break;
			case 'g':
				core=1;
				break;
			case 'h':
				Usage();
				exit(0);
			case 'v':
				Version();
				exit(0);
			case '?':
				Usage();
				exit(1);
		}
	}


	ReadConfig();
	proxylog = OpenLogfile();
	debugmsg("loading handlers");
	LoadHandlers();
	debugmsg("loaded handlers");
	
	if(core) {
		memset(&l, 0, sizeof(l));
		l.rlim_cur = RLIM_INFINITY;
		l.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &l)) {
			fprintf(stderr, "Unable to disable core size resource limit: %s\n", strerror(errno));
		}
	}
	
	if (SetProcUID()) {
		fprintf(stderr,"Cannot set user/group!	Check proc_user and proc_group config setting!\n");
		exit(1);
	}
	
	if(core) {
		if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
			fprintf(stderr, "Unable to set the process for core dumps after changing to a non-root user. %s\n", strerror(errno));
		}

		char dir[PATH_MAX];
		if (!getcwd(dir, sizeof(dir)) || eaccess(dir, W_OK)) {
			fprintf(stderr, "Unable to write to the running directory (%s).  Changing to '/tmp'.\n", strerror(errno));
			if (chdir("/tmp")) {
				fprintf(stderr, "chdir(\"/\") failed?!! %s\n", strerror(errno));
			}
		}
	}

	/* If we are not in debug mode, then fork to background */
	if (!debug && !foreground) {
		if ( (pid = fork()) < 0)
			exit( 1 );
		else if ( pid > 0)
			exit( 0 );
	}

	/* Setup signal handlers */
	(void) signal(SIGINT,leave);
	(void) signal(SIGHUP,hup);
	(void) signal(SIGTERM,leave);
	(void) signal(SIGPIPE, SIG_IGN);

	/* Initialize global mutexes */
	pthread_rwlock_init(&sessionlock, NULL);
	pthread_mutex_init(&userslock, NULL);
	pthread_mutex_init(&loglock, NULL);
	pthread_mutex_init(&debuglock, NULL);

	/* Read initial state for user permissions */
	ReadPerms();

	/* Initialize SSL Client-Side Context */
	client_init_secure();

	/* Initialize global client/server list */
	sessions = NULL;
	LaunchAsteriskThreads();

	/* Setup listener socket to setup new sessions... */
	if ((asock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	fprintf(stderr,"Cannot create listener socket!\n");
	exit(1);
	}
	bzero((char *) &serv_sock_addr, sizeof serv_sock_addr );
	serv_sock_addr.sin_family = AF_INET;

	if ( !strcmp(pc.listen_addr,"*") )
		serv_sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	else
		serv_sock_addr.sin_addr.s_addr = inet_addr( pc.listen_addr);
		
	serv_sock_addr.sin_port = htons((short)pc.listen_port);

	/* Set listener socket re-use options */
	flag = 1;
	if(setsockopt(asock, SOL_SOCKET, SO_REUSEADDR, (void *)&flag, sizeof(flag)) < 0) {
		fprintf(stderr,"Error setting SO_REUSEADDR on listener socket!\n");
	}
	lingerstruct.l_onoff = 1;
	lingerstruct.l_linger = 5;
	if(setsockopt(asock, SOL_SOCKET, SO_LINGER, (void *)&lingerstruct, sizeof(lingerstruct)) < 0) {
		fprintf(stderr,"Error setting SO_LINGER on listener socket!\n");
	}
	
	if (bind(asock, (struct sockaddr *) &serv_sock_addr, sizeof serv_sock_addr ) < 0) {
		fprintf(stderr,"Cannot bind to listener socket!\n");
		exit(1);
	}

	listen(asock, 5);
	cli_addrlen = sizeof(client_sock_addr);
	if (debug)
		debugmsg("Listening for connections");
	logmsg("Proxy Started: Listening for connections");

	/* Launch listener thread */
	accept_thread();

	pthread_exit(NULL);
	exit(0);
}
