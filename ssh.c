
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#ifdef LIBSSH_STANDALONE
  #include <lua.h>
  #include <lualib.h>
  #include <lauxlib.h>
#else
  #include <lite_xl_plugin_api.h>
#endif

// TODO
// 1. Host checking.
// 2. Callback-based password entry.
// 3. Hook up lite-xl file functions
// 4. Add in proc execute stuff for remote executions of things.
// 5. Hook into terminal if installed with a shell.
// 6. Allow for lua style file operations, ratrher than just reading amounts of bytes (i.e. :read("*l"), etc..)


typedef enum {
  STATE_DISCONNECTED,
  STATE_CONNECTING,
  STATE_HANDSHAKING,
  STATE_AUTHENTICATING,
  STATE_CONNECTED
} ssh_connection_state_e;

typedef struct {
  int socket;
  unsigned int port;
  ssh_connection_state_e state;
  LIBSSH2_SESSION* ssh;
  LIBSSH2_SFTP* sftp;
} ssh_session_t;

static ssh_session_t* lua_tossh(lua_State* L, int index) {
  luaL_checktype(L, index, LUA_TTABLE);
  lua_getfield(L, index, "__ssh");
  ssh_session_t* session = lua_touserdata(L, -1);
  lua_pop(L, 1);
  return session;
}

static int lua_pushssherr(lua_State* L, ssh_session_t* session) {
  lua_pushnil(L);
  char* err;
  int len;
  libssh2_session_last_error(session->ssh, &err, &len, 0);
  lua_pushlstring(L, err, len);
  return 2;
}


static int lua_pushsftperr(lua_State* L, ssh_session_t* session, int rc) {
  lua_pushnil(L);
  int errcode = libssh2_sftp_last_error(session->sftp);
  if (errcode == LIBSSH2_ERROR_SFTP_PROTOCOL) {
    lua_pushstring(L, strerror(rc));
  } else {
    char* err;
    int len;
    libssh2_session_last_error(session->ssh, &err, &len, 0);
    lua_pushlstring(L, err, len);
  }
  return 2;
}

static int lua_sshyield(lua_State* L, lua_KFunction continuation) {
  ssh_session_t* session = lua_tossh(L, 1);
  lua_newtable(L);
  lua_pushinteger(L, session->socket);
  lua_setfield(L, -2, "fd");
  return lua_yieldk(L, 1, 0, continuation);
}


void lua_pushattributes(lua_State* L, LIBSSH2_SFTP_ATTRIBUTES* attributes) {
  lua_newtable(L);
  lua_pushinteger(L, attributes->filesize);
  lua_setfield(L, -2, "size");
  if (LIBSSH2_SFTP_S_ISREG(attributes->flags)) {
    lua_pushstring(L, "file");
  } else if (LIBSSH2_SFTP_S_ISDIR(attributes->flags)) {
    lua_pushstring(L, "dir");
  } else if (LIBSSH2_SFTP_S_ISLNK(attributes->flags)) {
    //sftp_attributes lstats = sftp_lstat(session_>sftp, luaL_checkstring(L, 1));
    //lua_pushstring(L, "file");
    //lua_pushstring(L, "dir");
    lua_pushnil(L);
  } else {
    lua_pushnil(L);
  }
  lua_setfield(L, -2, "type");
  lua_pushnumber(L, attributes->mtime);
  lua_setfield(L, -2, "modified");
}

int f_file_closek(lua_State* L, int status, lua_KContext context) {
  LIBSSH2_SFTP_HANDLE** file = luaL_checkudata(L, 1, "sftp_file");
  if (*file) {
    if (libssh2_sftp_close(*file) == LIBSSH2_ERROR_EAGAIN)
      return lua_sshyield(L, f_file_closek);
    *file = NULL;
  }
  return 0;
}
int f_file_close(lua_State* L) { return f_file_closek(L, 0, 0); }


int f_file_readk(lua_State* L, int status, lua_KContext context) {
  LIBSSH2_SFTP_HANDLE** file = luaL_checkudata(L, 1, "sftp_file");
  if (!*file) {
    lua_pushnil(L);
    lua_pushliteral(L, "invalid file handle");
    return 2;
  }
  lua_getiuservalue(L, 1, 1);
  ssh_session_t* session = lua_tossh(L, -1);
  size_t len = luaL_checkinteger(L, 2);
  char* buffer = malloc(len);
  ssize_t bytes = libssh2_sftp_read(*file, buffer, len);
  if (bytes == LIBSSH2_ERROR_EAGAIN) {
    free(buffer);
    return lua_sshyield(L, f_file_readk);
  } else if (bytes < 0) {
    free(buffer);
    return lua_pushsftperr(L, session, bytes);
  }
  lua_pushlstring(L, buffer, bytes);
  free(buffer);
  return 1;
}
int f_file_read(lua_State* L) { return f_file_readk(L, 0, 0); }

int f_file_seek(lua_State* L) {
  LIBSSH2_SFTP_HANDLE** file = luaL_checkudata(L, 1, "sftp_file");
  if (!*file) {
    lua_pushnil(L);
    lua_pushliteral(L, "invalid file handle");
    return 2;
  }
  libssh2_sftp_seek64(*file, luaL_checkinteger(L, 2));
  lua_pushboolean(L, 1);
  return 1;
}


int f_file_writek(lua_State* L, int status, lua_KContext context) {
  LIBSSH2_SFTP_HANDLE** file = luaL_checkudata(L, 1, "sftp_file");
  if (!*file) {
    lua_pushnil(L);
    lua_pushliteral(L, "invalid file handle");
    return 2;
  }
  lua_getiuservalue(L, 1, 1);
  ssh_session_t* session = lua_tossh(L, -1);
  size_t len;
  const char* buffer = luaL_checklstring(L, 2, &len);
  ssize_t bytes = libssh2_sftp_write(*file, buffer, len);
  if (bytes == LIBSSH2_ERROR_EAGAIN)
    return lua_sshyield(L, f_file_writek);
  else if (bytes < 0)
    return lua_pushsftperr(L, session, bytes);
  lua_pushinteger(L, bytes);
  return 1;
}
int f_file_write(lua_State* L) { return f_file_writek(L, 0, 0); }


static luaL_Reg sftp_file_api[] = {
  { "__gc",       f_file_close },
  { "close",      f_file_close },
  { "read",       f_file_read },
  { "seek",       f_file_seek },
  { "write",      f_file_write } 
};


int f_dir_closek(lua_State* L, int status, lua_KContext context) {
  LIBSSH2_SFTP_HANDLE** dir = luaL_checkudata(L, 1, "sftp_dir");
  if (*dir) {
    if (libssh2_sftp_closedir(*dir) == LIBSSH2_ERROR_EAGAIN)
      return lua_sshyield(L, f_dir_closek);
    *dir = NULL;
  }
  return 0;
}
int f_dir_close(lua_State* L) { return f_dir_closek(L, 0, 0); }

int f_dir_readk(lua_State* L, int status, lua_KContext context) {
  LIBSSH2_SFTP_HANDLE** dir = luaL_checkudata(L, 1, "sftp_dir");
  if (!*dir)
    return 0;
  lua_getiuservalue(L, 1, 1);
  ssh_session_t* session = lua_tossh(L, -1);
  char buffer[PATH_MAX] = {0};
  LIBSSH2_SFTP_ATTRIBUTES attributes;
  int result = libssh2_sftp_readdir(*dir, buffer, sizeof(buffer), &attributes);
  if (result == LIBSSH2_ERROR_EAGAIN)
    return lua_sshyield(L, f_dir_readk);
  else if (result < 0)
    return lua_pushsftperr(L, session, result);
  if (result == 0) {
    lua_pushnil(L);
    return 1;
  }
  lua_pushattributes(L, &attributes);
  lua_pushlstring(L, buffer, result);
  lua_setfield(L, -2, "path");
  return 1;
}
int f_dir_read(lua_State* L) { return f_dir_readk(L, 0, 0); }

static luaL_Reg sftp_dir_api[] = {
  { "read",      f_dir_read  },
  { "__gc",      f_dir_close },
  { "close",     f_dir_close },
};

static int f_ssh_disconnect(lua_State* L) {
  ssh_session_t* session = lua_tossh(L, 1);
  if (session->sftp)
    libssh2_sftp_shutdown(session->sftp);
  if (session->ssh) {
    libssh2_session_disconnect(session->ssh, "manual disconnection"); // should check for EAGAIN
    libssh2_session_free(session->ssh);
  }
  if (session->socket) {
    close(session->socket);
    session->socket = 0;
  }
  session->state = STATE_DISCONNECTED;
}


static int f_ssh_connectk(lua_State* L, int status, lua_KContext ctx) {
  ssh_session_t* session = lua_tossh(L, 1);
  switch (session->state) {
    case STATE_CONNECTING: {
      lua_getfield(L, 1, "host");
      const char* host = luaL_checkstring(L, -1);
      struct hostent *hostinfo = gethostbyname(host);
      struct sockaddr_in dest_addr = {0};
      if (!hostinfo) {
        lua_pushnil(L);
        lua_pushfstring(L, "unable to resolve hostname %s: %s", lua_tostring(L, -1), strerror(errno));
        return 2;
      }
      lua_pop(L, 1);
      dest_addr.sin_family = AF_INET;
      lua_getfield(L, 1, "port");
      dest_addr.sin_port = htons(luaL_optinteger(L, -1, 22));
      lua_pop(L, 1);
      dest_addr.sin_addr.s_addr = *(long*)(hostinfo->h_addr);  
      int result = connect(session->socket, (struct sockaddr*)(&dest_addr), sizeof(struct sockaddr_in));
      if (result == -1) {
        if (errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY)
          return lua_sshyield(L, f_ssh_connectk);
        lua_pushnil(L);
        lua_pushfstring(L, "unable to connect: %s", strerror(errno));
        return 2;
      }
      session->state = STATE_HANDSHAKING;
    }
    case STATE_HANDSHAKING: {
      int result = libssh2_session_handshake(session->ssh, session->socket);
      if (result == LIBSSH2_ERROR_EAGAIN)
        return lua_sshyield(L, f_ssh_connectk);
      else if (result != 0)
        return lua_pushssherr(L, session);
      session->state = STATE_AUTHENTICATING;
    } // deliberate fallthrough
    case STATE_AUTHENTICATING: {
      int password = -1;
      lua_getfield(L, 1, "user");
      lua_getfield(L, 1, "identity");
      if (!lua_isnil(L, -1))
        password = 0;
      lua_getfield(L, 1, "password");
      if (!lua_isnil(L, -1) && password == -1)
        password = 1;
      
      int result;
      if (password == 1) {
        result = libssh2_userauth_password(session->ssh, lua_tostring(L, -3), lua_tostring(L, -1));
      } else if (password == 0) {
        size_t username_len;
        const char* username = lua_tolstring(L, -3, &username_len);
        size_t identity_len;
        const char* identity = lua_tolstring(L, -2, &identity_len);
        size_t password_len;
        const char* password = lua_tolstring(L, -1, &password_len);
        result = libssh2_userauth_publickey_frommemory(session->ssh, username, username_len, NULL, 0, identity, identity_len, password);
      } else {
        lua_pushnil(L);
        lua_pushliteral(L, "requires eitehr a password or an identity");
        return 2;
      }
      lua_pop(L, 3);
      if (result == LIBSSH2_ERROR_EAGAIN)
        return lua_sshyield(L, f_ssh_connectk);
      else if (result)
        return lua_pushssherr(L, session);
      session->state = STATE_CONNECTED;
    }
  }
  return 1;
}

static int f_ssh_connect(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  luaL_setmetatable(L, "ssh");
  ssh_session_t* session = lua_newuserdata(L, sizeof(ssh_session_t));
  memset(session, 0, sizeof(ssh_session_t));
  lua_setfield(L, 1, "__ssh");
  session->ssh = libssh2_session_init();
  if (!session->ssh) {
    lua_pushnil(L);
    lua_pushliteral(L, "unable to allocate new ssh session");
    return 2;
  }
  lua_getfield(L, 1, "blocking");
  int nonblocking = lua_isyieldable(L);
  if (!lua_isnil(L, -1))
    nonblocking = !lua_toboolean(L, -1);
  lua_pop(L, 1);
  session->socket = socket(AF_INET, SOCK_STREAM, 0);
  if (!session->socket) {
    lua_pushnil(L);
    lua_pushfstring(L, "unable to create socket: %s", strerror(errno));
    return 2;
  }
  if (nonblocking)
    fcntl(session->socket, F_SETFL, fcntl(session->socket, F_GETFL) | O_NONBLOCK);
  session->state = STATE_CONNECTING;
  return f_ssh_connectk(L, 0, 0);
}

static int f_ssh_sftp(lua_State* L) {
  ssh_session_t* session = lua_tossh(L, 1);
  if (session && !session->sftp) {
    session->sftp = libssh2_sftp_init(session->ssh);
    if (!session->sftp)
      return lua_pushssherr(L, session);
  }
  return 0;
}

static int f_sftp_statk(lua_State* L, int status, lua_KContext context) {
  ssh_session_t* session = lua_tossh(L, 1);
  int rc = f_ssh_sftp(L);
  if (rc != 0)
    return rc;
  LIBSSH2_SFTP_ATTRIBUTES attributes;
  rc = libssh2_sftp_stat(session->sftp, luaL_checkstring(L, 2), &attributes);
  if (rc == LIBSSH2_ERROR_EAGAIN)
    return lua_sshyield(L, f_sftp_statk);
  else if (rc != 0)
    return lua_pushsftperr(L, session, rc);
  lua_pushattributes(L, &attributes);
  return 1;  
}
static int f_sftp_stat(lua_State* L) { return f_sftp_statk(L, 0, 0); }

static int f_sftp_mkdirk(lua_State* L, int status, lua_KContext context) { 
  ssh_session_t* session = lua_tossh(L, 1); 
  int rc = f_ssh_sftp(L); 
  if (rc != 0) 
    return rc;
  rc =  libssh2_sftp_mkdir(session->sftp, luaL_checkstring(L, 2), S_IRWXU);
  if (rc == LIBSSH2_ERROR_EAGAIN) 
    return lua_sshyield(L, f_sftp_mkdirk); 
  else if (rc != 0)
    return lua_pushsftperr(L, session, rc); 
  lua_pushboolean(L, 1); 
  return 1;
}
static int f_sftp_mkdir(lua_State* L) { return f_sftp_mkdirk(L, 0, 0); }

static int f_sftp_rmdirk(lua_State* L, int status, lua_KContext context) { 
  ssh_session_t* session = lua_tossh(L, 1); 
  int rc = f_ssh_sftp(L); 
  if (rc != 0) 
    return rc;
  rc =  libssh2_sftp_rmdir(session->sftp, luaL_checkstring(L, 2));
  if (rc == LIBSSH2_ERROR_EAGAIN) 
    return lua_sshyield(L, f_sftp_rmdirk); 
  else if (rc != 0)
    return lua_pushsftperr(L, session, rc); 
  lua_pushboolean(L, 1); 
  return 1;
}
static int f_sftp_rmdir(lua_State* L) { return f_sftp_rmdirk(L, 0, 0); }

static int f_sftp_renamek(lua_State* L, int status, lua_KContext context) { 
  ssh_session_t* session = lua_tossh(L, 1); 
  int rc = f_ssh_sftp(L); 
  if (rc != 0) 
    return rc;
  rc =  libssh2_sftp_rename(session->sftp, luaL_checkstring(L, 2), luaL_checkstring(L, 3));
  if (rc == LIBSSH2_ERROR_EAGAIN) 
    return lua_sshyield(L, f_sftp_renamek); 
  else if (rc != 0)
    return lua_pushsftperr(L, session, rc); 
  lua_pushboolean(L, 1); 
  return 1;
}
static int f_sftp_rename(lua_State* L) { return f_sftp_renamek(L, 0, 0); }

static int f_sftp_unlinkk(lua_State* L, int status, lua_KContext context) { 
  ssh_session_t* session = lua_tossh(L, 1); 
  int rc = f_ssh_sftp(L); 
  if (rc != 0) 
    return rc;
  rc =  libssh2_sftp_unlink(session->sftp, luaL_checkstring(L, 2));
  if (rc == LIBSSH2_ERROR_EAGAIN) 
    return lua_sshyield(L, f_sftp_unlinkk); 
  else if (rc != 0)
    return lua_pushsftperr(L, session, rc); 
  lua_pushboolean(L, 1); 
  return 1;
}
static int f_sftp_unlink(lua_State* L) { return f_sftp_unlinkk(L, 0, 0); }


static int f_sftp_opendirk(lua_State* L, int status, lua_KContext context) {
  ssh_session_t* session = lua_tossh(L, 1);
  int rc = f_ssh_sftp(L);
  if (rc != 0)
    return rc;
  LIBSSH2_SFTP_HANDLE* dir = libssh2_sftp_opendir(session->sftp, luaL_checkstring(L, 2));
  if (!dir) {
    int ssh_error = libssh2_session_last_errno(session->ssh);
    if (ssh_error == LIBSSH2_ERROR_EAGAIN)
      return lua_sshyield(L, f_sftp_opendirk);
    else if (ssh_error == LIBSSH2_ERROR_SFTP_PROTOCOL) {
      lua_pushnil(L);
      lua_pushfstring(L, "opendir error: %s", strerror(libssh2_sftp_last_error(session->sftp)));
      return 2;
    } else
      return lua_pushssherr(L, session);
  }
  LIBSSH2_SFTP_HANDLE** dirp = lua_newuserdatauv(L, sizeof(LIBSSH2_SFTP_HANDLE*), 1);
  *dirp = dir;
  luaL_setmetatable(L, "sftp_dir");
  lua_pushvalue(L, 1);
  lua_setiuservalue(L, -2, 1);
  return 1;
}
static int f_sftp_opendir(lua_State* L) { return f_sftp_opendirk(L, 0, 0); }

static int f_sftp_openk(lua_State* L, int status, lua_KContext context) {
  ssh_session_t* session = lua_tossh(L, 1);
  int rc = f_ssh_sftp(L);
  if (rc != 0)
    return rc;
  const char* type = luaL_optstring(L, 3, "rb");
  int flags = 0;
  if (strchr(type, 'r'))
    flags |= LIBSSH2_FXF_READ;
  if (strchr(type, 'w') || strchr(type, 'a'))
    flags |= LIBSSH2_FXF_WRITE;
  if (strchr(type, 'w'))
    flags |= LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC;
  LIBSSH2_SFTP_HANDLE* file = libssh2_sftp_open(session->sftp, luaL_checkstring(L, 2), flags, S_IRWXU);
  if (!file) {
    int ssh_error = libssh2_session_last_errno(session->ssh);
    if (ssh_error == LIBSSH2_ERROR_EAGAIN)
      return lua_sshyield(L, f_sftp_openk);
    else if (ssh_error == LIBSSH2_ERROR_SFTP_PROTOCOL) {
      lua_pushnil(L);
      lua_pushfstring(L, "open error: %s", strerror(libssh2_sftp_last_error(session->sftp)));
      return 2;
    } else
      return lua_pushssherr(L, session);
  }
  LIBSSH2_SFTP_HANDLE** filep = lua_newuserdatauv(L, sizeof(LIBSSH2_SFTP_HANDLE*), 1);
  *filep = file;
  luaL_setmetatable(L, "sftp_file");
  lua_pushvalue(L, 1);
  lua_setiuservalue(L, -2, 1);
  return 1;
}
static int f_sftp_open(lua_State* L) { return f_sftp_openk(L, 0, 0); }
  
  
static const luaL_Reg ssh_api[] = {
  { "__gc",          f_ssh_disconnect    },
  { "connect",       f_ssh_connect       },
  { "disconnect",    f_ssh_disconnect    },
  
  { "stat",          f_sftp_stat         },
  { "mkdir",         f_sftp_mkdir        },
  { "rmdir",         f_sftp_rmdir        },
  { "rename",        f_sftp_rename       },
  { "unlink",        f_sftp_unlink       },
  { "opendir",       f_sftp_opendir      },
  { "open",          f_sftp_open         },
  { NULL,            NULL                }
};


#define LUASSH_VERSION "unknown"
 

#ifndef LIBSSH_STANDALONE
int luaopen_lite_xl_libssh(lua_State* L, void* XL) {
  lite_xl_plugin_init(XL);
#else
int luaopen_libssh(lua_State* L) {
#endif
  int rc = libssh2_init(0);
  if (rc)
    return luaL_error(L, "unable to initialize ssh2: %d", rc);
  luaL_newmetatable(L, "sftp_file"), luaL_setfuncs(L, sftp_file_api, 0),  lua_pushvalue(L, -1), lua_setfield(L, -2, "__index");
  luaL_newmetatable(L, "sftp_dir"), luaL_setfuncs(L, sftp_dir_api, 0),  lua_pushvalue(L, -1), lua_setfield(L, -2, "__index");
  luaL_newmetatable(L, "ssh"), luaL_setfuncs(L, ssh_api, 0),  lua_pushvalue(L, -1), lua_setfield(L, -2, "__index");
  lua_pushliteral(L, LUASSH_VERSION);
  lua_setfield(L, -2, "version");
  lua_pushvalue(L, -1);
  return 1;
}
