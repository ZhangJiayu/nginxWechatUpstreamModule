How does this module work
=========================

``` C
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <pcre.h>
#include <stdio.h>

#define ngx_bitvector_index(index) index / (8 * sizeof(uintptr_t))
#define ngx_bitvector_bit(index) (uintptr_t)1 << index % (8 * sizeof(uintptr_t))

typedef struct {
  ngx_str_t output_words;
} ngx_http_hello_world_loc_conf_t;

typedef struct {
  struct sockaddr *sockaddr;
  socklen_t socklen;
  ngx_str_t name;
} ngx_http_upstream_thutuan_peer_t;

typedef struct {
  ngx_uint_t number;
  ngx_http_upstream_thutuan_peer_t peer[1];
} ngx_http_upstream_thutuan_peers_t;

typedef struct {
  ngx_uint_t hash;
  ngx_http_upstream_thutuan_peers_t *peers;
  uintptr_t tried[1];
} ngx_http_upstream_thutuan_peer_data_t;

typedef struct {
  char *ToUserName;
  char *FromUserName;
  char *CreateTime;
  char *msgtype;
  char *msgcontent;
  char *PicUrl;
  char *MediaId;
  char *Format;
  char *ThumbMediaId;
  char *Location_X;
  char *Location_Y;
  char *Scale;
  char *Label;
  char *Title;
  char *Description;
  char *Url;
  char *MsgId;
  char *Event;
  char *EventKey;
  char *ScanCodeInfo;
  char *ScanType;
  char *ScanResult;
  char *SendPicsInfo;
  char *Count;
  char *PicList;
  char *PicMd5Sum;
  char *SendLocationInfo;
  char *Poiname;
  char *Recognition;
  char *Ticket;
  char *Latitude;
  char *Longitude;
  char *Precision;
} msg_info;

static ngx_int_t ngx_http_upstream_init_thutuan_peer(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_thutuan_peer(ngx_peer_connection_t *pc,
                                                 void *data);
static void ngx_http_upstream_free_thutuan_peer(ngx_peer_connection_t *pc,
                                             void *data, ngx_uint_t state);
static char *ngx_http_upstream_thutuan(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf);
static ngx_int_t ngx_http_upstream_init_thutuan(ngx_conf_t *cf,
                                             ngx_http_upstream_srv_conf_t *us);
static int does_match(char *parameter, const char *xml_name,
                      msg_info request_info, u_char *request_body_all,
                      ngx_http_request_t *r);
static int str_match_regex(char *data, char *regex, u_char *request_body_all,
                           ngx_http_request_t *r);
static int xml_match_regex(xmlDocPtr docptr, xmlNodePtr curl,
                           msg_info request_info, u_char *request_body_all,
                           ngx_http_request_t *r);
static ngx_command_t ngx_http_upstream_thutuan_commands[] = {
    {ngx_string("ticketups"), NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
     ngx_http_upstream_thutuan, 0, 0, NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_upstream_thutuan_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_upstream_thutuan_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_thutuan_module_ctx, /* module context */
    ngx_http_upstream_thutuan_commands,    /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_upstream_init_thutuan(ngx_conf_t *cf,
                                             ngx_http_upstream_srv_conf_t *us) {
  ngx_uint_t i, j, n;
  ngx_http_upstream_server_t *server;
  ngx_http_upstream_thutuan_peers_t *peers;

  us->peer.init = ngx_http_upstream_init_thutuan_peer;

  if (!us->servers) {
    return NGX_ERROR;
  }

  server = us->servers->elts;

  for (n = 0, i = 0; i < us->servers->nelts; i++) {
    n += server[i].naddrs;
  }

  peers = ngx_pcalloc(cf->pool,
                      sizeof(ngx_http_upstream_thutuan_peers_t) +
                          sizeof(ngx_http_upstream_thutuan_peer_t) * (n - 1));
  if (peers == NULL) {
    return NGX_ERROR;
  }

  peers->number = n;

  /* one hostname can have multiple IP addresses in DNS */
  for (n = 0, i = 0; i < us->servers->nelts; i++) {
    for (j = 0; j < server[i].naddrs; j++, n++) {
      peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
      peers->peer[n].socklen = server[i].addrs[j].socklen;
      peers->peer[n].name = server[i].addrs[j].name;
    }
  }
  us->peer.data = peers;

  return NGX_OK;
}

static ngx_int_t ngx_http_upstream_init_thutuan_peer(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "request_body_all%s", "sd");
  ngx_http_upstream_thutuan_peer_data_t *uhpd;

  ngx_str_t val;

  if (ngx_http_script_run(r, &val, us->lengths, 0, us->values) == NULL) {
    return NGX_ERROR;
  }

  uhpd = ngx_pcalloc(
      r->pool,
      sizeof(ngx_http_upstream_thutuan_peer_data_t) +
          sizeof(uintptr_t) *
              ((ngx_http_upstream_thutuan_peers_t *)us->peer.data)->number /
              (8 * sizeof(uintptr_t)));
  if (uhpd == NULL) {
    return NGX_ERROR;
  }

  r->upstream->peer.data = uhpd;

  uhpd->peers = us->peer.data;

  r->upstream->peer.free = ngx_http_upstream_free_thutuan_peer;
  r->upstream->peer.get = ngx_http_upstream_get_thutuan_peer;
  r->upstream->peer.tries = us->retries + 1;

  // Get the size of body in buffer chain
  ngx_chain_t *cl = r->request_body->bufs;
  int sum_rb_bufs = 0;
  for (; cl; cl = cl->next) {
    sum_rb_bufs += (size_t)ngx_buf_size(cl->buf);
    // u_char *buf_char_pointer = cl->buf->pos;
  }

  u_char *request_body_all =
      ngx_pcalloc(r->pool, (sum_rb_bufs + 1) * sizeof(u_char));
  int i_count_body_length = 0;
  cl = r->request_body->bufs;
  for (; cl; cl = cl->next) {
    u_char *buf_char_pointer = cl->buf->pos;
    for (; buf_char_pointer != cl->buf->last;
         buf_char_pointer += sizeof(u_char)) {
      request_body_all[i_count_body_length] = (u_char)(*buf_char_pointer);
      i_count_body_length++;
    }
  }

  msg_info request_info;
  request_info.ToUserName = NULL;
  request_info.FromUserName = NULL;
  request_info.CreateTime = NULL;
  request_info.msgtype = NULL;
  request_info.msgcontent = NULL;
  request_info.PicUrl = NULL;
  request_info.MediaId = NULL;
  request_info.Format = NULL;
  request_info.ThumbMediaId = NULL;
  request_info.Location_X = NULL;
  request_info.Location_Y = NULL;
  request_info.Scale = NULL;
  request_info.Label = NULL;
  request_info.Title = NULL;
  request_info.Description = NULL;
  request_info.Url = NULL;
  request_info.MsgId = NULL;
  request_info.Event = NULL;
  request_info.EventKey = NULL;
  request_info.ScanCodeInfo = NULL;
  request_info.ScanType = NULL;
  request_info.ScanResult = NULL;
  request_info.SendPicsInfo = NULL;
  request_info.Count = NULL;
  request_info.PicList = NULL;
  request_info.PicMd5Sum = NULL;
  request_info.SendLocationInfo = NULL;
  request_info.Poiname = NULL;
  request_info.Recognition = NULL;
  request_info.Ticket = NULL;
  request_info.Latitude = NULL;
  request_info.Longitude = NULL;
  request_info.Precision = NULL;
  xmlDocPtr docptr = xmlParseDoc(request_body_all);
  xmlNodePtr cur = NULL;
  cur = xmlDocGetRootElement(docptr);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "request_body_all%s", request_body_all);
  xmlChar *key = NULL;
  int isTicket = 0;
  uhpd->hash = uhpd->peers->number - 1;

  if (cur != NULL) {
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
      if (!xmlStrcmp(cur->name, (const xmlChar *)"ToUserName")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.ToUserName = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.ToUserName, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"FromUserName")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.FromUserName = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.FromUserName, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"CreateTime")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.CreateTime = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.CreateTime, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"MsgType")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.msgtype = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.msgtype, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Content")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.msgcontent = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.msgcontent, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"PicUrl")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.PicUrl = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.PicUrl, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"MediaId")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.MediaId = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.MediaId, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Format")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Format = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Format, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"ThumbMediaId")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.ThumbMediaId = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.ThumbMediaId, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Location_X")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Location_X = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Location_X, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Location_Y")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Location_Y = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Location_Y, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Scale")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Scale = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Scale, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Label")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Label = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Label, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Title")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Title = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Title, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Description")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Description = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Description, key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Url")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Url = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Url, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"MsgId")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.MsgId = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.MsgId, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Event")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Event = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Event, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"EventKey")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.EventKey = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.EventKey, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"ScanCodeInfo")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.ScanCodeInfo = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.ScanCodeInfo, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"SendPicsInfo")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.SendPicsInfo = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.SendPicsInfo, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Count")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Count = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Count, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"PicList")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.PicList = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.PicList, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"PicMd5Sum")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.PicMd5Sum = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.PicMd5Sum, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"SendLocationInfo")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.SendLocationInfo = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.SendLocationInfo, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Poiname")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Poiname = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Poiname, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Recognition")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Recognition = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Recognition, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Ticket")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Ticket = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Ticket, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Latitude")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Latitude = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Latitude, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Longitude")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Longitude = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Longitude, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      if (!xmlStrcmp(cur->name, (const xmlChar *)"Precision")) {
          key = xmlNodeListGetString(docptr, cur->xmlChildrenNode, 1);
        if (key != NULL) {
          request_info.Precision = ngx_pcalloc(
              r->pool, (strlen((const char *)key) + 1) * sizeof(char));
          strcpy(request_info.Precision, (const char *)key);
          xmlFree(key);
          key = NULL;
        }
      }
      cur = cur->next;
    }


    u_char *parameter = ngx_pcalloc(r->pool, (val.len + 1) * sizeof(u_char));
    int i = 0;
    for (; i < val.len; i++) {
      parameter[i] = val.data[i];
    }

    int serverNum = 0;
    for (; serverNum < uhpd->peers->number - 1; serverNum++) {
      char *xml_name = ngx_pcalloc(r->pool, 9 * sizeof(char));
      int i;
      for (i = 0; i < 6; i++) {
        xml_name[i] = "server"[i];
      }
      xml_name[6] = '0' + serverNum;
      if (does_match(parameter, (const char *)xml_name, request_info,
                     request_body_all, r)) {
        break;
      }
    }
    uhpd->hash = serverNum;

  }
  xmlFreeDoc(docptr);
  return NGX_OK;
}

static int does_match(char *parameter, const char *xml_name,
                      msg_info request_info, u_char *request_body_all,
                      ngx_http_request_t *r) {
  xmlDocPtr docptr = xmlParseDoc(parameter);
  xmlNodePtr cur = NULL;
  cur = xmlDocGetRootElement(docptr);

  int result = 0;
  if (cur != NULL) {
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
      if (!xmlStrcmp(cur->name, (const xmlChar *)xml_name)) {
        if (xml_match_regex(docptr, cur, request_info, request_body_all, r)) {
          result = 1;
        }
      }
      cur = cur->next;
    }
  }
  xmlFreeDoc(docptr);
  return result;
}
static int xml_match_regex(xmlDocPtr docptr, xmlNodePtr curl,
                           msg_info request_info, u_char *request_body_all,
                           ngx_http_request_t *r) {
  char *key = NULL;
  curl = curl->xmlChildrenNode;
  int result = 1;
  while (curl != NULL) {
    if (!xmlStrcmp(curl->name, (const xmlChar *)"ToUserName")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.ToUserName, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"FromUserName")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.FromUserName, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"CreateTime")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.CreateTime, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"MsgType")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pcrenomatch..%s", key);
                                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pcrenomatch..%s", request_info.msgtype);
        if (!str_match_regex(request_info.msgtype, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Content")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.msgcontent, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"PicUrl")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.PicUrl, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"MediaId")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.MediaId, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Format")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Format, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"ThumbMediaId")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.ThumbMediaId, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Location_X")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Location_X, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Location_Y")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Location_Y, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Scale")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Scale, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Label")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Label, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Title")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Title, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Description")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Description, key, request_body_all,
                             r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Url")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Url, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"MsgId")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.MsgId, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Event")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Event, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"EventKey")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.EventKey, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"ScanCodeInfo")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.ScanCodeInfo, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"ScanType")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.ScanType, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"ScanResult")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.ScanResult, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"SendPicsInfo")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.SendPicsInfo, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Count")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Count, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"PicList")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.PicList, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"PicMd5Sum")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.PicMd5Sum, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"SendLocationInfo")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.SendLocationInfo, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Poiname")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Poiname, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Recognition")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Recognition, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Ticket")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Ticket, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Latitude")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Latitude, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Longitude")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Longitude, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    if (!xmlStrcmp(curl->name, (const xmlChar *)"Precision")) {
        key = xmlNodeListGetString(docptr, curl->xmlChildrenNode, 1);
      if (key != NULL) {
        if (!str_match_regex(request_info.Precision, key, request_body_all, r)) {
          result = 0;
        }
        xmlFree(key);
        key = NULL;
      }
    }
    curl = curl->next;
  }
  return result;
}
static int str_match_regex(char *data, char *regex, u_char *request_body_all,
                           ngx_http_request_t *r) {

  if (data == NULL) return 0;

  void *(*old_pcre_malloc)(size_t);
  void (*old_pcre_free)(void *);
  old_pcre_malloc = pcre_malloc;
  old_pcre_free = pcre_free;
  pcre_malloc = malloc;
  pcre_free = free;
  pcre *re = NULL;
  const char *error;
  int erroffset;
  int ovector[30];
  int rc;
  int result = 0;
  re = pcre_compile(regex, 0, &error, &erroffset, 0);
  if (!re) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pcreerror%s",
                   error);
  }
  rc = pcre_exec(re, NULL, data, strlen(data), 0, 0, ovector, 30);
  if (rc <= 0) {
    switch (rc) {
      case PCRE_ERROR_NOMATCH:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "pcrenomatch!..", request_body_all);
        break;
      default:
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "error",
                       request_body_all);
        break;
    }
  } else {
    if (ovector[2 * rc - 1] < strlen(data)) {
    } else {
      result = 1;
    }
  }
  pcre_free(re);
  re = NULL;
  pcre_malloc = old_pcre_malloc;
  pcre_free = old_pcre_free;
  return result;
}

static ngx_int_t ngx_http_upstream_get_thutuan_peer(ngx_peer_connection_t *pc,
                                                 void *data) {
  ngx_http_upstream_thutuan_peer_data_t *uhpd = data;
  ngx_http_upstream_thutuan_peer_t *peer;
  ngx_uint_t peer_index;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "get upstream request index peer try %ui", pc->tries);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "get hash %ui", uhpd->hash);

  pc->cached = 0;
  pc->connection = NULL;

  peer_index = uhpd->hash % uhpd->peers->number;

  peer = &uhpd->peers->peer[peer_index];

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "chose peer %ui w/ index %ui",
                 peer_index, uhpd->hash);

  pc->sockaddr = peer->sockaddr;
  pc->socklen = peer->socklen;
  pc->name = &peer->name;

  return NGX_OK;
}

static void ngx_http_upstream_free_thutuan_peer(ngx_peer_connection_t *pc,
                                             void *data, ngx_uint_t state) {
  ngx_http_upstream_thutuan_peer_data_t *uhpd = data;
  ngx_uint_t current;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "free upstream index peer try %ui", pc->tries);
ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "free hash %di", uhpd->hash);
  if (state & NGX_PEER_FAILED && --pc->tries) {
    current = uhpd->hash % uhpd->peers->number;

    uhpd->tried[ngx_bitvector_index(current)] |= ngx_bitvector_bit(current);

    do {
      uhpd->hash = ngx_hash_key((u_char *)&uhpd->hash, sizeof(ngx_uint_t));
      current = uhpd->hash % uhpd->peers->number;
    } while ((uhpd->tried[ngx_bitvector_index(current)] &
              ngx_bitvector_bit(current)) &&
             --pc->tries);
  }
}


static char *ngx_http_upstream_thutuan(ngx_conf_t *cf, ngx_command_t *cmd,
                                    void *conf) {
  ngx_http_upstream_srv_conf_t *uscf;
  ngx_http_script_compile_t sc;
  ngx_str_t *value;
  ngx_array_t *vars_lengths, *vars_values;

  value = cf->args->elts;

  ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

  vars_lengths = NULL;
  vars_values = NULL;

  sc.cf = cf;
  sc.source = &value[1];
  sc.lengths = &vars_lengths;
  sc.values = &vars_values;
  sc.complete_lengths = 1;
  sc.complete_values = 1;

  if (ngx_http_script_compile(&sc) != NGX_OK) {
    return NGX_CONF_ERROR;
  }
  uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

  uscf->peer.init_upstream = ngx_http_upstream_init_thutuan;

  uscf->flags = NGX_HTTP_UPSTREAM_CREATE;

  uscf->values = vars_values->elts;
  uscf->lengths = vars_lengths->elts;

  if (uscf->hash_function == NULL) {
    uscf->hash_function = ngx_hash_key;
  }

  return NGX_CONF_OK;
}
```