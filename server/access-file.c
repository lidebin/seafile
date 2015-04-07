#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#else
#include <event.h>
#endif

#include <evhtp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <ccnet.h>

#include "seafile-object.h"
#include "seafile-crypt.h"

#include "utils.h"

#include "seafile-session.h"
#include "access-file.h"
#include "pack-dir.h"

#define FILE_TYPE_MAP_DEFAULT_LEN 1
#define BOUNDARY "1q2w3e4r5t6y"

struct file_type_map {
    char *suffix;
    char *type;
};

typedef struct SendBlockData {
    evhtp_request_t *req;
    char *block_id;
    BlockHandle *handle;
    uint32_t bsize;
    uint32_t remain;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendBlockData;

typedef struct SendfileData {
    evhtp_request_t *req;
    Seafile *file;
    SeafileCrypt *crypt;
    gboolean enc_init;
    EVP_CIPHER_CTX ctx;
    BlockHandle *handle;
    size_t remain;
    int idx;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendfileData;

typedef struct SendFileRangeData {
    evhtp_request_t *req;
    Seafile *file;
    BlockHandle *handle;
    // block related
    size_t blk_remain;
    int blk_idx;
    //range related
    GList *ranges;
    gboolean is_multi_range;
    guint64 range_remain;
    char *content_type;
    GList *blk_offset_cache;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendFileRangeData;

typedef struct SendDirData {
    evhtp_request_t *req;
    size_t remain;

    int zipfd;
    char *zipfile;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendDirData;



extern SeafileSession *seaf;

static struct file_type_map ftmap[] = {
    { "txt", "text/plain" },
    { "html", "text/html" },
    { "doc", "application/vnd.ms-word" },
    { "docx", "application/vnd.ms-word" },
    { "ppt", "application/vnd.ms-powerpoint" },
    { "pptx", "application/vnd.ms-powerpoint" },
    { "xls", "application/vnd.ms-excel" },
    { "xlsx", "application/vnd.ms-excel" },
    { "pdf", "application/pdf" },
    { "zip", "application/zip"},
    { "mp3", "audio/mp3" },
    { "mpeg", "video/mpeg" },
    { "mp4", "video/mp4" },
    { "jpg", "image/jpg" },
    { "JPG", "image/jpg" },
    { "png", "image/png" },
    { "PNG", "image/png" },
    { "gif", "image/gif" },
    { "GIF", "image/gif" },
    { NULL, NULL },
};

static void
free_sendblock_data (SendBlockData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block(seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, data->handle);
    }

    g_free (data->block_id);
    g_free (data);
}

static void
free_sendfile_data (SendfileData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block(seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, data->handle);
    }

    if (data->enc_init)
        EVP_CIPHER_CTX_cleanup (&data->ctx);

    seafile_unref (data->file);
    g_free (data->crypt);
    g_free (data);
}

void
free_guint64 (gpointer data)
{
    guint64 *val = data;
    g_free (val);
}

static void
free_send_file_range_data (SendFileRangeData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block(seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, data->handle);
    }

    if (data->is_multi_range) {
        g_free (data->content_type);
        g_list_free_full (data->blk_offset_cache, free_guint64);
    }
    g_list_free_full (data->ranges, free_guint64);
    seafile_unref (data->file);
    g_free (data);
}

static void
free_senddir_data (SendDirData *data)
{
    close (data->zipfd);
    g_unlink (data->zipfile);

    g_free (data->zipfile);
    g_free (data);
}

static void
write_block_data_cb (struct bufferevent *bev, void *ctx)
{
    SendBlockData *data = ctx;
    char *blk_id;
    BlockHandle *handle;
    char buf[1024 * 64];
    int n;

    blk_id = data->block_id;

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block(seaf->block_mgr,
                                                     data->store_id,
                                                     data->repo_version,
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s\n", blk_id);
            goto err;
        }

        data->remain = data->bsize;
    }
    handle = data->handle;

    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s.\n", blk_id);
        goto err;
    } else if (n == 0) {
        /* We've read up the data of this block, finish. */
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        data->handle = NULL;

        /* Recover evhtp's callbacks */
        bev->readcb = data->saved_read_cb;
        bev->writecb = data->saved_write_cb;
        bev->errorcb = data->saved_event_cb;
        bev->cbarg = data->saved_cb_arg;

        /* Resume reading incomming requests. */
        evhtp_request_resume (data->req);

        evhtp_send_reply_end (data->req);

        free_sendblock_data (data);
        return;
    }

    /* OK, we've got some data to send. */
    bufferevent_write (bev, buf, n);

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_sendblock_data (data);
    return;
}

static void
write_data_cb (struct bufferevent *bev, void *ctx)
{
    SendfileData *data = ctx;
    char *blk_id;
    BlockHandle *handle;
    char buf[1024 * 64];
    int n;

next:
    blk_id = data->file->blk_sha1s[data->idx];

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block(seaf->block_mgr,
                                                     data->store_id,
                                                     data->repo_version,
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s\n", blk_id);
            goto err;
        }

        BlockMetadata *bmd;
        bmd = seaf_block_manager_stat_block_by_handle (seaf->block_mgr,
                                                       data->handle);
        if (!bmd)
            goto err;
        data->remain = bmd->size;
        g_free (bmd);

        if (data->crypt) {
            if (seafile_decrypt_init (&data->ctx,
                                      data->crypt->version,
                                      (unsigned char *)data->crypt->key,
                                      (unsigned char *)data->crypt->iv) < 0) {
                seaf_warning ("Failed to init decrypt.\n");
                goto err;
            }
            data->enc_init = TRUE;
        }
    }
    handle = data->handle;

    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s.\n", blk_id);
        goto err;
    } else if (n == 0) {
        /* We've read up the data of this block, finish or try next block. */
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        data->handle = NULL;
        if (data->crypt != NULL) {
            EVP_CIPHER_CTX_cleanup (&data->ctx);
            data->enc_init = FALSE;
        }

        if (data->idx == data->file->n_blocks - 1) {
            /* Recover evhtp's callbacks */
            bev->readcb = data->saved_read_cb;
            bev->writecb = data->saved_write_cb;
            bev->errorcb = data->saved_event_cb;
            bev->cbarg = data->saved_cb_arg;

            /* Resume reading incomming requests. */
            evhtp_request_resume (data->req);

            evhtp_send_reply_end (data->req);

            free_sendfile_data (data);
            return;
        }

        ++(data->idx);
        goto next;
    }

    /* OK, we've got some data to send. */
    if (data->crypt != NULL) {
        char *dec_out;
        int dec_out_len = -1;
        struct evbuffer *tmp_buf;

        dec_out = g_new (char, n + 16);
        if (!dec_out) {
            seaf_warning ("Failed to alloc memory.\n");
            goto err;
        }

        int ret = EVP_DecryptUpdate (&data->ctx,
                                     (unsigned char *)dec_out,
                                     &dec_out_len,
                                     (unsigned char *)buf,
                                     n);
        if (ret == 0) {
            seaf_warning ("Decrypt block %s failed.\n", blk_id);
            g_free (dec_out);
            goto err;
        }

        tmp_buf = evbuffer_new ();

        evbuffer_add (tmp_buf, dec_out, dec_out_len);

        /* If it's the last piece of a block, call decrypt_final()
         * to decrypt the possible partial block. */
        if (data->remain == 0) {
            ret = EVP_DecryptFinal_ex (&data->ctx,
                                       (unsigned char *)dec_out,
                                       &dec_out_len);
            if (ret == 0) {
                seaf_warning ("Decrypt block %s failed.\n", blk_id);
                evbuffer_free (tmp_buf);
                g_free (dec_out);
                goto err;
            }
            evbuffer_add (tmp_buf, dec_out, dec_out_len);
        }
        /* This may call write_data_cb() recursively (by libevent_openssl).
         * SendfileData struct may be free'd in the recursive calls.
         * So don't use "data" variable after here.
         */
        bufferevent_write_buffer (bev, tmp_buf);

        evbuffer_free (tmp_buf);
        g_free (dec_out);
    } else {
        bufferevent_write (bev, buf, n);
    }

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_sendfile_data (data);
    return;
}

static void
write_dir_data_cb (struct bufferevent *bev, void *ctx)
{
    SendDirData *data = ctx;
    char buf[64 * 1024];
    int n;

    n = readn (data->zipfd, buf, sizeof(buf));
    if (n < 0) {
        seaf_warning ("failed to read zipfile %s\n", data->zipfile);
        evhtp_connection_free (evhtp_request_get_connection (data->req));
        free_senddir_data (data);
    } else if (n > 0) {
        bufferevent_write (bev, buf, n);
        data->remain -= n;

        if (data->remain == 0) {
            /* Recover evhtp's callbacks */
            bev->readcb = data->saved_read_cb;
            bev->writecb = data->saved_write_cb;
            bev->errorcb = data->saved_event_cb;
            bev->cbarg = data->saved_cb_arg;

            /* Resume reading incomming requests. */
            evhtp_request_resume (data->req);

            evhtp_send_reply_end (data->req);

            free_senddir_data (data);
            return;
        }
    }
}

static void
my_block_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendBlockData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendblock_data (data);
}

static void
my_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendfileData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendfile_data (data);
}

static void
file_range_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendFileRangeData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_send_file_range_data (data);
}

static void
my_dir_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendDirData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_senddir_data (data);
}

static char *
parse_content_type(const char *filename)
{
    char *p;
    int i;

    if ((p = strrchr(filename, '.')) == NULL)
        return NULL;
    p++;

    for (i = 0; ftmap[i].suffix != NULL; i++) {
        if (strcmp(p, ftmap[i].suffix) == 0)
            return ftmap[i].type;
    }

    return NULL;
}

static gboolean
test_windows (evhtp_request_t *req)
{
    const char *user_agent = evhtp_header_find (req->headers_in, "User-Agent");
    if (!user_agent)
        return FALSE;

    GString *s = g_string_new (user_agent);
    if (g_strrstr (g_string_ascii_down (s)->str, "windows")) {
        g_string_free (s, TRUE);
        return TRUE;
    }
    else {
        g_string_free (s, TRUE);
        return FALSE;
    }
}

static gboolean
test_firefox (evhtp_request_t *req)
{
    const char *user_agent = evhtp_header_find (req->headers_in, "User-Agent");
    if (!user_agent)
        return FALSE;

    GString *s = g_string_new (user_agent);
    if (g_strrstr (g_string_ascii_down (s)->str, "firefox")) {
        g_string_free (s, TRUE);
        return TRUE;
    }
    else {
        g_string_free (s, TRUE);
        return FALSE;
    }
}

static int
do_file(evhtp_request_t *req, SeafRepo *repo, const char *file_id,
        const char *filename, const char *operation,
        SeafileCryptKey *crypt_key)
{
    Seafile *file;
    char *type = NULL;
    char file_size[255];
    gchar *content_type = NULL;
    char cont_filename[SEAF_PATH_MAX];
    char *key_hex, *iv_hex;
    unsigned char enc_key[32], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    SendfileData *data;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                       repo->store_id, repo->version, file_id);
    if (file == NULL)
        return -1;

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        if (repo->enc_version == 1)
            hex_to_rawdata (key_hex, enc_key, 16);
        else
            hex_to_rawdata (key_hex, enc_key, 32);
        hex_to_rawdata (iv_hex, enc_iv, 16);
        crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
        g_free (key_hex);
        g_free (iv_hex);
    }

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Access-Control-Allow-Origin",
                                              "*", 1, 1));


    type = parse_content_type(filename);
    if (type != NULL) {
        if (strstr(type, "text")) {
            content_type = g_strjoin("; ", type, "charset=gbk", NULL);
        } else {
            content_type = g_strdup (type);
        }

        evhtp_headers_add_header(req->headers_out,
                                 evhtp_header_new("Content-Type",
                                                  content_type, 1, 1));
        g_free (content_type);
    } else
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new("Content-Type",
                                                   "application/octet-stream", 1, 1));

    snprintf(file_size, sizeof(file_size), "%"G_GINT64_FORMAT"", file->file_size);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Length", file_size, 1, 1));

    if (strcmp(operation, "download") == 0) {
        if (test_firefox (req)) {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "attachment;filename*=\"utf8\' \'%s\"", filename);
        } else {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "attachment;filename=\"%s\"", filename);
        }
    } else {
        if (test_firefox (req)) {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "inline;filename*=\"utf8\' \'%s\"", filename);
        } else {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "inline;filename=\"%s\"", filename);
        }
    }
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Disposition", cont_filename,
                                              1, 1));

    /* If it's an empty file, send an empty reply. */
    if (file->n_blocks == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
        seafile_unref (file);
        return 0;
    }

    data = g_new0 (SendfileData, 1);
    data->req = req;
    data->file = file;
    data->crypt = crypt;

    memcpy (data->store_id, repo->store_id, 36);
    data->repo_version = repo->version;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    bufferevent_setcb (bev,
                       NULL,
                       write_data_cb,
                       my_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
}

// get block handle for range start
// blk_offset_cache is NULL, it means single-range otherwise multi-range
static BlockHandle *
get_start_block_handle (const char *store_id, int version, Seafile *file,
                        guint64 start, GList **blk_offset_cache, int *blk_idx,
                        size_t *blk_remain)
{
    BlockHandle *handle = NULL;
    BlockMetadata *bmd;
    char *blkid;
    int i = 0;
    GList *iter = NULL;
    GList *prev = NULL;
    guint64 off_start = 0;
    guint64 off_end = 0;

    if (blk_offset_cache) {
        guint64 *offset;
        for (iter=*blk_offset_cache; iter; iter=iter->next) {
           offset = iter->data;
           if (start >= *offset) {
               ++i;
               if (iter->next == NULL)
                   off_end = *offset;
           } else {
               off_end = *offset;
               prev = iter->prev;
               if (prev) {
                   offset = prev->data;
                   off_start = *offset;
               }
               blkid = file->blk_sha1s[i];
               break;
           }
        }
    }

    if (!iter) {
        guint64 *cached_off;
        for (; i < file->n_blocks; i++) {
            blkid = file->blk_sha1s[i];

            bmd = seaf_block_manager_stat_block(seaf->block_mgr, store_id, version, blkid);
            if (!bmd)
                return NULL;

            off_start = off_end;
            off_end += bmd->size;

            if (blk_offset_cache) {
                cached_off = g_new (guint64, 1);
                *cached_off = off_end;
                *blk_offset_cache = g_list_append (*blk_offset_cache, cached_off);
            }
            if (start < off_end) {
                g_free (bmd);
                break;
            }
            g_free (bmd);
        }
    }

    /* beyond the file size */
    if (i == file->n_blocks)
        return NULL;

    handle = seaf_block_manager_open_block(seaf->block_mgr,
                                           store_id, version,
                                           blkid, BLOCK_READ);
    if (!handle) {
        seaf_warning ("Failed to open block %s.\n", blkid);
        return NULL;
    }

    /* trim the offset in a block */
    if (start > off_start) {
        char *tmp = (char *)malloc(sizeof(*tmp) * (start - off_start));
        if (!tmp)
            goto err;

        int n = seaf_block_manager_read_block(seaf->block_mgr, handle,
                                              tmp, start-off_start);
        if (n != start-off_start) {
            seaf_warning ("Failed to read block %s.\n", blkid);
            free (tmp);
            goto err;
        }

    }

    *blk_remain = (off_end - off_start) - (start - off_start);
    *blk_idx = i;
    return handle;

err:
    seaf_block_manager_close_block(seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    return NULL;
}

static void
finish_file_range_request (struct bufferevent *bev, SendFileRangeData *data)
{
    /* Recover evhtp's callbacks */
    bev->readcb = data->saved_read_cb;
    bev->writecb = data->saved_write_cb;
    bev->errorcb = data->saved_event_cb;
    bev->cbarg = data->saved_cb_arg;

    /* Resume reading incomming requests. */
    evhtp_request_resume (data->req);

    evhtp_send_reply_end (data->req);

    free_send_file_range_data (data);
}

static void
write_file_range_cb (struct bufferevent *bev, void *ctx)
{
    SendFileRangeData *data = ctx;
    char *blk_id;
    BlockHandle *handle;
    char buf[1024 * 64];
    int bsize;
    int n;

    if (data->blk_idx == -1) {
        // start to send block from first range
        guint64 start;
        guint64 end;
        GList *pstart = data->ranges;
        GList *pend = pstart->next;

        start = *(guint64 *)pstart->data;
        end = *(guint64 *)pend->data;
        data->range_remain = end - start + 1;
        GList **blk_offset_cache = data->is_multi_range ? &data->blk_offset_cache : NULL;
        data->handle = get_start_block_handle (data->store_id, data->repo_version, data->file,
                                               start, blk_offset_cache, &data->blk_idx,
                                               &data->blk_remain);
        if (!data->handle)
            goto err;
        if (data->is_multi_range) {
            struct evbuffer *range_header = evbuffer_new ();
            evbuffer_add_printf (range_header, "--%s\r\n"
                                 "Content-Type: %s\r\n"
                                 "Content-Range: %s %"G_GUINT64_FORMAT"-%"G_GUINT64_FORMAT
                                 "/%"G_GUINT64_FORMAT"\r\n\r\n",
                                 BOUNDARY, data->content_type, "bytes",
                                 start, end, data->file->file_size);
            bufferevent_write_buffer (bev, range_header);
            evbuffer_free (range_header);
        }
    }

next:
    blk_id = data->file->blk_sha1s[data->blk_idx];

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block(seaf->block_mgr,
                                                     data->store_id,
                                                     data->repo_version,
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s\n", blk_id);
            goto err;
        }

        BlockMetadata *bmd;
        bmd = seaf_block_manager_stat_block_by_handle (seaf->block_mgr,
                                                       data->handle);
        if (!bmd)
            goto err;
        data->blk_remain = bmd->size;
        g_free (bmd);
    }

    handle = data->handle;
    bsize = sizeof(buf);
    bsize = bsize > data->range_remain ? data->range_remain : bsize;
    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, bsize);
    data->blk_remain -= n;
    data->range_remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s.\n", blk_id);
        goto err;
    } else if (n == 0 || data->blk_remain == 0) {
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        data->handle = NULL;
        ++data->blk_idx;
        if (n == 0)
            goto next;
    }

    if (data->is_multi_range) {
        if (data->range_remain == 0) {
            GList *head = data->ranges;
            g_free (head->data);
            data->ranges = g_list_delete_link (data->ranges, head);
            head = data->ranges;
            g_free (head->data);
            data->ranges = g_list_delete_link (data->ranges, head);
            data->blk_idx = -1;

            buf[n] = '\0';
            struct evbuffer *body_end = evbuffer_new ();
            if (data->ranges == NULL) {
                evbuffer_add_printf (body_end, "%s\r\n--%s--\r\n",
                                     buf, BOUNDARY);
            } else {
                evbuffer_add_printf (body_end, "%s\r\n", buf);
            }
            bufferevent_write_buffer (bev, body_end);
            evbuffer_free (body_end);

            if (data->ranges == NULL) {
                finish_file_range_request (bev, data);
            }
        } else {
            bufferevent_write (bev, buf, n);
        }
    } else {
        bufferevent_write (bev, buf, n);
        if (data->range_remain == 0) {
            finish_file_range_request (bev, data);
        }
    }

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_send_file_range_data (data);
    return;
}

static GList *
parse_range_array (const char *byte_ranges, int *range_num,
                   guint64 *body_size, guint64 fsize)
{
    char *minus;
    char *end_ptr;
    gboolean error = FALSE;
    char *ranges_dup = g_strdup (strchr(byte_ranges, '=') + 1);
    char *tmp = ranges_dup;
    char *range_str;
    GList *range_vals = NULL;
    guint64 start;
    guint64 end;
    guint64 *pstart;
    guint64 *pend;

    while (tmp && (minus = strchr(tmp, '-')) != NULL) {
        if (minus == tmp) {
            // -num mode
            start = strtoll(tmp, &end_ptr, 10);
            if (start == 0) {
                // range format is invalid
                error = TRUE;
                break;
            } else if (*end_ptr == '\0' || *end_ptr == ',') {
                end = fsize - 1;
                start += fsize;
                if (*end_ptr == ',') {
                    tmp = end_ptr + 1;
                } else {
                    tmp = end_ptr;
                }
            } else {
                error = TRUE;
                break;
            }
        } else if (*(minus + 1) == '\0' || *(minus + 1) == ',') {
            // num- mode
            start = strtoll(tmp, &end_ptr, 10);
            if (*end_ptr == *minus) {
                if (*(end_ptr + 1) == '\0') {
                    tmp = end_ptr + 1;
                } else {
                    tmp = end_ptr + 2;
                }
                end = fsize - 1;
            } else {
                error = TRUE;
                break;
            }
        } else {
            // num-num mode
            start = strtoll(tmp, &end_ptr, 10);
            if (end_ptr == minus) {
                end = strtoll(minus + 1, &end_ptr, 10);
                if (*end_ptr == '\0' || *end_ptr == ',') {
                    if (*end_ptr == ',') {
                        tmp = end_ptr + 1;
                    } else {
                        tmp = end_ptr;
                    }
                } else {
                    error = TRUE;
                    break;
                }
            } else {
                error = TRUE;
                break;
            }
        }
        if (start < 0) {
            start = 0;
        }
        if (end > fsize - 1) {
            end = fsize - 1;
        }
        if (start > end) {
            // Range format is valid, but range number is invalid
            error = TRUE;
            break;
        }
        pstart = g_new (guint64, 1);
        pend = g_new (guint64, 1);
        *pstart = start;
        *pend = end;
        range_vals = g_list_prepend (range_vals, pstart);
        range_vals = g_list_prepend (range_vals, pend);
        *range_num += 1;
        *body_size += end - start + 1;

        range_str = g_strdup_printf ("%"G_GUINT64_FORMAT"-%"G_GUINT64_FORMAT
                                     "/%"G_GUINT64_FORMAT, start, end, fsize);
        *body_size += strlen(range_str);
        g_free (range_str);
    }

    g_free (ranges_dup);

    if (error) {
        g_list_free_full (range_vals, free_guint64);
        return NULL;
    }

    return g_list_reverse (range_vals);
}

static guint64
calc_body_size (size_t ctype_size, guint64 rbody_size, int range_num)
{
    guint64 size = 0;
    size_t boundary_size = strlen (BOUNDARY);

    size += 4 + boundary_size + \
            strlen("Content-Range: bytes ") + 2 + \
            strlen("Content-Type: ") + 4 + ctype_size + 2;

    size *= range_num;
    size += boundary_size + 6 + rbody_size;

    return size;
}

static void
set_resp_disposition (evhtp_request_t *req, const char *operation,
                      const char *filename)
{
    char *cont_filename = NULL;

    if (strcmp(operation, "download") == 0) {
        if (test_firefox (req)) {
            cont_filename = g_strdup_printf("attachment;filename*=\"utf8\' \'%s\"",
                                            filename);

        } else {
            cont_filename = g_strdup_printf("attachment;filename=\"%s\"", filename);
        }
    } else {
        if (test_firefox (req)) {
            cont_filename = g_strdup_printf("inline;filename*=\"utf8\' \'%s\"",
                                            filename);
        } else {
            cont_filename = g_strdup_printf("inline;filename=\"%s\"", filename);
        }
    }

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Disposition", cont_filename,
                                              1, 1));
    g_free (cont_filename);
}

static void
set_resp_range_header (evhtp_request_t *req, const char *content_type,
                       GList *range_array, int range_num, guint64 body_size,
                       guint64 file_size)
{
    if (range_num == 1) {
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new ("Content-Type", content_type, 1, 1));

        guint64 start = *(guint64 *)range_array->data;
        guint64 end = *(guint64 *)range_array->next->data;
        char *con_len = g_strdup_printf ("%"G_GUINT64_FORMAT, end-start+1);
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new("Content-Length", con_len, 1, 1));
        g_free (con_len);

        char *con_range = g_strdup_printf ("%s %"G_GUINT64_FORMAT"-%"G_GUINT64_FORMAT
                                           "/%"G_GUINT64_FORMAT, "bytes",
                                           start, end, file_size);
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new ("Content-Range", con_range, 1, 1));
        g_free (con_range);
    } else {
        char *multi_range_type = g_strdup_printf ("multipart/byteranges; boundary=%s",
                                                  BOUNDARY);
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new ("Content-Type", multi_range_type, 1, 1));
        g_free (multi_range_type);

        char *con_len = g_strdup_printf ("%"G_GUINT64_FORMAT,
                                            calc_body_size (strlen(content_type),
                                                            body_size, range_num));
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new("Content-Length", con_len, 1, 1));
        g_free (con_len);
    }
}

static int
do_file_range (evhtp_request_t *req, SeafRepo *repo, const char *file_id,
               const char *filename, const char *operation, const char *byte_ranges)
{
    Seafile *file;
    char *content_type = NULL;
    SendFileRangeData *data = NULL;
    GList *range_array;
    int range_num = 0;
    guint64 body_size = 0;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                       repo->store_id, repo->version, file_id);
    if (file == NULL)
        return -1;

    /* If it's an empty file, send an empty reply. */
    if (file->n_blocks == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
        seafile_unref (file);
        return 0;
    }

    if ((range_array = parse_range_array (byte_ranges, &range_num, &body_size,
                                          file->file_size)) == NULL) {
        seafile_unref (file);
        char *con_range = g_strdup_printf ("bytes */%"G_GUINT64_FORMAT, file->file_size);
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new("Content-Range", con_range,
                                                   1, 1));
        g_free (con_range);
        evhtp_send_reply (req, EVHTP_RES_RANGENOTSC);
        return 0;
    }

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new ("Accept-Ranges", "bytes", 1, 1));

    set_resp_disposition (req, operation, filename);

    char *type = parse_content_type (filename);
    if (type != NULL) {
        if (strstr(type, "text")) {
            content_type = g_strjoin("; ", type, "charset=gbk", NULL);
        } else {
            content_type = g_strdup (type);
        }
    } else {
        content_type = g_strdup ("application/octet-stream");
    }

    set_resp_range_header (req, content_type, range_array,
                           range_num, body_size, file->file_size);

    data = g_new0 (SendFileRangeData, 1);
    if (!data)
        return -1;
    data->req = req;
    data->file = file;
    data->ranges = range_array;
    data->blk_idx = -1;
    if (range_num > 1) {
        data->content_type = content_type;
        data->is_multi_range = TRUE;
    } else {
        g_free (content_type);
    }

    memcpy (data->store_id, repo->store_id, 36);
    data->repo_version = repo->version;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    bufferevent_setcb (bev,
                       NULL,
                       write_file_range_cb,
                       file_range_event_cb,
                       data);


    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_PARTIAL);

    return 0;
}

static int
do_dir (evhtp_request_t *req, SeafRepo *repo, const char *dir_id,
        const char *filename, const char *operation,
        SeafileCryptKey *crypt_key)
{
    char *zipfile = NULL;
    char *filename_escaped = NULL;
    char cont_filename[SEAF_PATH_MAX];
    char file_size[255];
    SeafStat st;
    char *key_hex, *iv_hex;
    unsigned char enc_key[32], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    int zipfd = 0;
    int ret = 0;
    gint64 dir_size = 0;

    /* ensure file size does not exceed limit */
    dir_size = seaf_fs_manager_get_fs_size (seaf->fs_mgr,
                                            repo->store_id, repo->version,
                                            dir_id);
    if (dir_size < 0 || dir_size > seaf->http_server->max_download_dir_size) {
        seaf_warning ("invalid dir size: %"G_GINT64_FORMAT"\n", dir_size);
        ret = -1;
        goto out;
    }

    /* Let's zip the directory first */
    filename_escaped = g_uri_unescape_string (filename, NULL);
    if (!filename_escaped) {
        seaf_warning ("failed to unescape string %s\n", filename);
        ret = -1;
        goto out;
    }

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        if (repo->enc_version == 1)
            hex_to_rawdata (key_hex, enc_key, 16);
        else
            hex_to_rawdata (key_hex, enc_key, 32);
        hex_to_rawdata (iv_hex, enc_iv, 16);
        crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
        g_free (key_hex);
        g_free (iv_hex);
    }

    zipfile = pack_dir (repo->store_id, repo->version,
                        filename_escaped, dir_id, crypt, test_windows(req));
    if (!zipfile) {
        ret = -1;
        goto out;
    }

    /* OK, the dir is zipped */
    evhtp_headers_add_header(req->headers_out,
                evhtp_header_new("Content-Type", "application/zip", 1, 1));

    if (seaf_stat(zipfile, &st) < 0) {
        ret = -1;
        goto out;
    }

    snprintf (file_size, sizeof(file_size), "%"G_GUINT64_FORMAT"", st.st_size);
    evhtp_headers_add_header (req->headers_out,
            evhtp_header_new("Content-Length", file_size, 1, 1));

    if (test_firefox (req)) {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename*=\"utf8\' \'%s.zip\"", filename);
    } else {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename=\"%s.zip\"", filename);
    }

    evhtp_headers_add_header(req->headers_out,
            evhtp_header_new("Content-Disposition", cont_filename, 1, 1));

    zipfd = g_open (zipfile, O_RDONLY | O_BINARY, 0);
    if (zipfd < 0) {
        seaf_warning ("failed to open zipfile %s\n", zipfile);
        ret = -1;
        goto out;
    }

    SendDirData *data;
    data = g_new0 (SendDirData, 1);
    data->req = req;
    data->zipfd = zipfd;
    data->zipfile = zipfile;
    data->remain = st.st_size;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    bufferevent_setcb (bev,
                       NULL,
                       write_dir_data_cb,
                       my_dir_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

out:
    g_free (filename_escaped);
    if (ret < 0) {
        if (zipfile != NULL) {
            g_unlink (zipfile);
            g_free (zipfile);
        }

        if (zipfd > 0) {
            close (zipfd);
        }
    }

    return ret;
}

static void
access_cb(evhtp_request_t *req, void *arg)
{
    SeafRepo *repo = NULL;
    char *error = NULL;
    char *token = NULL;
    char *filename = NULL;
    const char *repo_id = NULL;
    const char *id = NULL;
    const char *operation = NULL;
    const char *user = NULL;
    const char *byte_ranges = NULL;

    GError *err = NULL;
    SeafileCryptKey *key = NULL;
    SeafileWebAccess *webaccess = NULL;

    /* Skip the first '/'. */
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 3 ||
        strcmp (parts[0], "files") != 0) {
        error = "Invalid URL";
        goto bad_req;
    }

    token = parts[1];
    filename = parts[2];

    webaccess = seaf_web_at_manager_query_access_token (seaf->web_at_mgr, token);
    if (!webaccess) {
        error = "Bad access token";
        goto bad_req;
    }

    if (evhtp_kv_find (req->headers_in, "If-Modified-Since") != NULL) {
        evhtp_send_reply (req, EVHTP_RES_NOTMOD);
        goto success;
    } else {
        char http_date[256];
        evhtp_kv_t *kv;
        time_t now = time(NULL);

        /* Set Last-Modified header if the client gets this file
         * for the first time. So that the client will set
         * If-Modified-Since header the next time it gets the same
         * file.
         */
#ifndef WIN32
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %T GMT",
                  gmtime(&now));
#else
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %H:%M:%S GMT",
                  gmtime(&now));
#endif
        kv = evhtp_kv_new ("Last-Modified", http_date, 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);

        kv = evhtp_kv_new ("Cache-Control", "max-age=3600", 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);
    }

    repo_id = seafile_web_access_get_repo_id (webaccess);
    id = seafile_web_access_get_obj_id (webaccess);
    operation = seafile_web_access_get_op (webaccess);
    user = seafile_web_access_get_username (webaccess);
    byte_ranges = evhtp_kv_find (req->headers_in, "Range");

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        error = "Bad repo id\n";
        goto bad_req;
    }

    if (repo->encrypted) {
        err = NULL;
        key = seaf_passwd_manager_get_decrypt_key (seaf->passwd_mgr,
                                                   repo_id, user);
        if (!key) {
            error = "Repo is encrypted. Please provide password to view it.";
            goto bad_req;
        }
    }

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                        repo->store_id, repo->version, id)) {
        error = "Invalid file id\n";
        goto bad_req;
    }

    if (strcmp(operation, "download-dir") == 0) {
        if (do_dir(req, repo, id, filename, operation, key) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }

    } else if (!repo->encrypted && byte_ranges) {
        if (do_file_range (req, repo, id, filename, operation, byte_ranges) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }
    } else if (do_file(req, repo, id, filename, operation, key) < 0) {
        error = "Internal server error\n";
        goto bad_req;
    }

success:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    if (key != NULL)
        g_object_unref (key);
    if (webaccess)
        g_object_unref (webaccess);

    return;

bad_req:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    if (key != NULL)
        g_object_unref (key);
    if (webaccess != NULL)
        g_object_unref (webaccess);

    evbuffer_add_printf(req->buffer_out, "%s\n", error);
    evhtp_send_reply(req, EVHTP_RES_BADREQ);
}

static int
do_block(evhtp_request_t *req, SeafRepo *repo, const char *file_id,
         const char *blk_id)
{
    Seafile *file;
    uint32_t bsize;
    gboolean found = FALSE;
    int i;
    char blk_size[255];
    char cont_filename[SEAF_PATH_MAX];
    SendBlockData *data;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                       repo->store_id, repo->version, file_id);
    if (file == NULL)
        return -1;

    for (i = 0; i < file->n_blocks; i++) {
        if (memcmp(file->blk_sha1s[i], blk_id, 40) == 0) {
            BlockMetadata *bm = seaf_block_manager_stat_block (seaf->block_mgr,
                                                               repo->store_id,
                                                               repo->version,
                                                               blk_id);
            if (bm && bm->size >= 0) {
                bsize = bm->size;
                found = TRUE;
            }
            g_free (bm);
            break;
        }
    }

    seafile_unref (file);

    /* block not found. */
    if (!found) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return 0;
    }
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Access-Control-Allow-Origin",
                                              "*", 1, 1));

    if (test_firefox (req)) {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename*=\"utf8\' \'%s\"", blk_id);
    } else {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename=\"%s\"", blk_id);
    }
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Disposition", cont_filename,
                                              1, 1));

    snprintf(blk_size, sizeof(blk_size), "%"G_GUINT32_FORMAT"", bsize);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Length", blk_size, 1, 1));

    data = g_new0 (SendBlockData, 1);
    data->req = req;
    data->block_id = g_strdup(blk_id);

    memcpy (data->store_id, repo->store_id, 36);
    data->repo_version = repo->version;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    data->bsize = bsize;
    bufferevent_setcb (bev,
                       NULL,
                       write_block_data_cb,
                       my_block_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
}

static void
access_blks_cb(evhtp_request_t *req, void *arg)
{
    SeafRepo *repo = NULL;
    char *error = NULL;
    char *token = NULL;
    char *blkid = NULL;
    const char *repo_id = NULL;
    const char *id = NULL;
    const char *operation = NULL;

    char *repo_role = NULL;
    SeafileWebAccess *webaccess = NULL;

    /* Skip the first '/'. */
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 3 ||
        strcmp (parts[0], "blks") != 0) {
        error = "Invalid URL";
        goto bad_req;
    }

    token = parts[1];
    blkid = parts[2];

    webaccess = seaf_web_at_manager_query_access_token (seaf->web_at_mgr, token);
    if (!webaccess) {
        error = "Bad access token";
        goto bad_req;
    }

    if (evhtp_kv_find (req->headers_in, "If-Modified-Since") != NULL) {
        evhtp_send_reply (req, EVHTP_RES_NOTMOD);
        goto success;
    } else {
        char http_date[256];
        evhtp_kv_t *kv;
        time_t now = time(NULL);

        /* Set Last-Modified header if the client gets this file
         * for the first time. So that the client will set
         * If-Modified-Since header the next time it gets the same
         * file.
         */
#ifndef WIN32
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %T GMT",
                  gmtime(&now));
#else
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %H:%M:%S GMT",
                  gmtime(&now));
#endif
        kv = evhtp_kv_new ("Last-Modified", http_date, 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);

        kv = evhtp_kv_new ("Cache-Control", "max-age=3600", 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);
    }

    repo_id = seafile_web_access_get_repo_id (webaccess);
    id = seafile_web_access_get_obj_id (webaccess);
    operation = seafile_web_access_get_op (webaccess);

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        error = "Bad repo id\n";
        goto bad_req;
    }

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                        repo->store_id, repo->version, id)) {
        error = "Invalid file id\n";
        goto bad_req;
    }

    if (strcmp(operation, "downloadblks") == 0) {
        if (do_block(req, repo, id, blkid) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }
    }

success:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    g_object_unref (webaccess);

    return;

bad_req:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    if (webaccess != NULL)
        g_object_unref (webaccess);

    evbuffer_add_printf(req->buffer_out, "%s\n", error);
    evhtp_send_reply(req, EVHTP_RES_BADREQ);
}

int
access_file_init (evhtp_t *htp)
{
    evhtp_set_regex_cb (htp, "^/files/.*", access_cb, NULL);
    evhtp_set_regex_cb (htp, "^/blks/.*", access_blks_cb, NULL);

    return 0;
}
