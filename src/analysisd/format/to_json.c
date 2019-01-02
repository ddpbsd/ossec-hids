/* Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "to_json.h"
#include "json_extended.h"
#include "shared.h"
#include "rules.h"
#include "cJSON.h"
#include "config.h"



/* Convert Eventinfo to json */
char *Eventinfo_to_jsonstr(const Eventinfo *lf)
{
    cJSON *root;
    cJSON *rule;
    cJSON *file_diff;
    char *out;

    extern long int __crt_ftell;

    root = cJSON_CreateObject();
    
    cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());

    cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);

    if ( lf->time ) {

        char alert_id[23];
        double timestamp_ms;
        timestamp_ms = ((double)lf->time)*1000;
        alert_id[22] = '\0';
        if((snprintf(alert_id, 22, "%ld.%ld", (long int)lf->time, __crt_ftell)) < 0) {
            merror("snprintf failed");
        }

        cJSON_AddStringToObject(root, "id", alert_id);
        cJSON_AddNumberToObject(root, "TimeStamp", timestamp_ms);
    }

    if (lf->generated_rule->comment) {
        cJSON_AddStringToObject(rule, "comment", lf->generated_rule->comment);
    }
    if (lf->generated_rule->sigid) {
        cJSON_AddNumberToObject(rule, "sidid", lf->generated_rule->sigid);
    }
    if (lf->generated_rule->group) {
        cJSON_AddStringToObject(rule, "group", lf->generated_rule->group);
    }
    if (lf->generated_rule->cve) {
        cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);
    }
    if (lf->generated_rule->info) {
        cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);
    }

    if( lf->decoder_info->name ) {
        cJSON_AddStringToObject(root, "decoder", lf->decoder_info->name);
    }
    if( lf->decoder_info->parent ) {
        cJSON_AddStringToObject(root, "decoder_parent", lf->decoder_info->parent);
    }

    if (lf->action) {
        cJSON_AddStringToObject(root, "action", lf->action);
    }
    if (lf->protocol) {
        cJSON_AddStringToObject(root, "protocol", lf->protocol);
    }
    if (lf->srcip) {
        cJSON_AddStringToObject(root, "srcip", lf->srcip);
    }

#ifdef LIBGEOIP_ENABLED
    if (lf->srcgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "srcgeoip", lf->srcgeoip);
    }
#endif

    if (lf->srcport) {
        cJSON_AddStringToObject(root, "srcport", lf->srcport);
    }
    if (lf->srcuser) {
        cJSON_AddStringToObject(root, "srcuser", lf->srcuser);
    }
    if (lf->dstip) {
        cJSON_AddStringToObject(root, "dstip", lf->dstip);
    }
#ifdef LIBGEOIP_ENABLED
    if (lf->dstgeoip && Config.geoip_jsonout) {
        cJSON_AddStringToObject(root, "dstgeoip", lf->dstgeoip);
    }
#endif

    if (lf->dstport) {
        cJSON_AddStringToObject(root, "dstport", lf->dstport);
    }
    if (lf->dstuser) {
        cJSON_AddStringToObject(root, "dstuser", lf->dstuser);
    }
    if (lf->location) {
        cJSON_AddStringToObject(root, "location", lf->location);
    }
    if (lf->full_log) {
        cJSON_AddStringToObject(root, "full_log", lf->full_log);
    }
    if (lf->generated_rule->last_events && lf->generated_rule->last_events[1] && lf->generated_rule->last_events[1][0]) {
        cJSON_AddStringToObject(root, "previous_output", lf->generated_rule->last_events[1]);
    }

    if (lf->filename) {
        cJSON_AddItemToObject(root, "file", file_diff = cJSON_CreateObject());

        cJSON_AddStringToObject(file_diff, "path", lf->filename);

#ifdef LIBSODIUM_ENABLED
        if(lf->hash1_before && lf->hash1_after && strncmp(lf->hash1_before, lf->hash1_after, 129) != 0) {
            /* Have to handle _before and _after separately since they could be different algs */
            /* hash1_before */
            char *os_alg = NULL;
            if (strncmp(lf->hash1_before, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash1_before, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash1_before, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash1_before, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            char *os_alg_status = NULL;
            int os_s_return;
             os_s_return = snprintf(os_alg_status, 32, "%s_before", os_alg);
             if (os_s_return == -1) {
                 merror("snprintf error");
             } else if (os_s_return > 32) {
                 merror("snprintf overshot");
             }
             cJSON_AddStringToObject(file_diff, os_alg_status, lf->hash1_before);

            /* hash1_after */
            if (strncmp(lf->hash1_after, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash1_after, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash1_after, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash1_after, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            os_alg_status[0] = '\0';
            os_s_return = 0;
            os_s_return = snprintf(os_alg_status, 32, "%s_after", os_alg);
            if (os_s_return == -1) {
                merror("snprintf error");
            } else if (os_s_return > 32) {
                merror("snprintf overshot");
            }
            cJSON_AddStringToObject(file_diff, os_alg_status, lf->hash1_after);
        }

        if(lf->hash1_before && lf->hash2_after && strncmp(lf->hash2_before, lf->hash2_after, 129) != 0) {
            /* Have to handle _before and _after separately since they could be different algs */
            /* hash2_before */
            char *os_alg = NULL;
            if (strncmp(lf->hash2_before, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash2_before, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash2_before, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash2_before, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            char *os_alg_status = NULL;
            int os_s_return;
             os_s_return = snprintf(os_alg_status, 32, "%s_before", os_alg);
             if (os_s_return == -1) {
                 merror("snprintf error");
             } else if (os_s_return > 32) {
                 merror("snprintf overshot");
             }
             cJSON_AddStringToObject(file_diff, os_alg_status, lf->hash1_before);

            /* hash1_after */
            if (strncmp(lf->hash2_after, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash2_after, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash2_after, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash2_after, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            os_alg_status[0] = '\0';
            os_s_return = 0;
            os_s_return = snprintf(os_alg_status, 32, "%s_after", os_alg);
            if (os_s_return == -1) {
                merror("snprintf error");
            } else if (os_s_return > 32) {
                merror("snprintf overshot");
            }
            cJSON_AddStringToObject(file_diff, os_alg_status, lf->hash2_after);
        }



#else   //LIBSODIUM_ENABLED
        if (lf->md5_before && lf->md5_after && strcmp(lf->md5_before, lf->md5_after) != 0  ) {
            cJSON_AddStringToObject(file_diff, "md5_before", lf->md5_before);
            cJSON_AddStringToObject(file_diff, "md5_after", lf->md5_after);
        }
        if (lf->sha1_before && lf->sha1_after && (!strcmp(lf->sha1_before, lf->sha1_after)) != 0) {
            cJSON_AddStringToObject(file_diff, "sha1_before", lf->sha1_before);
            cJSON_AddStringToObject(file_diff, "sha1_after", lf->sha1_after);
        }
#endif  //LIBSODIUM_ENABLED
        if (lf->owner_before && lf->owner_after && (!strcmp(lf->owner_before, lf->owner_after)) != 0) {
            cJSON_AddStringToObject(file_diff, "owner_before", lf->owner_before);
            cJSON_AddStringToObject(file_diff, "owner_after", lf->owner_after);
        }
        if (lf->gowner_before && lf->gowner_after && (!strcmp(lf->gowner_before, lf->gowner_after)) != 0 ) {
            cJSON_AddStringToObject(file_diff, "gowner_before", lf->gowner_before);
            cJSON_AddStringToObject(file_diff, "gowner_after", lf->gowner_after);
        }
        if (lf->perm_before && lf->perm_after && lf->perm_before != lf->perm_after) {
            cJSON_AddNumberToObject(file_diff, "perm_before", lf->perm_before);
            cJSON_AddNumberToObject(file_diff, "perm_after", lf->perm_after);
        }
    }
    if ( lf->data ) {
        cJSON_AddStringToObject(root, "data", lf->data);
    }
    if ( lf->url ) {
        cJSON_AddStringToObject(root, "url", lf->url);
    }
    if ( lf->systemname ) {
        cJSON_AddStringToObject(root, "system_name", lf->systemname);
    }
    if ( lf->status ) {
        cJSON_AddStringToObject(root, "status", lf->status);
    }
    if ( lf->hostname ) {
        cJSON_AddStringToObject(root, "hostname", lf->hostname);
    }
    if ( lf->program_name ) {
        cJSON_AddStringToObject(root, "program_name", lf->program_name);
    }

    W_ParseJSON(root, lf);

    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

/* Convert Archiveinfo to json */
char *Archiveinfo_to_jsonstr(const Eventinfo *lf)
{
    cJSON *root;
    char *out;

    root = cJSON_CreateObject();

    if(lf->program_name)
	   cJSON_AddStringToObject(root, "program_name", lf->program_name);

    if(lf->log)
       cJSON_AddStringToObject(root, "log", lf->log);

   if(lf->srcip)
       cJSON_AddStringToObject(root, "srcip", lf->srcip); 

   if(lf->dstip)
       cJSON_AddStringToObject(root, "dstip", lf->dstip); 

   if(lf->srcport)
       cJSON_AddStringToObject(root, "srcport", lf->srcport); 

   if(lf->dstport)
       cJSON_AddStringToObject(root, "dstport", lf->dstport); 

   if(lf->protocol)
       cJSON_AddStringToObject(root, "protocol", lf->protocol);

   if(lf->action)
       cJSON_AddStringToObject(root, "action", lf->action);

   if(lf->srcuser)
       cJSON_AddStringToObject(root, "srcuser", lf->srcuser);

   if(lf->dstuser)
       cJSON_AddStringToObject(root, "dstuser", lf->dstuser);

   if(lf->id)
       cJSON_AddStringToObject(root, "id", lf->id);

   if(lf->status)
       cJSON_AddStringToObject(root, "status", lf->status);

   if(lf->command)
       cJSON_AddStringToObject(root, "command", lf->command);

   if(lf->url)
       cJSON_AddStringToObject(root, "url", lf->url);

   if(lf->data)
       cJSON_AddStringToObject(root, "data", lf->data);

   if(lf->systemname)
       cJSON_AddStringToObject(root, "systemname", lf->systemname);

  
   if (lf->filename) {
       cJSON_AddStringToObject(root, "filename", lf->filename);

#ifdef LIBSODIUM_ENABLED
        if(lf->hash1_before && lf->hash1_after && strncmp(lf->hash1_before, lf->hash1_after, 129) != 0) {
            /* Have to handle _before and _after separately since they could be different algs */
            /* hash1_before */
            char *os_alg = NULL;
            if (strncmp(lf->hash1_before, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash1_before, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash1_before, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash1_before, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            char *os_alg_status = NULL;
            int os_s_return;
             os_s_return = snprintf(os_alg_status, 32, "%s_before", os_alg);
             if (os_s_return == -1) {
                 merror("snprintf error");
             } else if (os_s_return > 32) {
                 merror("snprintf overshot");
             }
             cJSON_AddStringToObject(root, os_alg_status, lf->hash1_before);

            /* hash1_after */
            if (strncmp(lf->hash1_after, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash1_after, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash1_after, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash1_after, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            os_alg_status[0] = '\0';
            os_s_return = 0;
            os_s_return = snprintf(os_alg_status, 32, "%s_after", os_alg);
            if (os_s_return == -1) {
                merror("snprintf error");
            } else if (os_s_return > 32) {
                merror("snprintf overshot");
            }
            cJSON_AddStringToObject(root, os_alg_status, lf->hash1_after);
        }

        if(lf->hash1_before && lf->hash2_after && strncmp(lf->hash2_before, lf->hash2_after, 129) != 0) {
            /* Have to handle _before and _after separately since they could be different algs */
            /* hash2_before */
            char *os_alg = NULL;
            if (strncmp(lf->hash2_before, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash2_before, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash2_before, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash2_before, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            char *os_alg_status = NULL;
            int os_s_return;
             os_s_return = snprintf(os_alg_status, 32, "%s_before", os_alg);
             if (os_s_return == -1) {
                 merror("snprintf error");
             } else if (os_s_return > 32) {
                 merror("snprintf overshot");
             }
             cJSON_AddStringToObject(root, os_alg_status, lf->hash1_before);

            /* hash1_after */
            if (strncmp(lf->hash2_after, "SHA256", 6) == 0) {
                os_alg = "sha256";
            } else if (strncmp(lf->hash2_after, "GENERIC", 7) == 0) {
                os_alg = "blake2b";
            } else if (strncmp(lf->hash2_after, "MD5", 3) == 0) {
                os_alg = "md5";
            } else if (strncmp(lf->hash2_after, "SHA1", 4) == 0) {
                os_alg = "sha1";
            } else {
                merror("DOES NOT COMPUTER");
            }
            os_alg_status[0] = '\0';
            os_s_return = 0;
            os_s_return = snprintf(os_alg_status, 32, "%s_after", os_alg);
            if (os_s_return == -1) {
                merror("snprintf error");
            } else if (os_s_return > 32) {
                merror("snprintf overshot");
            }
            cJSON_AddStringToObject(root, os_alg_status, lf->hash2_after);
        }


#else   //LIBSODIUM_ENABLED
       if (lf->md5_before && lf->md5_after && strcmp(lf->md5_before, lf->md5_after) != 0) {
           cJSON_AddStringToObject(root, "md5_before", lf->md5_before);
           cJSON_AddStringToObject(root, "md5_after", lf->md5_after);
       }
       if (lf->sha1_before && lf->sha1_after && strcmp(lf->sha1_before, lf->sha1_after) != 0) {
           cJSON_AddStringToObject(root, "sha1_before", lf->sha1_before);
           cJSON_AddStringToObject(root, "sha1_after", lf->sha1_after);
       }
#endif  //LIBSODIUM_ENABLED
       if (lf->owner_before && lf->owner_after && strcmp(lf->owner_before, lf->owner_after) != 0) {
           cJSON_AddStringToObject(root, "owner_before", lf->owner_before);
           cJSON_AddStringToObject(root, "owner_after", lf->owner_after);
       }
       if (lf->gowner_before && lf->gowner_after && strcmp(lf->gowner_before, lf->gowner_after) != 0) {
           cJSON_AddStringToObject(root, "gowner_before", lf->gowner_before);
           cJSON_AddStringToObject(root, "gowner_after", lf->gowner_after);
       }
       if (lf->perm_before && lf->perm_after && lf->perm_before != lf->perm_after) {
           cJSON_AddNumberToObject(root, "perm_before", lf->perm_before);
           cJSON_AddNumberToObject(root, "perm_after", lf->perm_after);
       }
   }


   // RuleInfo
    if(lf->generated_rule){
        cJSON *rule;

        cJSON_AddItemToObject(root, "rule", rule = cJSON_CreateObject());

        if (lf->generated_rule->level) 
            cJSON_AddNumberToObject(rule, "level", lf->generated_rule->level);

        if (lf->generated_rule->comment) 
            cJSON_AddStringToObject(rule, "comment", lf->generated_rule->comment);
        
        if (lf->generated_rule->sigid) 
            cJSON_AddNumberToObject(rule, "sidid", lf->generated_rule->sigid);
        
        if (lf->generated_rule->cve) 
            cJSON_AddStringToObject(rule, "cve", lf->generated_rule->cve);
        
        if (lf->generated_rule->info) 
            cJSON_AddStringToObject(rule, "info", lf->generated_rule->info);

        if (lf->generated_rule->frequency) 
            cJSON_AddNumberToObject(rule, "frequency", lf->generated_rule->frequency);

        if (lf->generated_rule->firedtimes) 
            cJSON_AddNumberToObject(rule, "firedtimes", lf->generated_rule->frequency);

    }

    // DecoderInfo
    if(lf->decoder_info){
        cJSON *decoder;
        cJSON_AddItemToObject(root, "decoder", decoder = cJSON_CreateObject());

        if (lf->decoder_info->fts) 
            cJSON_AddNumberToObject(decoder, "fts", lf->decoder_info->fts);
        if (lf->decoder_info->accumulate) 
            cJSON_AddNumberToObject(decoder, "accumulate", lf->decoder_info->accumulate);
        if (lf->decoder_info->accumulate) 
            cJSON_AddNumberToObject(decoder, "accumulate", lf->decoder_info->accumulate);

        if (lf->decoder_info->parent) 
            cJSON_AddStringToObject(decoder, "parent", lf->decoder_info->parent);
        if (lf->decoder_info->name) 
            cJSON_AddStringToObject(decoder, "name", lf->decoder_info->name);
        if (lf->decoder_info->ftscomment) 
            cJSON_AddStringToObject(decoder, "ftscomment", lf->decoder_info->ftscomment);

    }


    if (lf->full_log)
        cJSON_AddStringToObject(root, "full_log", lf->full_log);

    if(lf->year && strnlen(lf->mon, 4) && lf->day && strnlen(lf->hour, 10))
        W_JSON_ParseTimestamp(root, lf);

    if(lf->hostname){
        W_JSON_ParseHostname(root, lf->hostname);
        W_JSON_ParseAgentIP(root, lf); 
    }

    if (lf->location)
       W_JSON_ParseLocation(root,lf,1);



    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}
