
// http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html

// https://en.bitcoin.it/wiki/Merged_mining_specification#Merged_mining_coinbase

#include "stratum.h"

#define TX_VALUE(v, s)	((unsigned int)(v>>s)&0xff)

static void encode_tx_value(char *encoded, json_int_t value)
{
	sprintf(encoded, "%02x%02x%02x%02x%02x%02x%02x%02x",
		TX_VALUE(value, 0), TX_VALUE(value, 8), TX_VALUE(value, 16), TX_VALUE(value, 24),
		TX_VALUE(value, 32), TX_VALUE(value, 40), TX_VALUE(value, 48), TX_VALUE(value, 56));
}

static void p2sh_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, char *payee)
{
	char evalue[32];
	char coinb2_part[256];
	char coinb2_len[4];
	sprintf(coinb2_part, "a9%02x%s87", (unsigned int)(strlen(payee) >> 1) & 0xFF, payee);
	sprintf(coinb2_len, "%02x", (unsigned int)(strlen(coinb2_part) >> 1) & 0xFF);
	encode_tx_value(evalue, amount);
	strcat(data, evalue);
	strcat(data, coinb2_len);
	strcat(data, coinb2_part);
}

static void job_pack_tx(YAAMP_COIND *coind, char *data, json_int_t amount, char *key)
{
	int ol = strlen(data);
	char evalue[32];

	if(coind->p2sh_address && !key) {
		p2sh_pack_tx(coind, data, amount, coind->script_pubkey);
		return;
	}

	encode_tx_value(evalue, amount);
	sprintf(data+strlen(data), "%s", evalue);

	if(coind->pos && !key)
		sprintf(data+strlen(data), "2321%sac", coind->pubkey);

	else
		sprintf(data+strlen(data), "1976a914%s88ac", key? key: coind->script_pubkey);

	// debuglog("pack tx %s\n", data+ol);
	// debuglog("pack tx %lld\n", amount);
}

void coinbase_aux(YAAMP_JOB_TEMPLATE *templ, char *aux_script)
{
	vector<string> hashlist = coind_aux_hashlist(templ->auxs, templ->auxs_size);
	while(hashlist.size() > 1)
	{
		vector<string> l;
		for(int i = 0; i < hashlist.size()/2; i++)
		{
			string s = hashlist[i*2] + hashlist[i*2+1];

			char bin[YAAMP_HASHLEN_BIN*2];
			char out[YAAMP_HASHLEN_STR];

			binlify((unsigned char *)bin, s.c_str());
			sha256_double_hash_hex(bin, out, YAAMP_HASHLEN_BIN*2);

			l.push_back(out);
		}

		hashlist = l;
	}

	char merkle_hash[4*1024];
	memset(merkle_hash, 0, 4*1024);
	string_be(hashlist[0].c_str(), merkle_hash);

	sprintf(aux_script+strlen(aux_script), "fabe6d6d%s%02x00000000000000", merkle_hash, templ->auxs_size);
//	debuglog("aux_script is %s\n", aux_script);
}

void coinbase_create(YAAMP_COIND *coind, YAAMP_JOB_TEMPLATE *templ, json_value *json_result)
{
	char eheight[32], etime[32];
	char entime[32] = { 0 };
	char commitment[128] = { 0 };

	ser_number(templ->height, eheight);
	ser_number(bswap32((int)time(NULL)), etime);

        // this is dim, but time will literally 'disappear' from coinb2 w/o it (!)
        char timefield[10], timeflip[10];
        memset(timefield,'\0',10);
        memset(timeflip,'\0',10);
        sprintf(timefield,"%08x",bswap32((int)time(NULL)));
        memcpy(timeflip,timefield+6,2);
        memcpy(timeflip+2,timefield+4,2);
        memcpy(timeflip+4,timefield+2,2);
        memcpy(timeflip+6,timefield,2);

	char eversion1[32] = "01000000000000";
	char script1[4*1024];
	sprintf(script1, "%s%s%s08", eheight, templ->flags, etime);
	char script2[32] = "626172727900"; // "barry\0" in hex ascii
	int script_len = 24;
	sprintf(templ->coinb1, "%s%s01"
		"0000000000000000000000000000000000000000000000000000000000000000"
		"ffffffff%02x%s", eversion1, entime, script_len, script1);
	sprintf(templ->coinb2, "%s00000000", script2);

        json_int_t available = templ->value;
        strcat(templ->coinb2, "0101");
	job_pack_tx(coind, templ->coinb2, available, NULL);
        sprintf(templ->coinb1+98,"04%s08",timeflip);
	coind->reward = (double)available/100000000*coind->reward_mul;

//	debuglog("coinbase %f\n", coind->reward);
//	debuglog("coinbase %s: version %s, nbits %s, time %s\n", coind->symbol, templ->version, templ->nbits, templ->ntime);
//      debuglog("coinb1 %s\n", templ->coinb1);
//	debuglog("coinb2 %s\n", templ->coinb2);
}
