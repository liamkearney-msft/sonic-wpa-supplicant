/*
 * MACsec rollover across an asymmetric primary-CA loss.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "utils/includes.h"
#include <assert.h>
#include "utils/common.h"
#include "utils/eloop.h"
#include "pae/ieee802_1x_cp.c"
#include "pae/ieee802_1x_kay.c"

static struct wpabuf *captured_mkpdu;
static bool capture_mkpdu;
static unsigned int fixture_count;

/* Exercise production encoding, authentication, KaY, CP, SecY and timers;
 * replace only packet transport and hardware. */
int l2_packet_send(struct l2_packet_data *l2, const u8 *dst, u16 proto,
		   const u8 *buf, size_t len)
{
	if (capture_mkpdu) {
		assert(!captured_mkpdu);
		captured_mkpdu = wpabuf_alloc_copy(buf, len);
		assert(captured_mkpdu);
	}
	return 0;
}

void l2_packet_deinit(struct l2_packet_data *l2)
{
}

struct fixture {
	struct ieee802_1x_kay kay;
	struct ieee802_1x_kay_ctx ops;
	struct ieee802_1x_mka_participant *p[2];
	int selected_an;
	struct fixture *remote;
};

static int set_flag(void *ctx, bool enabled)
{
	return 0;
}

static int enable_port(void *ctx, bool enabled)
{
	assert(!((struct fixture *) ctx)->remote || enabled);
	return 0;
}

static int set_cipher(void *ctx, u64 cs)
{
	return 0;
}

static int set_replay(void *ctx, bool enabled, u32 window)
{
	return 0;
}

static int rx_sc(void *ctx, struct receive_sc *sc,
		 enum validate_frames vf, enum confidentiality_offset co)
{
	return 0;
}

static int delete_rx_sc(void *ctx, struct receive_sc *sc)
{
	return 0;
}

static int delete_tx_sc(void *ctx, struct transmit_sc *sc)
{
	return 0;
}

static int rx_sa(void *ctx, struct receive_sa *sa)
{
	return 0;
}

static int tx_sa(void *ctx, struct transmit_sa *sa)
{
	return 0;
}

static int release_rx(void *ctx, struct receive_sa *sa)
{
	struct fixture *f = ctx;

	if (f->remote) {
		struct transmit_sa *tx = lookup_txsa_by_an(
			f->remote->kay.txsc, f->remote->selected_an);

		assert(tx && !is_ki_equal(&tx->pkey->key_identifier,
					 &sa->pkey->key_identifier));
	}
	return 0;
}

static int release_tx(void *ctx, struct transmit_sa *sa)
{
	struct fixture *f = ctx;

	assert(!f->remote || sa->an != f->selected_an);
	return 0;
}

static int select_tx(void *ctx, struct transmit_sa *sa)
{
	struct fixture *f = ctx;

	if (f->remote) {
		struct receive_sc *sc = ieee802_1x_kay_find_receive_sc(
			&f->remote->kay, &f->kay.actor_sci);
		struct receive_sa *rx = sc ? lookup_rxsa_by_an(sc, sa->an) : NULL;

		assert(rx && rx->in_use && rx->enable_receive);
		assert(is_ki_equal(&sa->pkey->key_identifier,
				  &rx->pkey->key_identifier));
		assert(sa->pkey->key_len == rx->pkey->key_len);
		assert(!os_memcmp(sa->pkey->key, rx->pkey->key,
				  sa->pkey->key_len));
	}
	f->selected_an = sa->an;
	return 0;
}

static struct ieee802_1x_kay_peer *first_peer(
	struct ieee802_1x_mka_participant *p)
{
	return dl_list_first(&p->live_peers, struct ieee802_1x_kay_peer, list);
}

static void init_fixture(struct fixture *f)
{
	struct ieee802_1x_cp_sm *sm;
	struct data_key *key;
	unsigned int i;

	os_memset(f, 0, sizeof(*f));
	if (!fixture_count++)
		assert(!eloop_init());
	f->ops.ctx = f;
	f->ops.enable_controlled_port = enable_port;
	f->ops.enable_protect_frames = set_flag;
	f->ops.enable_encrypt = set_flag;
	f->ops.set_replay_protect = set_replay;
	f->ops.set_current_cipher_suite = set_cipher;
	f->ops.create_receive_sc = rx_sc;
	f->ops.delete_receive_sc = delete_rx_sc;
	f->ops.delete_transmit_sc = delete_tx_sc;
	f->ops.create_receive_sa = rx_sa;
	f->ops.create_transmit_sa = tx_sa;
	f->ops.delete_receive_sa = release_rx;
	f->ops.delete_transmit_sa = release_tx;
	f->ops.enable_receive_sa = rx_sa;
	f->ops.enable_transmit_sa = select_tx;
	f->ops.disable_receive_sa = release_rx;
	f->ops.disable_transmit_sa = release_tx;
	f->ops.get_transmit_next_pn = tx_sa;
	f->kay.ctx = &f->ops;
	f->kay.macsec_desired = true;
	f->kay.macsec_capable = MACSEC_CAP_INTEG_AND_CONF;
	f->kay.macsec_cs_id = cipher_suite_tbl[0].id;
	f->kay.pn_exhaustion = cipher_suite_tbl[0].pn_exhaustion;
	f->kay.max_sa_per_sc = MAX_SA_PER_SC_2;
	f->kay.mka_hello_time = MKA_HELLO_TIME;
	f->kay.mka_version = MKA_VERSION_ID;
	os_memcpy(f->kay.algo_agility, mka_algo_agility, 4);
	f->kay.actor_sci.addr[0] = 2;
	f->kay.actor_sci.addr[5] = 1;
	f->kay.actor_sci.port = host_to_be16(1);
	f->kay.key_server_sci = f->kay.actor_sci;
	f->kay.dist_kn = 3;
	dl_list_init(&f->kay.participant_list);
	dl_list_init(&f->kay.sak_list);
	dl_list_init(&f->kay.rxsc_list);
	f->kay.txsc = ieee802_1x_kay_init_transmit_sc(&f->kay.actor_sci);
	assert(f->kay.txsc);
	f->kay.cp = sm = ieee802_1x_cp_sm_init(&f->kay);
	assert(sm);
	for (i = 0; i < ARRAY_SIZE(f->p); i++) {
		struct ieee802_1x_mka_participant *p = os_zalloc(sizeof(*p));
		struct ieee802_1x_kay_peer *peer;
		u8 mi[MI_LEN];

		assert(p);
		f->p[i] = p;
		p->kay = &f->kay;
		p->active = true;
		p->is_key_server = p->can_be_key_server = p->is_elected = true;
		p->advised_desired = true;
		p->advised_capability = MACSEC_CAP_INTEG_AND_CONF;
		p->is_primary = i == 0;
		p->mode = PSK;
		p->ckn.len = 4;
		p->ckn.name[0] = i + 1;
		p->cak.len = p->kek.len = p->ick.len = 16;
		os_memset(p->mi, i + 1, MI_LEN);
		p->mn = 100;
		dl_list_init(&p->live_peers);
		dl_list_init(&p->potential_peers);
		dl_list_add_tail(&f->kay.participant_list, &p->list);
		p->current_peer_sci = f->kay.actor_sci;
		p->current_peer_sci.addr[5] = 2;
		p->current_peer_id.mn = host_to_be32(1);
		os_memset(mi, 0x80 + i, sizeof(mi));
		peer = ieee802_1x_kay_create_live_peer(p, mi, 1);
		assert(peer);
		peer->macsec_desired = true;
		peer->macsec_capability = MACSEC_CAP_INTEG_AND_CONF;
		os_memcpy(p->current_peer_id.mi, mi, MI_LEN);
	}
	f->kay.principal_participant = f->p[0];
	key = os_zalloc(sizeof(*key));
	assert(key);
	key->key = os_zalloc(16);
	assert(key->key);
	key->key_len = 16;
	os_memset(key->key_identifier.mi, 1, MI_LEN);
	key->key_identifier.kn = 1;
	key->confidentiality_offset = CONFIDENTIALITY_NONE;
	ieee802_1x_kay_init_data_key(key);
	ieee802_1x_kay_use_data_key(key);
	dl_list_add(&f->kay.sak_list, &key->list);
	f->kay.new_key = key;
	assert(!ieee802_1x_kay_create_sas(&f->kay, &key->key_identifier));
	assert(!ieee802_1x_kay_enable_rx_sas(&f->kay, &key->key_identifier));
	assert(!ieee802_1x_kay_enable_tx_sas(&f->kay, &key->key_identifier));
	sm->oki = os_memdup(&key->key_identifier, sizeof(*sm->oki));
	assert(sm->oki);
	sm->otx = sm->orx = true;
	ieee802_1x_kay_set_old_sa_attr(&f->kay, sm->oki, 0, true, true);
	sm->CP_state = CP_RETIRE;
	sm->connect = SECURE;
	sm->elected_self = true;
	sm->controlled_port_enabled = true;
	sm->using_receive_sas = sm->using_transmit_sa = false;
}

static void deinit_fixture(struct fixture *f)
{
	unsigned int i;

	f->remote = NULL;
	for (i = 0; i < ARRAY_SIZE(f->p); i++) {
		if (f->p[i])
			ieee802_1x_kay_delete_mka(&f->kay, &f->p[i]->ckn);
	}
	assert(dl_list_empty(&f->kay.sak_list) && !f->kay.new_key);
	ieee802_1x_cp_sm_deinit(f->kay.cp);
	if (!--fixture_count)
		eloop_destroy();
}

static void check_path(struct fixture *a, struct fixture *b)
{
	struct ieee802_1x_cp_sm *sm = a->kay.cp;
	struct transmit_sa *tx =
		lookup_txsa_by_an(a->kay.txsc, a->selected_an);
	struct receive_sc *sc =
		ieee802_1x_kay_find_receive_sc(&b->kay, &a->kay.actor_sci);
	struct receive_sa *rx = sc && tx ?
		lookup_rxsa_by_an(sc, tx->an) : NULL;

	assert(sm->controlled_port_enabled);
	assert(tx && tx->in_use && tx->enable_transmit);
	assert(rx && rx->in_use && rx->enable_receive);
	assert(is_ki_equal(&tx->pkey->key_identifier, &rx->pkey->key_identifier));
	assert(tx->pkey->key_len == rx->pkey->key_len);
	assert(!os_memcmp(tx->pkey->key, rx->pkey->key, tx->pkey->key_len));
	tx->next_pn++;
}

static void check_pair(struct fixture *a, struct fixture *b)
{
	ieee802_1x_cp_step_run(a->kay.cp);
	ieee802_1x_cp_step_run(b->kay.cp);
	check_path(a, b);
	check_path(b, a);
}

static struct wpabuf *make_packet(struct fixture *from, unsigned int ca)
{
	struct wpabuf *buf;

	capture_mkpdu = true;
	assert(!ieee802_1x_participant_send_mkpdu(from->p[ca]));
	capture_mkpdu = false;
	buf = captured_mkpdu;
	captured_mkpdu = NULL;
	assert(buf);
	return buf;
}

static void *packet_body(struct wpabuf *buf, u8 type)
{
	u8 *pos = wpabuf_mhead_u8(buf) + sizeof(struct ieee8023_hdr) +
		sizeof(struct ieee802_1x_hdr);
	u8 *end = wpabuf_mhead_u8(buf) + wpabuf_len(buf) - DEFAULT_ICV_LEN;

	pos += MKA_HDR_LEN + MKA_ALIGN_LENGTH(get_mka_param_body_len(pos));
	while (pos + MKA_HDR_LEN < end) {
		if (get_mka_param_body_type(pos) == type)
			return pos;
		pos += MKA_HDR_LEN + MKA_ALIGN_LENGTH(get_mka_param_body_len(pos));
	}
	assert(0);
	return NULL;
}

static void sign_packet(struct fixture *from, unsigned int ca,
			struct wpabuf *buf)
{
	struct ieee802_1x_mka_participant *p = from->p[ca];
	size_t len = wpabuf_len(buf) - DEFAULT_ICV_LEN;

	assert(!ieee802_1x_icv_aes_cmac(p->ick.key, p->ick.len,
		wpabuf_head(buf), len, wpabuf_mhead_u8(buf) + len));
}

static void deliver(struct fixture *from, struct fixture *to, struct wpabuf *buf)
{
	assert(!ieee802_1x_kay_decode_mkpdu(&to->kay, wpabuf_head(buf),
					  wpabuf_len(buf)));
	check_pair(from, to);
}

static void send_to_peer(struct fixture *from, struct fixture *to,
			 unsigned int ca)
{
	struct wpabuf *buf = make_packet(from, ca);

	deliver(from, to, buf);
	wpabuf_free(buf);
}

static void init_pair(struct fixture *server, struct fixture *follower)
{
	struct receive_sc *sc;
	struct ieee802_1x_cp_sm *sm;
	unsigned int i;

	init_fixture(server);
	init_fixture(follower);
	follower->kay.actor_sci.addr[5] = 2;
	follower->kay.txsc->sci = follower->kay.actor_sci;
	follower->kay.key_server_sci = server->kay.actor_sci;
	follower->kay.actor_priority = 255;
	dl_list_for_each(sc, &follower->kay.rxsc_list, struct receive_sc, list)
		sc->sci = server->kay.actor_sci;
	sm = follower->kay.cp;
	sm->elected_self = false;
	for (i = 0; i < ARRAY_SIZE(follower->p); i++) {
		struct ieee802_1x_mka_participant *p = follower->p[i];
		struct ieee802_1x_kay_peer *peer = first_peer(p);

		os_memset(p->mi, 0x80 + i, MI_LEN);
		p->is_key_server = p->can_be_key_server = false;
		p->new_sak = server->p[i]->new_sak = false;
		peer->sci = p->current_peer_sci = server->kay.actor_sci;
		os_memcpy(peer->mi, server->p[i]->mi, MI_LEN);
		os_memcpy(p->current_peer_id.mi, peer->mi, MI_LEN);
		peer->mn = server->p[i]->mn;
		peer->is_key_server = true;
		first_peer(server->p[i])->mn = p->mn;
	}
	server->remote = follower;
	follower->remote = server;
	check_pair(server, follower);
}

static void test_primary_loss(unsigned int phase, bool deadline_first)
{
	struct fixture server, follower;
	struct ieee802_1x_cp_sm *sm, *fsm;
	struct ieee802_1x_mka_ki pending;
	struct transmit_sa *retained;
	u64 pn;
	unsigned int i;

	printf("primary loss: phase=%u deadline-first=%u\n", phase,
	       deadline_first);
	fflush(stdout);
	init_pair(&server, &follower);
	sm = server.kay.cp;
	fsm = follower.kay.cp;
	server.p[0]->new_sak = true;
	ieee802_1x_participant_timer(server.p[0], NULL);
	check_pair(&server, &follower);
	pending = server.kay.new_key->key_identifier;
	assert(sm->CP_state == CP_RECEIVING);
	if (phase >= 1) {
		send_to_peer(&server, &follower, 0);
		assert(is_ki_equal(&follower.kay.lki, &pending));
		assert(fsm->CP_state == CP_READY);
	}
	if (phase >= 2) {
		send_to_peer(&follower, &server, 0);
		assert(sm->CP_state == CP_TRANSMITTING);
	}
	if (phase >= 3)
		send_to_peer(&server, &follower, 0);

	retained = lookup_txsa_by_an(follower.kay.txsc, follower.selected_an);
	pn = retained->next_pn;
	ieee802_1x_kay_delete_mka(&follower.kay, &follower.p[0]->ckn);
	follower.p[0] = NULL;
	check_pair(&server, &follower);
	assert(follower.kay.principal_participant == follower.p[1]);
	assert(lookup_txsa_by_an(follower.kay.txsc, follower.selected_an) ==
	       retained);
	assert(retained->next_pn == pn + 1);
	for (i = 0; i < 3; i++) {
		send_to_peer(&server, &follower, 1);
		send_to_peer(&follower, &server, 1);
		assert(server.kay.principal_participant == server.p[0]);
	}
	if (deadline_first) {
		ieee802_1x_cp_transmit_when_timeout(sm, NULL);
		check_pair(&server, &follower);
	}

	retained = lookup_txsa_by_an(server.kay.txsc, server.selected_an);
	pn = retained->next_pn;
	first_peer(server.p[0])->expire = time(NULL) - 1;
	ieee802_1x_participant_timer(server.p[0], NULL);
	check_pair(&server, &follower);
	assert(dl_list_empty(&server.p[0]->live_peers));
	assert(server.kay.principal_participant == server.p[1]);
	assert(lookup_txsa_by_an(server.kay.txsc, server.selected_an) == retained);
	assert(retained->next_pn == pn + 1);
	if (!deadline_first) {
		ieee802_1x_cp_transmit_when_timeout(sm, NULL);
		check_pair(&server, &follower);
	}
	assert(!server.p[1]->new_sak);
	assert(eloop_is_timeout_registered(ieee802_1x_kay_deferred_rekey,
					   &server.kay, NULL));
	eloop_cancel_timeout(ieee802_1x_kay_deferred_rekey, &server.kay, NULL);
	ieee802_1x_kay_deferred_rekey(&server.kay, NULL);
	assert(server.p[1]->new_sak);
	server.kay.dist_time = time(NULL) - MKA_LIFE_TIME / 1000;
	for (i = 0; i < 12; i++) {
		send_to_peer(&server, &follower, 1);
		send_to_peer(&follower, &server, 1);
		ieee802_1x_participant_timer(server.p[1], NULL);
		check_pair(&server, &follower);
	}
	assert(sm->CP_state == CP_RETIRE && fsm->CP_state == CP_RETIRE);
	assert(!os_memcmp(server.kay.oki.mi, server.p[1]->mi, MI_LEN));
	assert(server.kay.oki.kn == pending.kn + 1);
	assert(server.kay.dist_kn == pending.kn + 2);
	assert(is_ki_equal(&server.kay.oki, &follower.kay.oki));
	assert(!server.p[1]->new_sak && !sm->new_sak && !fsm->new_sak);
	server.remote = follower.remote = NULL;
	deinit_fixture(&follower);
	deinit_fixture(&server);
}

static void start_rekey(struct fixture *server, struct fixture *follower)
{
	server->kay.dist_time = time(NULL) - MKA_LIFE_TIME / 1000;
	server->p[0]->new_sak = true;
	ieee802_1x_participant_timer(server->p[0], NULL);
	check_pair(server, follower);
	send_to_peer(server, follower, 0);
}

static void test_sak_use_validation(void)
{
	struct fixture server, follower;
	struct ieee802_1x_cp_sm *sm;
	struct wpabuf *buf;
	struct ieee802_1x_mka_sak_use_body *use;
	struct ieee802_1x_mka_peer_body *peers;
	unsigned int invalid;

	init_pair(&server, &follower);
	sm = server.kay.cp;
	start_rekey(&server, &follower);
	for (invalid = 0; invalid < 6; invalid++) {
		printf("SAK Use negative case %u\n", invalid);
		buf = make_packet(&follower, 0);
		use = packet_body(buf, MKA_SAK_USE);
		switch (invalid) {
		case 0: use->lan ^= 1; break;
		case 1: use->lkn = host_to_be32(999); break;
		case 2: use->lsrv_mi[0] ^= 1; break;
		case 3: use->lrx = use->ltx = false; break;
		case 4:
			peers = packet_body(buf, MKA_LIVE_PEER_LIST);
			/* A fresh actor MN without our recent MI/MN is not
			 * a fresh key confirmation. */
			os_memset(peers->peer + MI_LEN, 0, sizeof(be32));
			break;
		case 5:
			/* Both slots explicitly empty must clear prior advice. */
			use->lrx = use->ltx = use->orx = use->otx = false;
			break;
		}
		sign_packet(&follower, 0, buf);
		deliver(&follower, &server, buf);
		assert(sm->CP_state == CP_RECEIVING);
		assert(!sm->all_receiving && !sm->all_transmitting);
		assert(ieee802_1x_kay_decode_mkpdu(&server.kay,
			wpabuf_head(buf), wpabuf_len(buf)) < 0);
		wpabuf_free(buf);
	}
	buf = make_packet(&follower, 0);
	wpabuf_mhead_u8(buf)[wpabuf_len(buf) - 1] ^= 1;
	assert(ieee802_1x_kay_decode_mkpdu(&server.kay,
		wpabuf_head(buf), wpabuf_len(buf)) < 0);
	assert(sm->CP_state == CP_RECEIVING);
	wpabuf_free(buf);

	/* Match the installed KI+AN in the old slot even when the peer
	 * advertises a different latest RX key. */
	buf = make_packet(&follower, 0);
	use = packet_body(buf, MKA_SAK_USE);
	os_memcpy(use->osrv_mi, use->lsrv_mi, MI_LEN);
	use->okn = use->lkn;
	use->oan = use->lan;
	use->orx = true;
	use->otx = false;
	use->lkn = host_to_be32(999);
	sign_packet(&follower, 0, buf);
	deliver(&follower, &server, buf);
	assert(sm->CP_state == CP_TRANSMITTING && sm->oki);
	wpabuf_free(buf);
	send_to_peer(&server, &follower, 0);
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_RETIRE);
	server.remote = follower.remote = NULL;
	deinit_fixture(&follower);
	deinit_fixture(&server);
	puts("PASS: authenticated wrong KI/AN, stale MN/ack, bad ICV and old-slot advice");
}

static void test_old_key_advertisement(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct wpabuf *buf;
	struct ieee802_1x_mka_sak_use_body *use;

	init_fixture(&f);
	sm = f.kay.cp;
	f.kay.dist_kn = sm->oki->kn;
	f.p[0]->mi[0] ^= 1;
	assert(!ieee802_1x_kay_generate_new_sak(f.p[0]));
	ieee802_1x_cp_step_run(sm);
	buf = make_packet(&f, 0);
	use = packet_body(buf, MKA_SAK_USE);
	assert(use->lkn == use->okn);
	assert(os_memcmp(use->lsrv_mi, use->osrv_mi, MI_LEN));
	assert(!use->ltx && use->lrx && use->otx && use->orx);
	wpabuf_free(buf);
	first_peer(f.p[0])->sak_used = true;
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING);
	buf = make_packet(&f, 0);
	use = packet_body(buf, MKA_SAK_USE);
	assert(use->ltx && use->lrx && !use->otx && use->orx);
	wpabuf_free(buf);
	deinit_fixture(&f);
	puts("PASS: full key identity and truthful old-slot TX/RX advertisement");
}

static void test_overlap_and_retirement(void)
{
	struct fixture server, follower;
	struct ieee802_1x_cp_sm *sm, *fsm;
	struct ieee802_1x_mka_ki candidate;
	u32 kn;
	unsigned int i;

	init_pair(&server, &follower);
	sm = server.kay.cp;
	fsm = follower.kay.cp;
	start_rekey(&server, &follower);
	candidate = server.kay.lki;
	kn = server.kay.dist_kn;
	server.kay.dist_time = time(NULL) - MKA_LIFE_TIME / 1000;
	assert(ieee802_1x_kay_generate_new_sak(server.p[0]) < 0);
	assert(server.kay.dist_kn == kn);
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_TRANSMITTING);
	server.p[0]->new_sak = true;
	ieee802_1x_participant_timer(server.p[0], NULL);
	check_pair(&server, &follower);
	assert(sm->oki && sm->lki && server.p[0]->new_sak);
	assert(server.kay.dist_kn == kn && is_ki_equal(sm->lki, &candidate));
	ieee802_1x_cp_transmit_when_timeout(sm, NULL);
	check_pair(&server, &follower);
	assert(sm->oki && sm->lki);
	send_to_peer(&server, &follower, 0);
	assert(fsm->CP_state == CP_TRANSMITTING);
	first_peer(server.p[1])->old_sak_txed = true;
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_RETIRE);
	assert(!first_peer(server.p[1])->old_sak_txed);
	for (i = 0; i < 6; i++) {
		ieee802_1x_participant_timer(server.p[0], NULL);
		check_pair(&server, &follower);
		send_to_peer(&server, &follower, 0);
		send_to_peer(&follower, &server, 0);
	}
	assert(server.kay.dist_kn == kn + 1);
	assert(sm->CP_state == CP_RETIRE && fsm->CP_state == CP_RETIRE);
	server.remote = follower.remote = NULL;
	deinit_fixture(&follower);
	deinit_fixture(&server);
	puts("PASS: queued rekey waits for committed rollover, then runs once");
}

static void test_multi_peer_and_expired_advice(void)
{
	struct fixture server, follower;
	struct ieee802_1x_mka_participant *p;
	struct ieee802_1x_kay_peer *extra, *peer;
	struct ieee802_1x_cp_sm *sm;
	struct ieee802_1x_mka_ki candidate;
	struct wpabuf *buf;
	struct ieee802_1x_mka_sak_use_body *use;
	u8 mi[MI_LEN];

	init_pair(&server, &follower);
	p = server.p[0];
	peer = ieee802_1x_kay_get_live_peer(p, follower.p[0]->mi);
	assert(peer);
	sm = server.kay.cp;
	p->current_peer_sci.addr[5] = 3;
	os_memset(mi, 0x90, MI_LEN);
	extra = ieee802_1x_kay_create_live_peer(p, mi, 1);
	assert(extra);
	start_rekey(&server, &follower);
	candidate = *sm->lki;
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_RECEIVING);
	assert(peer->sak_use_seen);
	extra->sak_used = true;
	extra->expire = time(NULL) - 1;
	ieee802_1x_cp_transmit_when_timeout(sm, NULL);
	check_pair(&server, &follower);
	assert(sm->CP_state == CP_RECEIVING);
	buf = make_packet(&follower, 0);
	use = packet_body(buf, MKA_SAK_USE);
	use->lan ^= 1;
	sign_packet(&follower, 0, buf);
	deliver(&follower, &server, buf);
	wpabuf_free(buf);
	extra->expire = time(NULL) + MKA_LIFE_TIME / 1000;
	check_pair(&server, &follower);
	assert(sm->CP_state == CP_RECEIVING);
	/* Missing-SAK-Use detection must survive readiness retraction. */
	buf = make_packet(&follower, 0);
	use = packet_body(buf, MKA_SAK_USE);
	{
		struct wpabuf *missing = wpabuf_alloc(
			wpabuf_len(buf) - sizeof(*use));
		struct ieee802_1x_hdr *hdr;
		size_t prefix = (u8 *) use - wpabuf_mhead_u8(buf);

		assert(missing);
		wpabuf_put_data(missing, wpabuf_head(buf), prefix);
		wpabuf_put_data(missing, (u8 *) use + sizeof(*use),
			wpabuf_len(buf) - prefix - sizeof(*use));
		hdr = (struct ieee802_1x_hdr *)
			(wpabuf_mhead_u8(missing) + sizeof(struct ieee8023_hdr));
		hdr->length = host_to_be16(be_to_host16(hdr->length) -
					 sizeof(*use));
		sign_packet(&follower, 0, missing);
		assert(ieee802_1x_kay_decode_mkpdu(&server.kay,
			wpabuf_head(missing), wpabuf_len(missing)) < 0);
		wpabuf_free(missing);
	}
	wpabuf_free(buf);
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_TRANSMITTING);
	/* The second live peer still transmits old, even if the first
	 * reports the candidate. A rekey request must not bypass it. */
	send_to_peer(&server, &follower, 0);
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_TRANSMITTING && sm->oki);
	server.p[0]->new_sak = true;
	ieee802_1x_participant_timer(server.p[0], NULL);
	check_pair(&server, &follower);
	assert(sm->CP_state == CP_TRANSMITTING);
	extra->sak_txed = true;
	peer->expire = time(NULL) - 1;
	check_pair(&server, &follower);
	assert(sm->CP_state == CP_TRANSMITTING);
	peer->expire = time(NULL) + MKA_LIFE_TIME / 1000;
	buf = make_packet(&follower, 0);
	use = packet_body(buf, MKA_SAK_USE);
	use->lkn = use->okn = host_to_be32(999);
	sign_packet(&follower, 0, buf);
	deliver(&follower, &server, buf);
	wpabuf_free(buf);
	check_pair(&server, &follower);
	assert(sm->CP_state == CP_TRANSMITTING);
	send_to_peer(&follower, &server, 0);
	assert(sm->CP_state == CP_RETIRE);
	assert(is_ki_equal(sm->oki, &candidate));
	server.remote = follower.remote = NULL;
	deinit_fixture(&follower);
	deinit_fixture(&server);
	puts("PASS: all-live-peer RX/TX gates and confirmation freshness at CP step");
}

static void test_follower_retire_failsafe(void)
{
	struct fixture server, follower;
	struct ieee802_1x_cp_sm *fsm;
	struct ieee802_1x_mka_participant *p;
	u8 mi[MI_LEN];

	init_pair(&server, &follower);
	p = follower.p[0];
	p->current_peer_sci.addr[5] = 3;
	os_memset(mi, 0x93, MI_LEN);
	assert(ieee802_1x_kay_create_live_peer(p, mi, 1));
	start_rekey(&server, &follower);
	send_to_peer(&follower, &server, 0);
	send_to_peer(&server, &follower, 0);
	fsm = follower.kay.cp;
	assert(fsm->CP_state == CP_TRANSMITTING && fsm->oki);
	assert(fsm->retire_when == MKA_SAK_RETIRE_FAILSAFE_TIME);
	/* Server TX alone is insufficient: this follower also receives from
	 * a live non-server peer that has not confirmed candidate TX. */
	check_pair(&server, &follower);
	assert(fsm->CP_state == CP_TRANSMITTING && fsm->oki);
	ieee802_1x_cp_retire_when_timeout(fsm, NULL);
	check_pair(&server, &follower);
	assert(fsm->CP_state == CP_RETIRE);
	server.remote = follower.remote = NULL;
	deinit_fixture(&follower);
	deinit_fixture(&server);
	puts("PASS: follower old RX waits for exact TX or existing 20-second escape");
}

static void test_absent_tx_recovery(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct transmit_sa *tx;
	struct ieee802_1x_mka_ki missing;

	init_fixture(&f);
	sm = f.kay.cp;
	f.p[0]->new_sak = true;
	ieee802_1x_participant_timer(f.p[0], NULL);
	ieee802_1x_cp_step_run(sm);
	missing = *sm->lki;
	tx = lookup_txsa_by_an(f.kay.txsc, sm->lan);
	assert(tx);
	ieee802_1x_delete_transmit_sa(&f.kay, tx);
	sm->CP_state = CP_TRANSMIT;
	sm->using_transmit_sa = false;
	sm->ltx = true;
	f.kay.ltx = true;
	f.kay.dist_time = time(NULL) - MKA_LIFE_TIME / 1000;
	assert(!ieee802_1x_cp_sak_pending(sm));
	assert(!ieee802_1x_kay_generate_new_sak(f.p[0]));
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state != CP_TRANSMIT && sm->lki);
	assert(!is_ki_equal(sm->lki, &missing));
	deinit_fixture(&f);
	puts("PASS: merged teardown recovery with actually absent TX SA");
}

static void test_queued_proposal_and_teardown(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct ieee802_1x_mka_ki abandoned;
	struct transmit_sa *tx;
	u64 pn;

	init_fixture(&f);
	sm = f.kay.cp;
	tx = lookup_txsa_by_an(f.kay.txsc, f.selected_an);
	pn = tx->next_pn;
	assert(!ieee802_1x_kay_generate_new_sak(f.p[0]));
	assert(sm->new_sak && !sm->lki);
	abandoned = sm->distributed_ki;
	assert(ieee802_1x_kay_generate_new_sak(f.p[0]) < 0);
	ieee802_1x_kay_delete_mka(&f.kay, &f.p[0]->ckn);
	f.p[0] = NULL;
	assert(!sm->new_sak && !sm->lki && sm->oki);
	assert(f.kay.principal_participant == f.p[1]);
	assert(!f.kay.new_key && dl_list_len(&f.kay.sak_list) == 1);
	assert(lookup_txsa_by_an(f.kay.txsc, f.selected_an) == tx);
	assert(tx->next_pn == pn);
	assert(!is_ki_equal(&tx->pkey->key_identifier, &abandoned));
	ieee802_1x_kay_delete_mka(&f.kay, &f.p[1]->ckn);
	f.p[1] = NULL;
	assert(!f.kay.txsc && dl_list_empty(&f.kay.sak_list));
	ieee802_1x_cp_step_run(sm);
	assert(!sm->lki && !sm->oki && !sm->controlled_port_enabled);
	deinit_fixture(&f);
	puts("PASS: queued uncommitted proposal and final-CA teardown");
}

static void test_cipher_and_authorization_change(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;

	init_fixture(&f);
	sm = f.kay.cp;
	assert(!ieee802_1x_kay_generate_new_sak(f.p[0]));
	ieee802_1x_cp_step_run(sm);
	assert(ieee802_1x_cp_sak_pending(sm));
	ieee802_1x_cp_set_ciphersuite(sm, cipher_suite_tbl[1].id);
	assert(!ieee802_1x_cp_sak_pending(sm));
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_SECURED && !sm->controlled_port_enabled);
	assert(!sm->lki && !sm->oki && dl_list_empty(&f.kay.sak_list));
	ieee802_1x_cp_connect_authenticated(sm);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_AUTHENTICATED);
	deinit_fixture(&f);
	puts("PASS: real cipher/authorization changes retain ordinary CP teardown");
}

int main(int argc, char *argv[])
{
	unsigned int phase, order;

	wpa_debug_level = getenv("MKA_DEBUG") ? MSG_DEBUG : MSG_ERROR;
	if (argc == 3) {
		test_primary_loss(atoi(argv[1]), atoi(argv[2]));
		return 0;
	}
	for (phase = 0; phase < 4; phase++)
		for (order = 0; order < 2; order++)
			test_primary_loss(phase, order);
	test_sak_use_validation();
	test_old_key_advertisement();
	test_overlap_and_retirement();
	test_multi_peer_and_expired_advice();
	test_follower_retire_failsafe();
	test_absent_tx_recovery();
	test_queued_proposal_and_teardown();
	test_cipher_and_authorization_change();
	puts("PASS: paired primary loss and first fallback rollover");
	return 0;
}
