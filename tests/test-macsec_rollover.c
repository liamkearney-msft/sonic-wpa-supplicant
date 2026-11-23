/*
 * Port-owned MACsec key lifecycle regression tests.
 * Copyright (c) 2026
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

/* Only packet transport and hardware operations are replaced. */
int l2_packet_send(struct l2_packet_data *l2, const u8 *dst, u16 proto,
		   const u8 *buf, size_t len)
{
	return 0;
}

void l2_packet_deinit(struct l2_packet_data *l2)
{
}

struct fixture {
	struct ieee802_1x_kay kay;
	struct ieee802_1x_kay_ctx ops;
	struct ieee802_1x_mka_participant *p[2];
	struct data_key *old, *candidate;
	unsigned int creates, deletes, selections;
	int selected_an, fail_an;
	int abandon_result;
	bool fail_rx, fail_after_select, abandon_during_select;
	bool expire_before_select;
};

static struct receive_sc *peer_sc(struct ieee802_1x_mka_participant *p);

static int set_flag(void *ctx, bool enabled)
{
	return 0;
}

static int enable_port(void *ctx, bool enabled)
{
	struct fixture *f = ctx;

	if (enabled && f->expire_before_select)
		peer_sc(f->kay.principal_participant)->sak_use_expire = time(NULL) - 1;
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

static int create_rx(void *ctx, struct receive_sa *sa)
{
	((struct fixture *) ctx)->creates++;
	return 0;
}

static int create_tx(void *ctx, struct transmit_sa *sa)
{
	((struct fixture *) ctx)->creates++;
	return 0;
}

static int delete_rx(void *ctx, struct receive_sa *sa)
{
	((struct fixture *) ctx)->deletes++;
	return 0;
}

static int delete_tx(void *ctx, struct transmit_sa *sa)
{
	((struct fixture *) ctx)->deletes++;
	return 0;
}

static int enable_rx(void *ctx, struct receive_sa *sa)
{
	return ((struct fixture *) ctx)->fail_rx ? -1 : 0;
}

static int disable_rx(void *ctx, struct receive_sa *sa)
{
	return 0;
}

static int disable_tx(void *ctx, struct transmit_sa *sa)
{
	return 0;
}

static int enable_tx(void *ctx, struct transmit_sa *sa)
{
	struct fixture *f = ctx;

	if (f->abandon_during_select && sa->an == 1) {
		f->abandon_during_select = false;
		f->abandon_result = ieee802_1x_cp_abandon_sak(f->kay.cp);
	}
	if (f->fail_an == sa->an && !f->fail_after_select)
		return -1;
	f->selected_an = sa->an;
	f->selections++;
	return f->fail_an == sa->an ? -1 : 0;
}

static int get_pn(void *ctx, struct transmit_sa *sa)
{
	return 0;
}

static struct ieee802_1x_kay_peer *first_peer(
	struct ieee802_1x_mka_participant *p)
{
	return dl_list_first(&p->live_peers, struct ieee802_1x_kay_peer, list);
}

static struct receive_sc *peer_sc(struct ieee802_1x_mka_participant *p)
{
	return ieee802_1x_kay_find_receive_sc(p->kay, &first_peer(p)->sci);
}

static struct data_key *add_key(struct fixture *f, u32 kn, u8 an, u8 mi)
{
	struct data_key *key = os_zalloc(sizeof(*key));

	assert(key);
	key->key = os_zalloc(16);
	assert(key->key);
	key->key_len = 16;
	os_memset(key->key_identifier.mi, mi, MI_LEN);
	key->key_identifier.kn = kn;
	key->an = an;
	key->confidentiality_offset = CONFIDENTIALITY_NONE;
	key->next_pn = 1;
	ieee802_1x_kay_init_data_key(key);
	ieee802_1x_kay_use_data_key(key);
	dl_list_add(&f->kay.sak_list, &key->list);
	f->kay.new_key = key;
	return key;
}

static void init_fixture(struct fixture *f, bool candidate)
{
	struct ieee802_1x_cp_sm *sm;
	unsigned int i;

	os_memset(f, 0, sizeof(*f));
	assert(!eloop_init());
	f->fail_an = -1;
	f->ops.ctx = f;
	f->ops.enable_controlled_port = enable_port;
	f->ops.enable_protect_frames = set_flag;
	f->ops.enable_encrypt = set_flag;
	f->ops.set_replay_protect = set_replay;
	f->ops.set_current_cipher_suite = set_cipher;
	f->ops.create_receive_sc = rx_sc;
	f->ops.delete_receive_sc = delete_rx_sc;
	f->ops.delete_transmit_sc = delete_tx_sc;
	f->ops.create_receive_sa = create_rx;
	f->ops.create_transmit_sa = create_tx;
	f->ops.delete_receive_sa = delete_rx;
	f->ops.delete_transmit_sa = delete_tx;
	f->ops.enable_receive_sa = enable_rx;
	f->ops.enable_transmit_sa = enable_tx;
	f->ops.disable_receive_sa = disable_rx;
	f->ops.disable_transmit_sa = disable_tx;
	f->ops.get_transmit_next_pn = get_pn;
	f->kay.ctx = &f->ops;
	f->kay.macsec_desired = true;
	f->kay.macsec_capable = MACSEC_CAP_INTEG_AND_CONF;
	f->kay.macsec_cs_id = cipher_suite_tbl[0].id;
	f->kay.pn_exhaustion = cipher_suite_tbl[0].pn_exhaustion;
	f->kay.max_sa_per_sc = MAX_SA_PER_SC_2;
	f->kay.mka_hello_time = MKA_HELLO_TIME;
	f->kay.mka_version = MKA_VERSION_ID;
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
	f->old = add_key(f, 1, 0, 1);
	assert(!ieee802_1x_kay_create_sas(&f->kay, &f->old->key_identifier));
	assert(!ieee802_1x_kay_enable_rx_sas(&f->kay,
					     &f->old->key_identifier));
	assert(!ieee802_1x_kay_enable_tx_sas(&f->kay,
					     &f->old->key_identifier));
	sm->oki = os_memdup(&f->old->key_identifier, sizeof(*sm->oki));
	assert(sm->oki);
	sm->oan = 0;
	sm->otx = sm->orx = true;
	ieee802_1x_kay_set_old_sa_attr(&f->kay, sm->oki, 0, true, true);
	sm->CP_state = CP_RETIRE;
	sm->connect = SECURE;
	sm->elected_self = true;
	sm->controlled_port_enabled = true;
	sm->current_cipher_suite = sm->cipher_suite;
	sm->using_receive_sas = sm->using_transmit_sa = false;
	if (candidate) {
		f->candidate = add_key(f, 2, 1, 1);
		ieee802_1x_cp_set_distributedki(sm,
					       &f->candidate->key_identifier);
		ieee802_1x_cp_set_distributedan(sm, 1);
		ieee802_1x_cp_signal_newsak(sm);
		ieee802_1x_cp_step_run(sm);
		assert(sm->CP_state == CP_RECEIVING);
	}
}

static void deinit_fixture(struct fixture *f)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(f->p); i++) {
		if (f->p[i])
			ieee802_1x_kay_delete_mka(&f->kay, &f->p[i]->ckn);
	}
	assert(dl_list_empty(&f->kay.sak_list));
	assert(!f->kay.new_key);
	ieee802_1x_cp_sm_deinit(f->kay.cp);
	eloop_destroy();
}

static void observe_old(struct fixture *f, unsigned int ca, bool candidate_tx)
{
	struct ieee802_1x_kay_peer *peer = first_peer(f->p[ca]);
	struct receive_sc *sc = peer_sc(f->p[ca]);

	sc->sak_ki[0] = f->old->key_identifier;
	sc->sak_an[0] = 0;
	sc->sak_rx[0] = sc->sak_tx[0] = true;
	sc->sak_ki[1] = f->candidate->key_identifier;
	sc->sak_an[1] = 1;
	sc->sak_rx[1] = true;
	sc->sak_tx[1] = candidate_tx;
	sc->sak_use_expire = peer->expire = time(NULL) + 6;
}

static void observe_missing_candidate(struct fixture *f, unsigned int ca)
{
	observe_old(f, ca, false);
	peer_sc(f->p[ca])->sak_rx[1] = false;
}

static void commit_transmit(struct fixture *f)
{
	struct ieee802_1x_cp_sm *sm = f->kay.cp;
	unsigned int ca = f->kay.principal_participant == f->p[0] ? 0 : 1;

	observe_old(f, ca, false);
	ieee802_1x_kay_update_sak_use(f->p[ca]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING);
	assert(f->selected_an == 1);
}

static void test_unready_transmit_deadline(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;

	init_fixture(&f, true);
	sm = f.kay.cp;
	observe_missing_candidate(&f, 0);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	assert(!sm->all_receiving);
	ieee802_1x_cp_transmit_when_timeout(sm, NULL);
	assert(f.selected_an == 0 && !sm->ltx);
	assert(!lookup_txsa_by_an(f.kay.txsc, 1)->enable_transmit);
	assert(f.p[0]->new_sak);
	deinit_fixture(&f);
	puts("PASS: a missed DistSAK cannot force TX at the transmit deadline");
}

static void test_fresh_readiness_at_selection(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct receive_sc *sc;
	struct ieee802_1x_kay_peer other;
	struct receive_sc other_sc;
	unsigned int i;

	for (i = 0; i < 6; i++) {
		init_fixture(&f, true);
		sm = f.kay.cp;
		observe_old(&f, 0, false);
		sc = peer_sc(f.p[0]);
		switch (i) {
		case 0:
			sc->sak_rx[1] = false;
			break;
		case 1:
			sc->sak_ki[1].mi[0] ^= 1;
			break;
		case 2:
			sc->sak_an[1] = 0;
			break;
		case 3:
			sc->sak_use_expire = time(NULL) - 1;
			break;
		case 4:
			first_peer(f.p[0])->expire = time(NULL) - 1;
			break;
		case 5:
			sm->controlled_port_enabled = false;
			sc->sak_rx[1] = false;
			break;
		}
		sm->all_receiving = true;
		ieee802_1x_cp_transmit_when_timeout(sm, NULL);
		assert(f.selected_an == 0 && !sm->tx_selection_started);
		deinit_fixture(&f);
	}
	init_fixture(&f, true);
	sm = f.kay.cp;
	observe_old(&f, 0, false);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	f.expire_before_select = true;
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_RECEIVING && !sm->tx_selection_started);
	assert(f.selected_an == 0);
	deinit_fixture(&f);

	init_fixture(&f, true);
	sm = f.kay.cp;
	observe_old(&f, 0, false);
	other = *first_peer(f.p[0]);
	other_sc = *peer_sc(f.p[0]);
	other_sc.sci.addr[5] = 3;
	other.sci = other_sc.sci;
	other_sc.sak_rx[1] = false;
	dl_list_init(&other_sc.sa_list);
	dl_list_add(&f.kay.rxsc_list, &other_sc.list);
	dl_list_add(&f.p[0]->live_peers, &other.list);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_RECEIVING && f.selected_an == 0);
	other_sc.sak_rx[1] = true;
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING && f.selected_an == 1);
	dl_list_del(&other.list);
	dl_list_del(&other_sc.list);
	deinit_fixture(&f);

	init_fixture(&f, true);
	sm = f.kay.cp;
	sm->elected_self = f.p[0]->is_key_server = false;
	sm->controlled_port_enabled = false;
	first_peer(f.p[0])->is_key_server = true;
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_READY && f.selected_an == 0);
	observe_missing_candidate(&f, 0);
	sm->server_transmitting = true;
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_READY && f.selected_an == 0);
	observe_old(&f, 0, false);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_READY && f.selected_an == 0);
	observe_old(&f, 0, true);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING && f.selected_an == 1);
	deinit_fixture(&f);
	puts("PASS: stale flags, wrong KI/AN and closed-port startup cannot bypass RX readiness");
}

static void test_missed_distribution_failover(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct transmit_sa *old_tx;
	unsigned int selections;

	init_fixture(&f, true);
	sm = f.kay.cp;
	old_tx = lookup_txsa_by_an(f.kay.txsc, 0);
	old_tx->next_pn = 777;
	selections = f.selections;
	observe_missing_candidate(&f, 0);
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[1]);
	ieee802_1x_kay_elect_key_server(f.p[1], true);
	ieee802_1x_kay_update_sak_use(f.p[1]);
	assert(sm->CP_state == CP_ABANDON && f.selected_an == 0);
	assert(f.candidate->abandoned && !sm->tx_selection_started);
	ieee802_1x_kay_delete_mka(&f.kay, &f.p[0]->ckn);
	f.p[0] = NULL;
	ieee802_1x_cp_retire_when_timeout(sm, NULL);
	assert(!f.kay.lki.kn && f.kay.oki.kn == 1);
	assert(f.selections == selections && old_tx->next_pn == 777);
	assert(old_tx == lookup_txsa_by_an(f.kay.txsc, 0));
	assert(!ieee802_1x_kay_generate_new_sak(f.p[1]));
	f.candidate = f.kay.new_key;
	assert(f.candidate->key_identifier.kn == 3);
	assert(!os_memcmp(f.candidate->key_identifier.mi, f.p[1]->mi, MI_LEN));
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_RECEIVING && f.selected_an == 0);
	commit_transmit(&f);
	assert(f.selections == selections + 1);
	deinit_fixture(&f);
	puts("PASS: missed DistSAK at CAK failover retains TX until the fresh proposal is received");
}

static void test_tx_point_of_no_return(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	unsigned int creates, deletes, selections;

	init_fixture(&f, true);
	sm = f.kay.cp;
	f.abandon_during_select = true;
	commit_transmit(&f);
	assert(f.abandon_result < 0 && sm->tx_selection_started);
	assert(sm->ltx && !f.candidate->abandoned);
	creates = f.creates;
	deletes = f.deletes;
	selections = f.selections;
	assert(ieee802_1x_cp_abandon_sak(sm) < 0);
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[1]);
	observe_missing_candidate(&f, 1);
	ieee802_1x_kay_update_sak_use(f.p[1]);
	assert(!ieee802_1x_kay_can_abandon_sak(&f.kay));
	assert(ieee802_1x_kay_generate_new_sak(f.p[1]) < 0);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING && f.selected_an == 1);
	assert(f.kay.new_key == f.candidate && !f.candidate->abandoned);
	assert(f.creates == creates && f.deletes == deletes &&
	       f.selections == selections);
	deinit_fixture(&f);
	puts("PASS: queued and committed TX survive handover without old-TX reselection");
}

static void test_shared_recovery(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct transmit_sa *old_tx;
	struct ieee802_1x_kay_peer other;
	struct receive_sc other_sc;
	unsigned int creates, deletes;

	init_fixture(&f, true);
	sm = f.kay.cp;
	old_tx = lookup_txsa_by_an(f.kay.txsc, 0);
	old_tx->next_pn = 777;
	creates = f.creates;
	deletes = f.deletes;
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[1]);
	assert(sm->CP_state == CP_RECEIVING);
	assert(f.kay.new_key == f.candidate);
	assert(!ieee802_1x_mka_sak_use_body_present(f.p[0]));
	assert(ieee802_1x_mka_sak_use_body_present(f.p[1]));
	assert(!ieee802_1x_mka_dist_sak_body_present(f.p[1]));
	assert(ieee802_1x_kay_generate_new_sak(f.p[1]) < 0);
	assert(ieee802_1x_kay_select_dist_an(f.p[1]) < 0);
	assert(!ieee802_1x_kay_can_abandon_sak(&f.kay));
	observe_old(&f, 1, true);
	assert(!ieee802_1x_kay_can_abandon_sak(&f.kay));
	observe_missing_candidate(&f, 1);
	other = *first_peer(f.p[1]);
	other_sc = *peer_sc(f.p[1]);
	other_sc.sci.addr[5] = 3;
	other.sci = other_sc.sci;
	other_sc.sak_use_expire = 0;
	dl_list_init(&other_sc.sa_list);
	dl_list_add(&f.kay.rxsc_list, &other_sc.list);
	dl_list_add(&f.p[1]->live_peers, &other.list);
	assert(!ieee802_1x_kay_can_abandon_sak(&f.kay));
	other_sc.sak_use_expire = time(NULL) + 6;
	other_sc.sak_tx[1] = true;
	assert(!ieee802_1x_kay_can_abandon_sak(&f.kay));
	other_sc.sak_tx[1] = false;
	other_sc.sak_rx[0] = false;
	assert(!ieee802_1x_kay_can_abandon_sak(&f.kay));
	other_sc.sak_rx[0] = true;
	assert(ieee802_1x_kay_can_abandon_sak(&f.kay));
	dl_list_del(&other.list);
	dl_list_del(&other_sc.list);
	f.fail_an = 0;
	assert(!ieee802_1x_cp_abandon_sak(sm));
	assert(sm->CP_state == CP_ABANDON && f.selected_an == 0);
	assert(f.candidate->abandoned);
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[0]);
	ieee802_1x_kay_elect_key_server(f.p[0], true);
	assert(!ieee802_1x_mka_dist_sak_body_present(f.p[0]));
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[1]);
	assert(old_tx == lookup_txsa_by_an(f.kay.txsc, 0));
	assert(old_tx->next_pn == 777 && f.creates == creates);
	sm->transmit_when = 1234;
	assert(!ieee802_1x_cp_abandon_sak(sm));
	assert(sm->transmit_when == 1234);
	peer_sc(f.p[1])->sak_use_expire = time(NULL) - 1;
	ieee802_1x_cp_retire_when_timeout(sm, NULL);
	ieee802_1x_cp_step_run(sm);
	assert(f.kay.lki.kn == 2 && f.deletes == deletes);
	observe_old(&f, 1, true);
	ieee802_1x_cp_step_run(sm);
	assert(f.kay.lki.kn == 2);
	observe_missing_candidate(&f, 1);
	ieee802_1x_cp_step_run(sm);
	assert(!f.kay.lki.kn && f.kay.oki.kn == 1);
	assert(f.kay.new_key == f.old);
	assert(f.deletes == deletes + 2);
	assert(!ieee802_1x_kay_generate_new_sak(f.p[1]));
	assert(f.kay.new_key->key_identifier.kn == 3);
	assert(!os_memcmp(f.kay.new_key->key_identifier.mi, f.p[1]->mi, MI_LEN));
	deinit_fixture(&f);
	puts("PASS: inherited pre-TX rekey, RX drain and fresh proposal without reselection");
}

static void test_pre_tx_and_bounds(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;

	init_fixture(&f, true);
	sm = f.kay.cp;
	observe_missing_candidate(&f, 0);
	assert(!ieee802_1x_cp_abandon_sak(sm));
	assert(f.selected_an == 0);
	ieee802_1x_cp_retire_when_timeout(sm, NULL);
	ieee802_1x_cp_step_run(sm);
	assert(!f.kay.lki.kn);
	deinit_fixture(&f);

	init_fixture(&f, true);
	sm = f.kay.cp;
	assert(!ieee802_1x_cp_abandon_sak(sm));
	ieee802_1x_cp_transmit_when_timeout(sm, NULL);
	ieee802_1x_cp_step_run(sm);
	assert(f.kay.failed && f.p[0]->new_sak);
	assert(dl_list_empty(&f.kay.sak_list));
	assert(!sm->controlled_port_enabled);
	deinit_fixture(&f);

	init_fixture(&f, true);
	sm = f.kay.cp;
	assert(!ieee802_1x_cp_abandon_sak(sm));
	sm->transmit_when = 1234;
	observe_old(&f, 0, true);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING && f.selected_an == 1);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_RETIRE && f.selected_an == 1);
	assert(f.kay.oki.kn == 2 && !f.kay.lki.kn);
	deinit_fixture(&f);
	puts("PASS: pre-TX abort, bounded unknown state and a late peer commitment");
}

static void test_lost_distribution_and_teardown(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct data_key *candidate;
	struct receive_sc *sc;
	unsigned int creates;

	init_fixture(&f, false);
	sm = f.kay.cp;
	assert(!ieee802_1x_kay_generate_new_sak(f.p[0]));
	f.p[0]->to_dist_sak = true;
	sc = peer_sc(f.p[0]);
	sc->sak_ki[0] = f.old->key_identifier;
	sc->sak_an[0] = 0;
	sc->sak_rx[0] = sc->sak_tx[0] = true;
	sc->sak_use_expire = time(NULL) + 6;
	ieee802_1x_kay_update_sak_use(f.p[0]);
	assert(!f.kay.lki.kn);
	assert(!sm->all_receiving && f.p[0]->to_dist_sak);
	deinit_fixture(&f);

	init_fixture(&f, false);
	sm = f.kay.cp;
	assert(!ieee802_1x_kay_generate_new_sak(f.p[0]));
	f.candidate = f.kay.new_key;
	observe_old(&f, 0, false);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	assert(!f.kay.lki.kn);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMITTING && f.selected_an == 1);
	deinit_fixture(&f);

	init_fixture(&f, true);
	sm = f.kay.cp;
	candidate = f.kay.new_key;
	creates = f.creates;
	f.p[0]->to_dist_sak = true;
	ieee802_1x_kay_elect_key_server(f.p[0], false);
	assert(ieee802_1x_mka_dist_sak_body_present(f.p[0]));
	assert(ieee802_1x_kay_generate_new_sak(f.p[0]) < 0);
	commit_transmit(&f);
	assert(ieee802_1x_kay_generate_new_sak(f.p[0]) < 0);
	assert(f.kay.new_key == candidate && f.creates == creates);
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[1]);
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[0]);
	ieee802_1x_kay_elect_key_server(f.p[0], true);
	assert(ieee802_1x_mka_dist_sak_body_present(f.p[0]));
	observe_old(&f, 0, false);
	ieee802_1x_kay_set_principal_participant(&f.kay, f.p[1]);
	ieee802_1x_kay_delete_mka(&f.kay, &f.p[0]->ckn);
	f.p[0] = NULL;
	assert(sm->CP_state == CP_TRANSMITTING && f.selected_an == 1);
	assert(f.kay.new_key == candidate && f.creates == creates);
	assert(f.kay.lki.kn == 2 && f.kay.oki.kn == 1);
	observe_old(&f, 1, false);
	ieee802_1x_kay_update_sak_use(f.p[1]);
	ieee802_1x_cp_step_run(sm);
	assert(f.kay.lki.kn == 2 && f.kay.oki.kn == 1);
	deinit_fixture(&f);
	puts("PASS: same-candidate retransmission and originating-CA deletion");
}

static void test_incoming_distribution(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct ieee802_1x_kay_peer *peer;
	u8 raw[sizeof(struct ieee802_1x_mka_dist_sak_body) + 24] = { 0 };
	struct ieee802_1x_mka_dist_sak_body *body = (void *) raw;
	u8 sak[16] = { 7 };
	unsigned int creates;

	init_fixture(&f, true);
	sm = f.kay.cp;
	commit_transmit(&f);
	f.p[0]->is_key_server = f.p[0]->can_be_key_server = false;
	peer = first_peer(f.p[0]);
	peer->is_key_server = true;
	f.kay.key_server_sci = peer->sci;
	sm->elected_self = false;
	body->type = MKA_DISTRIBUTED_SAK;
	body->dan = 0;
	body->confid_offset = CONFIDENTIALITY_NONE;
	body->kn = host_to_be32(77);
	set_mka_param_body_len(body, 28);
	assert(!aes_wrap(f.p[0]->kek.key, f.p[0]->kek.len, 2, sak, body->sak));
	creates = f.creates;
	assert(!ieee802_1x_mka_decode_dist_sak_body(f.p[0], raw, sizeof(raw)));
	assert(f.kay.new_key == f.candidate && f.creates == creates);
	assert(!sm->new_sak && f.kay.lki.kn == 2);
	sm->all_transmitting = true;
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_RETIRE && f.kay.oki.kn == 2);
	assert(!ieee802_1x_mka_decode_dist_sak_body(f.p[0], raw, sizeof(raw)));
	assert(f.kay.new_key->key_identifier.kn == 77);
	assert(!os_memcmp(f.kay.new_key->key_identifier.mi, peer->mi, MI_LEN));
	assert(!ieee802_1x_mka_decode_dist_sak_body(f.p[0], raw, sizeof(raw)));
	assert(dl_list_len(&f.kay.sak_list) == 2);
	deinit_fixture(&f);
	puts("PASS: incoming overlap is deferred; a repeated full KI is idempotent");
}

static void test_backend_errors_and_occupied_an(void)
{
	struct fixture f;
	struct ieee802_1x_cp_sm *sm;
	struct data_key *other;
	struct ieee802_1x_mka_ki ki;
	struct transmit_sa *tx;
	unsigned int creates;

	init_fixture(&f, false);
	tx = lookup_txsa_by_an(f.kay.txsc, 0);
	tx->next_pn = 999;
	creates = f.creates;
	assert(!ieee802_1x_kay_create_sas(&f.kay, &f.old->key_identifier));
	assert(f.creates == creates && tx->next_pn == 999);
	other = add_key(&f, 9, 0, 9);
	assert(ieee802_1x_kay_create_sas(&f.kay, &other->key_identifier) < 0);
	assert(tx == lookup_txsa_by_an(f.kay.txsc, 0) && tx->next_pn == 999);
	ki = other->key_identifier;
	assert(!ieee802_1x_kay_delete_sas(&f.kay, &ki));
	assert(f.kay.new_key == f.old);
	deinit_fixture(&f);

	init_fixture(&f, true);
	sm = f.kay.cp;
	f.fail_an = 1;
	f.fail_after_select = true;
	observe_old(&f, 0, false);
	ieee802_1x_kay_update_sak_use(f.p[0]);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMIT && sm->tx_selection_started);
	assert(f.selected_an == 1 && !sm->ltx && !sm->using_transmit_sa);
	assert(!lookup_txsa_by_an(f.kay.txsc, 1)->enable_transmit);
	creates = f.deletes;
	assert(ieee802_1x_cp_abandon_sak(sm) < 0);
	sm->new_sak = true;
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_TRANSMIT && f.deletes == creates);
	sm->new_sak = false;
	ieee802_1x_cp_transmit_when_timeout(sm, NULL);
	assert(!sm->controlled_port_enabled && f.kay.failed);
	deinit_fixture(&f);

	init_fixture(&f, false);
	sm = f.kay.cp;
	f.candidate = add_key(&f, 2, 1, 1);
	f.fail_rx = true;
	ieee802_1x_cp_set_distributedki(sm, &f.candidate->key_identifier);
	ieee802_1x_cp_set_distributedan(sm, 1);
	ieee802_1x_cp_signal_newsak(sm);
	ieee802_1x_cp_step_run(sm);
	assert(sm->CP_state == CP_ABANDON && !f.kay.lrx);
	assert(!sm->using_receive_sas && f.selected_an == 0);
	deinit_fixture(&f);
	puts("PASS: occupied ANs and failed activation never report successful use");
}

static struct wpabuf *packet(struct ieee802_1x_mka_participant *p,
			     bool echo, bool use)
{
	struct ieee802_1x_kay_peer *peer = first_peer(p);
	struct wpabuf *buf = wpabuf_alloc(256);
	struct ieee8023_hdr *eth;
	struct ieee802_1x_hdr *eapol;
	struct ieee802_1x_mka_basic_body *basic;
	struct ieee802_1x_mka_peer_body *live;
	struct ieee802_1x_mka_peer_id *id;
	struct ieee802_1x_mka_hdr *icv;
	u8 *mac;

	assert(buf);
	eth = wpabuf_put(buf, sizeof(*eth));
	os_memset(eth, 0, sizeof(*eth));
	os_memcpy(eth->dest, pae_group_addr, ETH_ALEN);
	os_memcpy(eth->src, peer->sci.addr, ETH_ALEN);
	eth->ethertype = host_to_be16(ETH_P_PAE);
	eapol = wpabuf_put(buf, sizeof(*eapol));
	os_memset(eapol, 0, sizeof(*eapol));
	eapol->version = 3;
	eapol->type = IEEE802_1X_TYPE_EAPOL_MKA;
	basic = wpabuf_put(buf, sizeof(*basic) + p->ckn.len);
	os_memset(basic, 0, sizeof(*basic) + p->ckn.len);
	basic->version = MKA_VERSION_ID;
	basic->priority = 255;
	basic->macsec_desired = true;
	basic->macsec_capability = MACSEC_CAP_INTEG_AND_CONF;
	basic->actor_sci = peer->sci;
	os_memcpy(basic->actor_mi, peer->mi, MI_LEN);
	basic->actor_mn = host_to_be32(peer->mn + 1);
	os_memcpy(basic->algo_agility, mka_algo_agility, 4);
	os_memcpy(basic->ckn, p->ckn.name, p->ckn.len);
	set_mka_param_body_len(basic, sizeof(*basic) - MKA_HDR_LEN + p->ckn.len);
	live = wpabuf_put(buf, sizeof(*live));
	os_memset(live, 0, sizeof(*live));
	live->type = MKA_LIVE_PEER_LIST;
	set_mka_param_body_len(live, sizeof(*id));
	id = wpabuf_put(buf, sizeof(*id));
	os_memcpy(id->mi, p->mi, MI_LEN);
	id->mn = host_to_be32(echo ? p->mn - 1 : p->mn - 10);
	if (use) {
		struct ieee802_1x_mka_sak_use_body *sak =
			wpabuf_put(buf, sizeof(*sak));

		os_memset(sak, 0, sizeof(*sak));
		sak->type = MKA_SAK_USE;
		set_mka_param_body_len(sak, sizeof(*sak) - MKA_HDR_LEN);
		sak->lrx = true;
		sak->lkn = host_to_be32(99);
		sak->orx = sak->otx = true;
		sak->oan = p->kay->lan;
		os_memcpy(sak->osrv_mi, p->kay->lki.mi, MI_LEN);
		sak->okn = host_to_be32(p->kay->lki.kn);
		sak->llpn = sak->olpn = host_to_be32(1);
	}
	icv = wpabuf_put(buf, MKA_HDR_LEN);
	os_memset(icv, 0, MKA_HDR_LEN);
	icv->type = MKA_ICV_INDICATOR;
	set_mka_param_body_len(icv, DEFAULT_ICV_LEN);
	mac = wpabuf_put(buf, DEFAULT_ICV_LEN);
	eapol->length = host_to_be16(wpabuf_len(buf) - sizeof(*eth) - sizeof(*eapol));
	assert(!ieee802_1x_icv_aes_cmac(p->ick.key, p->ick.len,
				       wpabuf_head(buf),
				       wpabuf_len(buf) - DEFAULT_ICV_LEN, mac));
	return buf;
}

static void test_liveness_and_key_matching(void)
{
	struct fixture f;
	struct wpabuf *buf;
	struct ieee802_1x_kay_peer *peer;
	struct ieee802_1x_cp_sm *sm;
	unsigned int i;

	init_fixture(&f, true);
	sm = f.kay.cp;
	peer = first_peer(f.p[1]);
	for (i = 0; i < 30; i++) {
		peer->expire = time(NULL) - 1;
		buf = packet(f.p[1], true, false);
		assert(!ieee802_1x_kay_decode_mkpdu(&f.kay,
						  wpabuf_head(buf), wpabuf_len(buf)));
		assert(peer->expire > time(NULL));
		assert(!peer->missing_sak_use_count &&
		       !peer_sc(f.p[1])->sak_use_expire);
		assert(sm->CP_state == CP_RECEIVING);
		wpabuf_free(buf);
	}
	peer->expire = time(NULL) - 1;
	buf = packet(f.p[1], false, false);
	assert(!ieee802_1x_kay_decode_mkpdu(&f.kay, wpabuf_head(buf), wpabuf_len(buf)));
	assert(peer->expire < time(NULL));
	wpabuf_free(buf);
	buf = packet(f.p[1], true, false);
	((u8 *) wpabuf_mhead(buf))[wpabuf_len(buf) - 1] ^= 1;
	assert(ieee802_1x_kay_decode_mkpdu(&f.kay, wpabuf_head(buf), wpabuf_len(buf)) < 0);
	assert(peer->expire < time(NULL));
	wpabuf_free(buf);
	buf = packet(f.p[0], true, true);
	assert(!ieee802_1x_kay_decode_mkpdu(&f.kay, wpabuf_head(buf), wpabuf_len(buf)));
	assert(sm->all_receiving && sm->all_transmitting);
	{
		time_t expiry = peer_sc(f.p[0])->sak_use_expire;
		struct wpabuf *standby = packet(f.p[1], true, false);

		assert(!ieee802_1x_kay_decode_mkpdu(&f.kay,
						  wpabuf_head(standby),
						  wpabuf_len(standby)));
		assert(peer_sc(f.p[1])->sak_use_expire == expiry);
		assert(sm->all_receiving && sm->all_transmitting);
		wpabuf_free(standby);
	}
	first_peer(f.p[0])->expire = time(NULL) - 1;
	assert(ieee802_1x_kay_decode_mkpdu(&f.kay, wpabuf_head(buf), wpabuf_len(buf)) < 0);
	assert(first_peer(f.p[0])->expire < time(NULL));
	wpabuf_free(buf);
	peer = first_peer(f.p[0]);
	f.p[0]->new_sak = false;
	peer_sc(f.p[0])->sak_use_expire = time(NULL) - 1;
	for (i = 0; i < MAX_MISSING_SAK_USE + 5; i++) {
		peer->expire = time(NULL) - 1;
		buf = packet(f.p[0], true, false);
		assert(!ieee802_1x_kay_decode_mkpdu(&f.kay,
						  wpabuf_head(buf), wpabuf_len(buf)));
		assert(peer->expire > time(NULL));
		wpabuf_free(buf);
	}
	assert(f.p[0]->new_sak && peer_sc(f.p[0])->sak_use_expire < time(NULL));
	deinit_fixture(&f);
	puts("PASS: signed liveness, progress repair, echo/replay/ICV and full-KI match");
}

int main(void)
{
	wpa_debug_level = MSG_ERROR;
	test_unready_transmit_deadline();
	test_fresh_readiness_at_selection();
	test_missed_distribution_failover();
	test_tx_point_of_no_return();
	test_shared_recovery();
	test_pre_tx_and_bounds();
	test_lost_distribution_and_teardown();
	test_incoming_distribution();
	test_backend_errors_and_occupied_an();
	test_liveness_and_key_matching();
	return 0;
}
