/*
 * IEEE 802.1X-2010 Controlled Port of PAE state machine - CP state machine
 * Copyright (c) 2013-2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/defs.h"
#include "common/ieee802_1x_defs.h"
#include "utils/state_machine.h"
#include "ieee802_1x_kay.h"
#include "ieee802_1x_secy_ops.h"
#include "pae/ieee802_1x_cp.h"

#define STATE_MACHINE_DATA struct ieee802_1x_cp_sm
#define STATE_MACHINE_DEBUG_PREFIX "CP"

/* The variable defined in clause 12 in IEEE Std 802.1X-2010 */
enum connect_type { PENDING, UNAUTHENTICATED, AUTHENTICATED, SECURE };

struct ieee802_1x_cp_sm {
	enum cp_states {
		CP_BEGIN, CP_INIT, CP_CHANGE, CP_ALLOWED, CP_AUTHENTICATED,
		CP_SECURED, CP_RECEIVE, CP_RECEIVING, CP_READY, CP_TRANSMIT,
		CP_TRANSMITTING, CP_ABANDON, CP_RETIRE
	} CP_state;
	bool changed;

	/* CP -> Client */
	bool port_valid;

	/* Logon -> CP */
	enum connect_type connect;

	/* KaY -> CP */
	bool chgd_server; /* clear by CP */
	bool elected_self;
	enum confidentiality_offset cipher_offset;
	u64 cipher_suite;
	bool new_sak; /* clear by CP */
	struct ieee802_1x_mka_ki distributed_ki;
	u8 distributed_an;
	bool using_receive_sas;
	bool all_receiving;
	bool all_transmitting;
	bool step_pending; /* a deferred step_cb is already queued */
	bool server_transmitting;
	bool using_transmit_sa;

	/* CP -> KaY */
	struct ieee802_1x_mka_ki *lki;
	u8 lan;
	bool ltx;
	bool lrx;
	struct ieee802_1x_mka_ki *oki;
	u8 oan;
	bool otx;
	bool orx;

	/* CP -> SecY */
	bool protect_frames;
	enum validate_frames validate_frames;

	bool replay_protect;
	u32 replay_window;

	u64 current_cipher_suite;
	enum confidentiality_offset confidentiality_offset;
	bool controlled_port_enabled;

	/* SecY -> CP */
	bool port_enabled; /* SecY->CP */

	/* private */
	u32 transmit_when;
	u32 transmit_delay;
	u32 retire_when;
	u32 retire_delay;
	bool tx_selection_started;

	/* not defined IEEE Std 802.1X-2010 */
	struct ieee802_1x_kay *kay;
};

static void ieee802_1x_cp_retire_when_timeout(void *eloop_ctx,
					      void *timeout_ctx);
static void ieee802_1x_cp_transmit_when_timeout(void *eloop_ctx,
						void *timeout_ctx);

static void ieee802_1x_cp_cancel_rollover(struct ieee802_1x_cp_sm *sm)
{
	eloop_cancel_timeout(ieee802_1x_cp_transmit_when_timeout, sm, NULL);
	eloop_cancel_timeout(ieee802_1x_cp_retire_when_timeout, sm, NULL);
}


static void ieee802_1x_cp_clear_latest(struct ieee802_1x_cp_sm *sm)
{
	if (sm->lki)
		ieee802_1x_kay_delete_sas(sm->kay, sm->lki);
	os_free(sm->lki);
	sm->lki = NULL;
	sm->ltx = sm->lrx = false;
	sm->tx_selection_started = false;
	sm->lan = 0;
	ieee802_1x_kay_set_latest_sa_attr(sm->kay, NULL, 0, false, false);
}


static int ieee802_1x_cp_select_latest(struct ieee802_1x_cp_sm *sm)
{
	if (!ieee802_1x_kay_can_transmit_sak(sm->kay, sm->lki))
		return -1;
	/* A driver error may follow a queued hardware selection. */
	sm->tx_selection_started = true;
	if (ieee802_1x_kay_enable_tx_sas(sm->kay, sm->lki))
		return -1;
	sm->ltx = true;
	ieee802_1x_kay_set_latest_sa_attr(sm->kay, sm->lki, sm->lan,
					  sm->ltx, sm->lrx);
	return 0;
}


static int changed_cipher(struct ieee802_1x_cp_sm *sm)
{
	return sm->confidentiality_offset != sm->cipher_offset ||
		sm->current_cipher_suite != sm->cipher_suite;
}


static int changed_connect(struct ieee802_1x_cp_sm *sm)
{
	return sm->connect != SECURE || sm->chgd_server || changed_cipher(sm);
}


SM_STATE(CP, INIT)
{
	SM_ENTRY(CP, INIT);
	ieee802_1x_cp_cancel_rollover(sm);

	sm->controlled_port_enabled = false;
	secy_cp_control_enable_port(sm->kay, sm->controlled_port_enabled);

	sm->port_valid = false;

	os_free(sm->lki);
	sm->lki = NULL;
	sm->ltx = false;
	sm->lrx = false;
	sm->tx_selection_started = false;

	os_free(sm->oki);
	sm->oki = NULL;
	sm->otx = false;
	sm->orx = false;

	sm->port_enabled = true;
	sm->chgd_server = false;
}


SM_STATE(CP, CHANGE)
{
	SM_ENTRY(CP, CHANGE);
	ieee802_1x_cp_cancel_rollover(sm);

	sm->port_valid = false;
	sm->controlled_port_enabled = false;
	secy_cp_control_enable_port(sm->kay, sm->controlled_port_enabled);

	if (sm->oki)
		ieee802_1x_kay_delete_sas(sm->kay, sm->oki);
	/* The standard doesn't say it but we should clear out the latest
	 * and old key values. Why would we keep advertising them if
	 * they've been deleted and the key server has been changed?
	 */
	os_free(sm->oki);
	sm->oki = NULL;
	sm->otx = false;
	sm->orx = false;
	sm->oan = 0;
	ieee802_1x_kay_set_old_sa_attr(sm->kay, sm->oki, sm->oan,
				       sm->otx, sm->orx);
	ieee802_1x_cp_clear_latest(sm);
	sm->using_receive_sas = sm->using_transmit_sa = false;
}


SM_STATE(CP, ALLOWED)
{
	SM_ENTRY(CP, ALLOWED);

	sm->protect_frames = false;
	sm->replay_protect = false;
	sm->validate_frames = Checked;

	sm->port_valid = false;
	sm->controlled_port_enabled = true;

	secy_cp_control_enable_port(sm->kay, sm->controlled_port_enabled);
	secy_cp_control_protect_frames(sm->kay, sm->protect_frames);
	secy_cp_control_encrypt(sm->kay, sm->kay->macsec_encrypt);
	secy_cp_control_validate_frames(sm->kay, sm->validate_frames);
	secy_cp_control_replay(sm->kay, sm->replay_protect, sm->replay_window);
}


SM_STATE(CP, AUTHENTICATED)
{
	SM_ENTRY(CP, AUTHENTICATED);

	sm->protect_frames = false;
	sm->replay_protect = false;
	sm->validate_frames = Checked;

	sm->port_valid = false;
	sm->controlled_port_enabled = true;

	secy_cp_control_enable_port(sm->kay, sm->controlled_port_enabled);
	secy_cp_control_protect_frames(sm->kay, sm->protect_frames);
	secy_cp_control_encrypt(sm->kay, sm->kay->macsec_encrypt);
	secy_cp_control_validate_frames(sm->kay, sm->validate_frames);
	secy_cp_control_replay(sm->kay, sm->replay_protect, sm->replay_window);
}


SM_STATE(CP, SECURED)
{
	SM_ENTRY(CP, SECURED);

	sm->chgd_server = false;

	sm->protect_frames = sm->kay->macsec_protect;
	sm->replay_protect = sm->kay->macsec_replay_protect;
	sm->validate_frames = sm->kay->macsec_validate;

	sm->current_cipher_suite = sm->cipher_suite;
	secy_cp_control_current_cipher_suite(sm->kay, sm->current_cipher_suite);

	sm->confidentiality_offset = sm->cipher_offset;
	secy_cp_control_confidentiality_offset(sm->kay,
					       sm->confidentiality_offset);

	sm->port_valid = true;

	secy_cp_control_protect_frames(sm->kay, sm->protect_frames);
	secy_cp_control_encrypt(sm->kay, sm->kay->macsec_encrypt);
	secy_cp_control_validate_frames(sm->kay, sm->validate_frames);
	secy_cp_control_replay(sm->kay, sm->replay_protect, sm->replay_window);
}


SM_STATE(CP, RECEIVE)
{
	SM_ENTRY(CP, RECEIVE);

	sm->lki = os_malloc(sizeof(*sm->lki));
	if (!sm->lki) {
		wpa_printf(MSG_ERROR, "CP-%s: Out of memory", __func__);
		return;
	}
	os_memcpy(sm->lki, &sm->distributed_ki, sizeof(*sm->lki));
	sm->lan = sm->distributed_an;
	sm->ltx = false;
	sm->lrx = false;
	sm->tx_selection_started = false;
	ieee802_1x_kay_set_latest_sa_attr(sm->kay, sm->lki, sm->lan,
					  sm->ltx, sm->lrx);
	sm->new_sak = false;
	sm->all_receiving = false;
	sm->all_transmitting = false;
	sm->using_receive_sas = false;
	sm->using_transmit_sa = false;
	if (ieee802_1x_kay_create_sas(sm->kay, sm->lki) ||
	    ieee802_1x_kay_enable_rx_sas(sm->kay, sm->lki)) {
		wpa_printf(MSG_ERROR, "CP: Could not install receive SAs");
		ieee802_1x_cp_abandon_sak(sm);
	}
}


SM_STATE(CP, RECEIVING)
{
	SM_ENTRY(CP, RECEIVING);

	sm->lrx = true;
	ieee802_1x_kay_set_latest_sa_attr(sm->kay, sm->lki, sm->lan,
					  sm->ltx, sm->lrx);
	sm->transmit_when = sm->transmit_delay;
	eloop_cancel_timeout(ieee802_1x_cp_transmit_when_timeout, sm, NULL);
	eloop_register_timeout(sm->transmit_when / 1000, 0,
			       ieee802_1x_cp_transmit_when_timeout, sm, NULL);
	/* the electedSelf have been set before CP entering to RECEIVING
	 * but the CP will transmit from RECEIVING to READY under
	 * the !electedSelf when KaY is not key server */
	ieee802_1x_cp_sm_step(sm);
	sm->using_receive_sas = false;
	sm->server_transmitting = false;
}


SM_STATE(CP, READY)
{
	SM_ENTRY(CP, READY);

	ieee802_1x_kay_enable_new_info(sm->kay);
}


SM_STATE(CP, TRANSMIT)
{
	SM_ENTRY(CP, TRANSMIT);

	sm->controlled_port_enabled = true;
	secy_cp_control_enable_port(sm->kay, sm->controlled_port_enabled);
	sm->transmit_when = MKA_SAK_RETIRE_FAILSAFE_TIME;
	eloop_cancel_timeout(ieee802_1x_cp_transmit_when_timeout, sm, NULL);
	if (eloop_register_timeout(sm->transmit_when / 1000, 0,
				   ieee802_1x_cp_transmit_when_timeout, sm, NULL)) {
		wpa_printf(MSG_ERROR, "CP: Could not arm TX selection timeout");
		sm->transmit_when = 0;
	}
	if (ieee802_1x_cp_select_latest(sm) && !sm->tx_selection_started)
		SM_ENTER(CP, RECEIVING);
	sm->all_receiving = false;
	sm->all_transmitting = false;
	sm->server_transmitting = false;
}


SM_STATE(CP, TRANSMITTING)
{
	SM_ENTRY(CP, TRANSMITTING);
	eloop_cancel_timeout(ieee802_1x_cp_transmit_when_timeout, sm, NULL);
	/* Peer TX reports do not drain old-key frames already in flight. */
	sm->retire_when = sm->orx ? sm->retire_delay : 0;
	sm->otx = false;
	ieee802_1x_kay_set_old_sa_attr(sm->kay, sm->oki, sm->oan,
				       sm->otx, sm->orx);
	ieee802_1x_kay_enable_new_info(sm->kay);
	eloop_cancel_timeout(ieee802_1x_cp_retire_when_timeout, sm, NULL);
	if (sm->retire_when &&
	    eloop_register_timeout(sm->retire_when / 1000, 0,
				   ieee802_1x_cp_retire_when_timeout, sm, NULL)) {
		wpa_printf(MSG_ERROR, "CP: Could not arm old RX drain timeout");
		SM_ENTER(CP, CHANGE);
		ieee802_1x_kay_rekey_failed(sm->kay);
	}
	sm->using_transmit_sa = false;
}


SM_STATE(CP, ABANDON)
{
	SM_ENTRY(CP, ABANDON);
	ieee802_1x_cp_cancel_rollover(sm);
	ieee802_1x_kay_abandon_sak(sm->kay, sm->lki);
	sm->using_transmit_sa = false;
	sm->all_receiving = sm->all_transmitting = false;
	sm->server_transmitting = false;
	sm->ltx = false;
	ieee802_1x_kay_set_latest_sa_attr(sm->kay, sm->lki, sm->lan,
					  sm->ltx, sm->lrx);
	/* Keep candidate RX through the drain, and require fresh peer evidence
	 * before deletion. The other timer bounds an unresolved recovery. */
	sm->retire_when = sm->retire_delay;
	sm->transmit_when = MKA_SAK_RETIRE_FAILSAFE_TIME;
	if (eloop_register_timeout(sm->retire_when / 1000, 0,
				   ieee802_1x_cp_retire_when_timeout, sm, NULL) ||
	    eloop_register_timeout(sm->transmit_when / 1000, 0,
				   ieee802_1x_cp_transmit_when_timeout, sm, NULL)) {
		wpa_printf(MSG_ERROR, "CP: Could not arm SAK recovery timers");
		sm->transmit_when = 0;
	}
	ieee802_1x_kay_enable_new_info(sm->kay);
}


SM_STATE(CP, RETIRE)
{
	SM_ENTRY(CP, RETIRE);
	ieee802_1x_cp_cancel_rollover(sm);
	if (sm->oki) {
		ieee802_1x_kay_delete_sas(sm->kay, sm->oki);
		os_free(sm->oki);
		sm->oki = NULL;
	}
	sm->oki = sm->lki;
	sm->otx = sm->ltx;
	sm->orx = sm->lrx;
	sm->oan = sm->lan;
	ieee802_1x_kay_set_old_sa_attr(sm->kay, sm->oki, sm->oan,
				       sm->otx, sm->orx);
	sm->lki = NULL;
	sm->ltx = false;
	sm->lrx = false;
	sm->tx_selection_started = false;
	sm->lan = 0;
	ieee802_1x_kay_set_latest_sa_attr(sm->kay, sm->lki, sm->lan,
					  sm->ltx, sm->lrx);
}


/**
 * CP state machine handler entry
 */
SM_STEP(CP)
{
	if (!sm->port_enabled)
		SM_ENTER(CP, INIT);

	switch (sm->CP_state) {
	case CP_BEGIN:
		SM_ENTER(CP, INIT);
		break;

	case CP_INIT:
		SM_ENTER(CP, CHANGE);
		break;

	case CP_CHANGE:
		if (sm->connect == UNAUTHENTICATED)
			SM_ENTER(CP, ALLOWED);
		else if (sm->connect == AUTHENTICATED)
			SM_ENTER(CP, AUTHENTICATED);
		else if (sm->connect == SECURE)
			SM_ENTER(CP, SECURED);
		break;

	case CP_ALLOWED:
		if (sm->connect != UNAUTHENTICATED)
			SM_ENTER(CP, CHANGE);
		break;

	case CP_AUTHENTICATED:
		if (sm->connect != AUTHENTICATED)
			SM_ENTER(CP, CHANGE);
		break;

	case CP_SECURED:
		if (changed_connect(sm))
			SM_ENTER(CP, CHANGE);
		else if (sm->new_sak)
			SM_ENTER(CP, RECEIVE);
		break;

	case CP_RECEIVE:
		if (sm->using_receive_sas)
			SM_ENTER(CP, RECEIVING);
		break;

	case CP_RECEIVING:
		if (changed_connect(sm))
			SM_ENTER(CP, CHANGE);
		else if (sm->new_sak)
			ieee802_1x_cp_abandon_sak(sm);
		else if (!sm->elected_self)
			SM_ENTER(CP, READY);
		else if (ieee802_1x_kay_can_transmit_sak(sm->kay, sm->lki))
			SM_ENTER(CP, TRANSMIT);
		else if (!sm->transmit_when &&
			 ieee802_1x_kay_can_abandon_sak(sm->kay))
			ieee802_1x_cp_abandon_sak(sm);
		break;

	case CP_TRANSMIT:
		if (changed_connect(sm))
			SM_ENTER(CP, CHANGE);
		else if (sm->using_transmit_sa)
			SM_ENTER(CP, TRANSMITTING);
		else if (!sm->transmit_when) {
			wpa_printf(MSG_ERROR, "CP: TX selection did not complete");
			SM_ENTER(CP, CHANGE);
			ieee802_1x_kay_rekey_failed(sm->kay);
		}
		break;

	case CP_TRANSMITTING:
		if (!sm->retire_when || changed_connect(sm))
			SM_ENTER(CP, RETIRE);
		break;

	case CP_RETIRE:
		if (changed_connect(sm))
			SM_ENTER(CP, CHANGE);
		else if (sm->new_sak)
			SM_ENTER(CP, RECEIVE);
		break;

	case CP_READY:
		/* A follower can become key server without replacing its SAK. */
		if (changed_connect(sm))
			SM_ENTER(CP, CHANGE);
		else if (sm->new_sak)
			ieee802_1x_cp_abandon_sak(sm);
		else if ((sm->elected_self || sm->server_transmitting) &&
			 ieee802_1x_kay_can_transmit_sak(sm->kay, sm->lki))
			SM_ENTER(CP, TRANSMIT);
		else if (sm->elected_self && !sm->transmit_when &&
			 ieee802_1x_kay_can_abandon_sak(sm->kay))
			ieee802_1x_cp_abandon_sak(sm);
		break;
	case CP_ABANDON:
		if (changed_connect(sm))
			SM_ENTER(CP, CHANGE);
		else if (sm->lki) {
			/* A late commitment is also convergence: keep the
			 * candidate if every peer has moved to it. */
			if (sm->all_receiving && sm->all_transmitting &&
			    ieee802_1x_kay_can_transmit_sak(sm->kay, sm->lki)) {
				SM_ENTER(CP, TRANSMIT);
			} else if (!sm->retire_when &&
			    ieee802_1x_kay_can_abandon_sak(sm->kay)) {
				ieee802_1x_cp_cancel_rollover(sm);
				ieee802_1x_cp_clear_latest(sm);
				ieee802_1x_kay_enable_new_info(sm->kay);
			} else if (!sm->transmit_when) {
				wpa_printf(MSG_ERROR,
					   "CP: SAK recovery did not converge");
				SM_ENTER(CP, CHANGE);
				ieee802_1x_kay_rekey_failed(sm->kay);
			}
		} else if (sm->new_sak)
			SM_ENTER(CP, RECEIVE);
		break;
	default:
		wpa_printf(MSG_ERROR, "CP: the state machine is not defined");
		break;
	}
}


/**
 * ieee802_1x_cp_sm_init -
 */
struct ieee802_1x_cp_sm * ieee802_1x_cp_sm_init(struct ieee802_1x_kay *kay)
{
	struct ieee802_1x_cp_sm *sm;

	sm = os_zalloc(sizeof(*sm));
	if (sm == NULL) {
		wpa_printf(MSG_ERROR, "CP-%s: out of memory", __func__);
		return NULL;
	}

	sm->kay = kay;

	sm->port_valid = false;

	sm->chgd_server = false;

	sm->protect_frames = kay->macsec_protect;
	sm->validate_frames = kay->macsec_validate;
	sm->replay_protect = kay->macsec_replay_protect;
	sm->replay_window = kay->macsec_replay_window;

	sm->controlled_port_enabled = false;

	sm->lki = NULL;
	sm->lrx = false;
	sm->ltx = false;
	sm->oki = NULL;
	sm->orx = false;
	sm->otx = false;

	sm->current_cipher_suite = kay->macsec_cs_id;
	sm->cipher_suite = kay->macsec_cs_id;
	sm->cipher_offset = kay->macsec_confidentiality;
	sm->confidentiality_offset = sm->cipher_offset;
	sm->transmit_delay = MKA_LIFE_TIME;
	sm->retire_delay = MKA_SAK_RETIRE_TIME;
	sm->CP_state = CP_BEGIN;
	sm->changed = false;

	wpa_printf(MSG_DEBUG, "CP: state machine created");

	secy_cp_control_protect_frames(sm->kay, sm->protect_frames);
	secy_cp_control_encrypt(sm->kay, sm->kay->macsec_encrypt);
	secy_cp_control_validate_frames(sm->kay, sm->validate_frames);
	secy_cp_control_replay(sm->kay, sm->replay_protect, sm->replay_window);
	secy_cp_control_enable_port(sm->kay, sm->controlled_port_enabled);
	secy_cp_control_confidentiality_offset(sm->kay,
					       sm->confidentiality_offset);

	SM_STEP_RUN(CP);

	return sm;
}


static void ieee802_1x_cp_step_run(struct ieee802_1x_cp_sm *sm)
{
	enum cp_states prev_state;
	int i;

	for (i = 0; i < 100; i++) {
		prev_state = sm->CP_state;
		SM_STEP_RUN(CP);
		if (prev_state == sm->CP_state)
			break;
	}
}


static void ieee802_1x_cp_step_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct ieee802_1x_cp_sm *sm = eloop_ctx;
	sm->step_pending = false;
	ieee802_1x_cp_step_run(sm);
}


/**
 * ieee802_1x_cp_sm_deinit -
 */
void ieee802_1x_cp_sm_deinit(struct ieee802_1x_cp_sm *sm)
{
	wpa_printf(MSG_DEBUG, "CP: state machine removed");
	if (!sm)
		return;

	ieee802_1x_cp_cancel_rollover(sm);
	eloop_cancel_timeout(ieee802_1x_cp_step_cb, sm, NULL);
	os_free(sm->lki);
	os_free(sm->oki);
	os_free(sm);
}


/**
 * ieee802_1x_cp_connect_pending
 */
void ieee802_1x_cp_connect_pending(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;

	sm->connect = PENDING;
}


/**
 * ieee802_1x_cp_connect_unauthenticated
 */
void ieee802_1x_cp_connect_unauthenticated(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = (struct ieee802_1x_cp_sm *)cp_ctx;

	sm->connect = UNAUTHENTICATED;
}


/**
 * ieee802_1x_cp_connect_authenticated
 */
void ieee802_1x_cp_connect_authenticated(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;

	sm->connect = AUTHENTICATED;
}


/**
 * ieee802_1x_cp_connect_secure
 */
void ieee802_1x_cp_connect_secure(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;

	sm->connect = SECURE;
}


/**
 * ieee802_1x_cp_set_chgdserver -
 */
void ieee802_1x_cp_signal_chgdserver(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;

	sm->chgd_server = true;
}


/**
 * ieee802_1x_cp_set_electedself -
 */
void ieee802_1x_cp_set_electedself(void *cp_ctx, bool status)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->elected_self = status;
}


/**
 * ieee802_1x_cp_set_ciphersuite -
 */
void ieee802_1x_cp_set_ciphersuite(void *cp_ctx, u64 cs)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->cipher_suite = cs;
}


/**
 * ieee802_1x_cp_set_offset -
 */
void ieee802_1x_cp_set_offset(void *cp_ctx, enum confidentiality_offset offset)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->cipher_offset = offset;
}


/**
 * ieee802_1x_cp_signal_newsak -
 */
void ieee802_1x_cp_signal_newsak(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->new_sak = true;
}


/**
 * ieee802_1x_cp_set_distributedki -
 */
void ieee802_1x_cp_set_distributedki(void *cp_ctx,
				     const struct ieee802_1x_mka_ki *dki)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	os_memcpy(&sm->distributed_ki, dki, sizeof(struct ieee802_1x_mka_ki));
}


/**
 * ieee802_1x_cp_set_distributedan -
 */
void ieee802_1x_cp_set_distributedan(void *cp_ctx, u8 an)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->distributed_an = an;
}


/**
 * ieee802_1x_cp_set_usingreceivesas -
 */
void ieee802_1x_cp_set_usingreceivesas(void *cp_ctx, bool status)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->using_receive_sas = status;
}


/**
 * ieee802_1x_cp_set_allreceiving -
 */
void ieee802_1x_cp_set_allreceiving(void *cp_ctx, bool status)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->all_receiving = status;
}


/**
 * ieee802_1x_cp_set_servertransmitting -
 */
void ieee802_1x_cp_set_servertransmitting(void *cp_ctx, bool status)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->server_transmitting = status;
}


/**
 * ieee802_1x_cp_set_usingtransmitsas -
 */
void ieee802_1x_cp_set_usingtransmitas(void *cp_ctx, bool status)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->using_transmit_sa = status;
}


int ieee802_1x_cp_abandon_sak(void *cp_ctx)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;

	if (sm->CP_state == CP_ABANDON)
		return 0;
	if (!sm->lki)
		return -1;
	if (sm->ltx || sm->tx_selection_started) {
		wpa_printf(MSG_DEBUG, "CP: Cannot abandon a started TX selection");
		return -1;
	}
	SM_ENTER(CP, ABANDON);
	ieee802_1x_cp_sm_step(sm);
	return 0;
}


/**
 * ieee802_1x_cp_set_all_transmitting -
 */
void ieee802_1x_cp_set_all_transmitting(void *cp_ctx, bool status)
{
	struct ieee802_1x_cp_sm *sm = cp_ctx;
	sm->all_transmitting = status;
}


/**
 * ieee802_1x_cp_sm_step - Advance EAPOL state machines
 * @sm: EAPOL state machine
 *
 * This function is called to advance CP state machines after any change
 * that could affect their state.
 */
void ieee802_1x_cp_sm_step(void *cp_ctx)
{
	/*
	 * Run ieee802_1x_cp_step_run from a registered timeout
	 * to make sure that other possible timeouts/events are processed
	 * and to avoid long function call chains.
	 *
	 * Coalesce onto an already-queued step instead of cancelling and
	 * re-registering it: step_run() loops until CP_state is stable, so one
	 * pending callback covers every change accumulated until it runs.
	 * Re-arming on each call let a burst of sm_step() invocations
	 * perpetually push the 0 s timeout back, starving an already-latched
	 * all_receiving until the ~6 s transmit_when failsafe.
	 */
	struct ieee802_1x_cp_sm *sm = cp_ctx;

	if (sm->step_pending)
		return;
	/* Latch only after the timeout is queued, so a failed registration
	 * lets the next sm_step() retry rather than wedging the SM. */
	if (eloop_register_timeout(0, 0, ieee802_1x_cp_step_cb, sm, NULL) == 0)
		sm->step_pending = true;
}


static void ieee802_1x_cp_retire_when_timeout(void *eloop_ctx,
					      void *timeout_ctx)
{
	struct ieee802_1x_cp_sm *sm = eloop_ctx;
	sm->retire_when = 0;
	ieee802_1x_cp_step_run(sm);
}


static void
ieee802_1x_cp_transmit_when_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct ieee802_1x_cp_sm *sm = eloop_ctx;
	sm->transmit_when = 0;
	ieee802_1x_cp_step_run(sm);
}
