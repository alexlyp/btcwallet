package vsp

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"decred.org/dcrwallet/errors"
	"decred.org/dcrwallet/internal/uniformprng"
	"decred.org/dcrwallet/wallet"
	"decred.org/dcrwallet/wallet/txrules"
	"decred.org/dcrwallet/wallet/txsizes"
	"github.com/decred/dcrd/blockchain/stake/v3"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
)

var prng lockedRand

type lockedRand struct {
	mu   sync.Mutex
	rand *uniformprng.Source
}

func (r *lockedRand) int63n(n int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rand.Int63n(n)
}

// duration returns a random time.Duration in [0,d) with uniform distribution.
func (r *lockedRand) duration(d time.Duration) time.Duration {
	return time.Duration(r.int63n(int64(d)))
}

func (r *lockedRand) coinflip() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rand.Uint32n(2) == 0
}

func init() {
	source, err := uniformprng.RandSource(cryptorand.Reader)
	if err != nil {
		panic(err)
	}
	prng = lockedRand{
		rand: source,
	}
}

var errStopped = errors.New("fee processing stopped")

// A random amount of delay (between zero and these jitter constants) is added
// before performing some background action with the VSP.  The delay is reduced
// when a ticket is currently live, as it may be called to vote any time.
const (
	immatureJitter = time.Hour
	liveJitter     = 5 * time.Minute
)

type feePayment struct {
	client *Client
	ctx    context.Context

	// Set at feepayment creation and never changes
	ticketHash     chainhash.Hash
	commitmentAddr dcrutil.Address
	votingAddr     dcrutil.Address
	policy         Policy

	// Requires locking for all access outside of Client.feePayment
	mu            sync.Mutex
	ticketLive    int32
	ticketExpires int32
	feeHash       chainhash.Hash
	fee           dcrutil.Amount
	feeAddr       dcrutil.Address
	feeTx         *wire.MsgTx
	votingKey     string
	state         state
	err           error

	timerMu sync.Mutex
	timer   *time.Timer
}

type state uint32

const (
	_ state = iota
	unprocessed
	feePublished
	_ // ...
	ticketSpent
)

func parseTicket(ticket *wire.MsgTx, params *chaincfg.Params) (
	votingAddr, commitmentAddr dcrutil.Address, err error) {
	fail := func(err error) (_, _ dcrutil.Address, _ error) {
		return nil, nil, err
	}
	if !stake.IsSStx(ticket) {
		return fail(fmt.Errorf("%v is not a ticket", ticket))
	}
	const scriptVersion = 0
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(scriptVersion,
		ticket.TxOut[0].PkScript, params, true) // Yes treasury
	if err != nil {
		return fail(fmt.Errorf("cannot parse voting addr: %w", err))
	}
	if len(addrs) != 1 {
		return fail(fmt.Errorf("cannot parse voting addr"))
	}
	votingAddr = addrs[0]
	commitmentAddr, err = stake.AddrFromSStxPkScrCommitment(ticket.TxOut[1].PkScript, params)
	if err != nil {
		return fail(fmt.Errorf("cannot parse commitment address: %w", err))
	}
	return
}

func (fp *feePayment) ticketSpent() bool {
	ctx := fp.ctx
	ticketOut := wire.OutPoint{Hash: fp.ticketHash, Index: 0, Tree: 1}
	_, _, err := fp.client.Wallet.Spender(ctx, &ticketOut)
	return err == nil
}

func (fp *feePayment) ticketExpired() bool {
	ctx := fp.ctx
	w := fp.client.Wallet
	_, tipHeight := w.MainChainTip(ctx)

	fp.mu.Lock()
	expires := fp.ticketExpires
	fp.mu.Unlock()

	return expires > 0 && tipHeight >= expires
}

func (fp *feePayment) removedExpiredOrSpent() bool {
	var reason string
	switch {
	case fp.ticketExpired():
		reason = "expired"
	case fp.ticketSpent():
		reason = "spent"
	}
	if reason != "" {
		log.Infof("ticket %v is %s; removing from VSP client", &fp.ticketHash, reason)
		fp.client.mu.Lock()
		delete(fp.client.jobs, fp.ticketHash)
		fp.client.mu.Unlock()
		// nothing scheduled
		return true
	}
	return false
}

// feePayment returns an existing managed fee payment, or creates and begins
// processing a fee payment for a ticket.
func (c *Client) feePayment(ticketHash *chainhash.Hash, policy Policy) (fp *feePayment) {
	c.mu.Lock()
	fp = c.jobs[*ticketHash]
	c.mu.Unlock()
	if fp != nil {
		return fp
	}

	ctx := context.Background()
	w := c.Wallet
	params := w.ChainParams()

	fp = &feePayment{
		client:     c,
		ctx:        ctx,
		ticketHash: *ticketHash,
		policy:     policy,
	}

	// No VSP interaction is required for spent tickets.
	if fp.ticketSpent() {
		fp.state = ticketSpent
		return fp
	}

	ticket, err := c.tx(ctx, ticketHash)
	if err != nil {
		log.Warnf("no ticket found for %v", ticketHash)
		return nil
	}

	_, ticketHeight, err := w.TxBlock(ctx, ticketHash)
	if err != nil {
		// This is not expected to ever error, as the ticket was fetched
		// from the wallet in the above call.
		log.Errorf("failed to query block which mines ticket: %v", err)
		return nil
	}
	if ticketHeight >= 2 {
		// Note the off-by-one; this is correct.  Tickets become live
		// one block after the params would indicate.
		fp.ticketLive = ticketHeight + int32(params.TicketMaturity) + 1
		fp.ticketExpires = fp.ticketLive + int32(params.TicketExpiry)
	}

	fp.votingAddr, fp.commitmentAddr, err = parseTicket(ticket, params)
	if err != nil {
		log.Errorf("%v is not a ticket: %v", ticketHash, err)
		return nil
	}
	// Try to access the voting key, ignore error unless the wallet is
	// locked.
	fp.votingKey, err = w.DumpWIFPrivateKey(ctx, fp.votingAddr)
	if err != nil && !errors.Is(err, errors.Locked) {
		log.Errorf("no voting key for ticket %v: %v", ticketHash, err)
		return nil
	}

	feeHash, err := w.VSPFeeHashForTicket(ctx, ticketHash)
	if err != nil {
		fp.state = unprocessed
		// caller must schedule next method, as paying the fee may
		// require using provided transaction inputs.
		return fp
	}

	fee, err := c.tx(ctx, &feeHash)
	if err != nil {
		// A fee hash is recorded for this ticket, but was not found in
		// the wallet.  This should not happen and may require manual
		// intervention.
		//
		// XXX should check ticketinfo and see if fee is not paid. if
		// possible, update it with a new fee.
		fp.err = fmt.Errorf("fee transaction not found in wallet: %w", err)
		return fp
	}

	fp.feeTx = fee
	fp.fee = -1            // XXX fee amount (not needed anymore?)
	fp.state = unprocessed // XXX fee created, but perhaps not submitted with vsp.
	fp.schedule("reconcile payment", fp.reconcilePayment)

	c.mu.Lock()
	c.jobs[*ticketHash] = fp
	c.mu.Unlock()

	return fp
}

func (c *Client) tx(ctx context.Context, hash *chainhash.Hash) (*wire.MsgTx, error) {
	txs, _, err := c.Wallet.GetTransactionsByHashes(ctx, []*chainhash.Hash{hash})
	if err != nil {
		return nil, err
	}
	return txs[0], nil
}

// Schedule a method to be executed.
// Any currently-scheduled method is replaced.
func (fp *feePayment) schedule(name string, method func() error) {
	delay := fp.next()

	fp.timerMu.Lock()
	defer fp.timerMu.Unlock()
	if fp.timer != nil {
		fp.timer.Stop()
		fp.timer = nil
	}
	if method != nil {
		fp.timer = time.AfterFunc(delay, fp.task(name, method))
	}
}

func (fp *feePayment) next() time.Duration {
	_, tipHeight := fp.client.Wallet.MainChainTip(fp.ctx)

	fp.mu.Lock()
	var jitter time.Duration
	// This liveness check requires the ticket to already be mined.
	switch {
	case tipHeight < fp.ticketLive:
		jitter = immatureJitter
	case tipHeight < fp.ticketExpires:
		jitter = liveJitter
	}
	fp.mu.Unlock()

	return prng.duration(jitter)
}

// task returns a function running a feePayment method.
// If the method errors, the error is logged, and the payment is put
// in an errored state and may require manual processing.
func (fp *feePayment) task(name string, method func() error) func() {
	return func() {
		err := method()
		fp.mu.Lock()
		fp.err = err
		fp.mu.Unlock()
		if err != nil {
			log.Errorf("ticket %v: %v: %v", &fp.ticketHash, name, err)
		}
	}
}

func (fp *feePayment) stop() {
	fp.schedule("", nil)
}

func (fp *feePayment) receiveFeeAddress() error {
	ctx := fp.ctx
	w := fp.client.Wallet
	params := w.ChainParams()

	// stop processing if ticket is expired or spent
	if fp.removedExpiredOrSpent() {
		// nothing scheduled
		return errStopped
	}

	// Fetch ticket and its parent transaction (typically, a split
	// transaction).
	ticket, err := fp.client.tx(ctx, &fp.ticketHash)
	if err != nil {
		return fmt.Errorf("failed to retrieve ticket: %w", err)
	}
	parentHash := &ticket.TxIn[0].PreviousOutPoint.Hash
	parent, err := fp.client.tx(ctx, parentHash)
	if err != nil {
		return fmt.Errorf("failed to retrieve parent %v of ticket: %w",
			parentHash, err)
	}

	var response struct {
		Timestamp  int64           `json:"timestamp"`
		FeeAddress string          `json:"feeaddress"`
		FeeAmount  int64           `json:"feeamount"`
		Request    json.RawMessage `json:"request"`
	}
	requestBody, err := json.Marshal(&struct {
		Timestamp  int64          `json:"timestamp"`
		TicketHash string         `json:"tickethash"`
		TicketHex  json.Marshaler `json:"tickethex"`
		ParentHex  json.Marshaler `json:"parenthex"`
	}{
		Timestamp:  time.Now().Unix(),
		TicketHash: fp.ticketHash.String(),
		TicketHex:  txMarshaler(ticket),
		ParentHex:  txMarshaler(parent),
	})
	if err != nil {
		return err
	}
	err = fp.client.post(ctx, "/api/v3/feeaddress", fp.commitmentAddr, &response,
		json.RawMessage(requestBody))
	if err != nil {
		return err
	}

	// verify initial request matches server
	if !bytes.Equal(requestBody, response.Request) {
		return fmt.Errorf("server response has differing request: %#v != %#v",
			requestBody, response.Request)
	}
	// TODO - validate server timestamp?

	_, err = dcrutil.DecodeAddress(response.FeeAddress, params)
	if err != nil {
		return fmt.Errorf("server fee address invalid: %w", err)
	}
	feeAmount := dcrutil.Amount(response.FeeAmount)

	log.Infof("VSP requires fee %v", feeAmount)
	if feeAmount > fp.policy.MaxFee {
		return fmt.Errorf("server fee amount too high: %v > %v",
			feeAmount, fp.policy.MaxFee)
	}

	// XXX first, create new fee tx, or fetch previous from db
	fp.schedule("submit payment", fp.submitPayment)
	return nil
}

// makeFeeTx adds outputs to tx to pay a VSP fee, optionally adding inputs as
// well to fund the transaction if no input value is already provided in the
// transaction.
func (fp *feePayment) makeFeeTx(tx *wire.MsgTx) error {
	ctx := fp.ctx
	w := fp.client.Wallet

	fp.mu.Lock()
	fee := fp.fee
	fpFeeTx := fp.feeTx
	fp.mu.Unlock()

	if fpFeeTx != nil {
		*tx = *fpFeeTx
		return nil
	} else {
		fp.mu.Lock()
		fp.feeTx = tx
		fpFeeTx = tx
		fp.mu.Unlock()
	}

	// XXX fp.fee == -1?
	if fee == 0 {
		// XXX locking
		// this schedules paying the fee
		err := fp.receiveFeeAddress()
		if err != nil {
			return err
		}
	}

	fp.mu.Lock()
	fee = fp.fee
	feeAddr := fp.feeAddr
	fp.mu.Unlock()

	// Reserve new outputs to pay the fee if outputs have not already been
	// reserved.  This will the the case for fee payments that were begun on
	// already purchased tickets, where the caller did not ensure that fee
	// outputs would already be reserved.
	if len(fpFeeTx.TxIn) == 0 {
		const minconf = 1
		inputs, err := w.ReserveOutputsForAmount(ctx, fp.policy.FeeAcct, fee, minconf)
		if err != nil {
			return fmt.Errorf("unable to reserve enough output value to "+
				"pay VSP fee for ticket %v: %w", fp.ticketHash, err)
		}
		for _, in := range inputs {
			tx.AddTxIn(wire.NewTxIn(&in.OutPoint, in.PrevOut.Value, nil))
		}
		// The transaction will be added to the wallet in an unpublished
		// state, so there is no need to leave the outputs locked.
		defer func() {
			for _, in := range inputs {
				w.UnlockOutpoint(&in.OutPoint.Hash, in.OutPoint.Index)
			}
		}()
	}

	var input int64
	for _, in := range tx.TxIn {
		input += in.ValueIn
	}
	if input < int64(fee) {
		err := fmt.Errorf("not enough input value to pay fee: %v < %v",
			dcrutil.Amount(input), fee)
		return err
	}

	feeScript, err := txscript.PayToAddrScript(feeAddr)
	if err != nil {
		log.Warnf("failed to generate pay to addr script for %v: %v",
			feeAddr, err)
		return err
	}

	addr, err := w.NewChangeAddress(ctx, fp.policy.ChangeAcct)
	if err != nil {
		log.Warnf("failed to get new change address: %v", err)
		return err
	}
	var changeOut *wire.TxOut
	switch addr := addr.(type) {
	case wallet.Address:
		vers, script := addr.PaymentScript()
		changeOut = &wire.TxOut{PkScript: script, Version: vers}
	default:
		return fmt.Errorf("failed to convert '%T' to wallet.Address", addr)
	}

	tx.TxOut = append(tx.TxOut[:0], wire.NewTxOut(int64(fee), feeScript))
	feeRate := w.RelayFee()
	scriptSizes := make([]int, len(tx.TxIn))
	for i := range scriptSizes {
		scriptSizes[i] = txsizes.RedeemP2PKHSigScriptSize
	}
	est := txsizes.EstimateSerializeSize(scriptSizes, tx.TxOut, txsizes.P2PKHPkScriptSize)
	change := input
	change -= tx.TxOut[0].Value
	change -= int64(txrules.FeeForSerializeSize(feeRate, est))
	if !txrules.IsDustAmount(dcrutil.Amount(change), txsizes.P2PKHPkScriptSize, feeRate) {
		changeOut.Value = change
		tx.TxOut = append(tx.TxOut, changeOut)
		// randomize position
		if prng.coinflip() {
			tx.TxOut[0], tx.TxOut[1] = tx.TxOut[1], tx.TxOut[0]
		}
	}

	feeHash := tx.TxHash()

	// sign
	sigErrs, err := w.SignTransaction(ctx, tx, txscript.SigHashAll, nil, nil, nil)
	if err != nil {
		log.Errorf("failed to sign transaction: %v", err)
		for _, sigErr := range sigErrs {
			log.Errorf("\t%v", sigErr)
		}
		return err
	}

	err = w.SetPublished(ctx, &feeHash, false)
	if err != nil {
		return err
	}
	err = w.AddTransaction(ctx, tx, nil)
	if err != nil {
		return err
	}
	err = w.UpdateVspTicketFeeToPaid(ctx, &fp.ticketHash, &feeHash)
	if err != nil {
		return err
	}

	fp.mu.Lock()
	fp.feeTx = tx
	fp.feeHash = feeHash
	fp.mu.Unlock()

	// nothing scheduled
	return nil
}

type ticketStatus struct {
	Timestamp       int64             `json:"timestamp"`
	TicketConfirmed bool              `json:"ticketconfirmed"`
	FeeTxStatus     string            `json:"feetxstatus"`
	FeeTxHash       string            `json:"feetxhash"`
	VoteChoices     map[string]string `json:"votechoices"`
	Request         json.RawMessage   `json:"request"`
}

func (fp *feePayment) status(ctx context.Context) (*ticketStatus, error) {
	if ctx == nil {
		ctx = fp.ctx
	}
	w := fp.client.Wallet
	params := w.ChainParams()

	ticketTx, err := fp.client.tx(ctx, &fp.ticketHash)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ticket %v: %w", &fp.ticketHash, err)
	}

	if !stake.IsSStx(ticketTx) {
		return nil, fmt.Errorf("%v is not a ticket", &fp.ticketHash)
	}
	commitmentAddr, err := stake.AddrFromSStxPkScrCommitment(ticketTx.TxOut[1].PkScript, params)
	if err != nil {
		return nil, fmt.Errorf("failed to extract commitment address from %v: %w",
			&fp.ticketHash, err)
	}

	var resp ticketStatus
	requestBody, err := json.Marshal(&struct {
		TicketHash string `json:"tickethash"`
	}{
		TicketHash: fp.ticketHash.String(),
	})
	if err != nil {
		return nil, err
	}
	err = fp.client.post(ctx, "/api/v3/ticketstatus", commitmentAddr, &resp,
		json.RawMessage(requestBody))
	if err != nil {
		return nil, err
	}

	// verify initial request matches server
	if !bytes.Equal(requestBody, resp.Request) {
		log.Warnf("server response has differing request: %#v != %#v",
			requestBody, resp.Request)
		return nil, fmt.Errorf("server response contains differing request")
	}

	// XXX validate server timestamp?

	return &resp, nil
}

func (fp *feePayment) reconcilePayment() error {
	ctx := fp.ctx
	w := fp.client.Wallet

	// stop processing if ticket is expired or spent
	if fp.removedExpiredOrSpent() {
		// nothing scheduled
		return errStopped
	}

	// A fee address has been obtained, and the fee transaction has been
	// created, but it is unknown if the VSP has received the fee and will
	// vote using the ticket.
	//
	// If the fee is mined, then check the status of the ticket and payment
	// with the VSP, to ensure that it has marked the fee payment as paid.
	//
	// If the fee is not mined, an API call with the VSP is used so it may
	// receive and publish the transaction.  A follow up on the ticket
	// status is scheduled for some time in the future.

	// XXX if ticket is no longer saved by wallet (because the tx expired,
	// or was double spent, etc) remove it

	fp.mu.Unlock()
	feeHash := fp.feeHash
	fp.mu.Lock()

	confs, err := w.TxConfirms(ctx, &feeHash)
	if err != nil {
		// XXX
		return err
	}
	if confs >= 1 {

	}

	// XXX? for each input, c.Wallet.UnlockOutpoint(&outpoint.Hash, outpoint.Index)
	// xxx, or let the published tx replace the unpublished one, and unlock
	// outpoints as it is processed.

	/* XXX
	err = v.cfg.Wallet.UpdateVspTicketFeeToPaid(ctx, &ticketHash, &feeHash)
	if err != nil {
		return nil, err
	}
	*/

	return nil
}

func (fp *feePayment) submitPayment() (err error) {
	ctx := fp.ctx
	w := fp.client.Wallet

	// stop processing if ticket is expired or spent
	if fp.removedExpiredOrSpent() {
		// nothing scheduled
		return errStopped
	}

	// Reschedule this method for any error
	defer func() {
		if err != nil {
			fp.schedule("submit payment", fp.submitPayment)
		}
	}()

	// submitting a payment requires the fee tx to already be created.
	fp.mu.Lock()
	feeTx := fp.feeTx
	votingKey := fp.votingKey
	fp.mu.Unlock()
	if feeTx == nil {
		feeTx = new(wire.MsgTx)
	}
	if len(feeTx.TxOut) == 0 {
		err := fp.makeFeeTx(feeTx)
		if err != nil {
			return err
		}
	}
	if votingKey == "" {
		votingKey, err = w.DumpWIFPrivateKey(ctx, fp.votingAddr)
		if err != nil {
			return err
		}
		fp.mu.Lock()
		fp.votingKey = votingKey
		fp.mu.Unlock()
	}

	// Retrieve voting preferences
	voteChoices := make(map[string]string)
	agendaChoices, _, err := w.AgendaChoices(ctx, &fp.ticketHash)
	if err != nil {
		return err
	}
	for _, agendaChoice := range agendaChoices {
		voteChoices[agendaChoice.AgendaID] = agendaChoice.ChoiceID
	}

	var payfeeResponse struct {
		Timestamp int64           `json:"timestamp"`
		Request   json.RawMessage `json:"request"`
	}
	requestBody, err := json.Marshal(&struct {
		Timestamp   int64             `json:"timestamp"`
		TicketHash  string            `json:"tickethash"`
		FeeTx       json.Marshaler    `json:"feetx"`
		VotingKey   string            `json:"votingkey"`
		VoteChoices map[string]string `json:"votechoices"`
	}{
		Timestamp:   time.Now().Unix(),
		TicketHash:  fp.ticketHash.String(),
		FeeTx:       txMarshaler(feeTx),
		VotingKey:   votingKey,
		VoteChoices: voteChoices,
	})
	if err != nil {
		return err
	}
	err = fp.client.post(ctx, "/api/v3/payfee", fp.commitmentAddr,
		&payfeeResponse, json.RawMessage(requestBody))
	if err != nil {
		return fmt.Errorf("payfee: %w", err)
	}

	// Check for matching original request.
	// This is signed by the VSP, and the signature
	// has already been checked above.
	if !bytes.Equal(requestBody, payfeeResponse.Request) {
		return fmt.Errorf("server response has differing request: %#v != %#v",
			requestBody, payfeeResponse.Request)
	}
	// TODO - validate server timestamp?

	log.Infof("successfully processed %v", fp.ticketHash)

	fp.schedule("confirm payment", fp.confirmPayment)
	return nil
}

func (fp *feePayment) confirmPayment() error {
	ctx := fp.ctx

	// stop processing if ticket is expired or spent
	if fp.removedExpiredOrSpent() {
		// nothing scheduled
		return errStopped
	}

	status, err := fp.status(ctx)
	if err != nil {
		log.Warnf("Rescheduling status check for %v: %v", &fp.ticketHash, err)
		fp.schedule("confirm payment", fp.confirmPayment)
		return nil
	}

	switch status.FeeTxStatus {
	case "broadcast":
		log.Infof("VSP has successfully sent the fee tx for %v", &fp.ticketHash)
		fp.schedule("confirm payment", fp.confirmPayment)
		return nil
	case "confirmed":
		log.Infof("VSP has successfully confirmed the fee tx for %v", &fp.ticketHash)
		// nothing scheduled
		return nil
	case "error":
		log.Warnf("VSP failed to broadcast feetx for %v -- restarting payment",
			&fp.ticketHash)
		fp.schedule("submit payment", fp.submitPayment)
		return nil
	default:
		// XXX put in unknown state
		log.Warnf("VSP responded with %v for %v", status.FeeTxStatus,
			&fp.ticketHash)
	}

	return nil
}

type marshaler struct {
	marshaled []byte
	err       error
}

func (m *marshaler) MarshalJSON() ([]byte, error) {
	return m.marshaled, m.err
}

func txMarshaler(tx *wire.MsgTx) json.Marshaler {
	var buf bytes.Buffer
	buf.Grow(2 + tx.SerializeSize()*2)
	buf.WriteByte('"')
	err := tx.Serialize(hex.NewEncoder(&buf))
	buf.WriteByte('"')
	return &marshaler{buf.Bytes(), err}
}
