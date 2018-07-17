// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package spv

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/decred/dcrd/addrmgr"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/gcs/blockcf"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/errors"
	"github.com/decred/dcrwallet/lru"
	"github.com/decred/dcrwallet/p2p"
	"github.com/decred/dcrwallet/validate"
	"github.com/decred/dcrwallet/wallet"
	"golang.org/x/sync/errgroup"
)

// reqSvcs defines the services that must be supported by outbounded peers.
// After fetching more addresses (if needed), peers are disconnected from if
// they do not provide each of these services.
const reqSvcs = wire.SFNodeNetwork | wire.SFNodeCF

// Syncer implements wallet synchronization services by over the Decred wire
// protocol using Simplified Payment Verification (SPV) with compact filters.
type Syncer struct {
	// atomics
	atomicCatchUpTryLock uint32 // CAS (entered=1) to call s.wallet.CatchUpToHeaders

	wallet *wallet.Wallet
	lp     *p2p.LocalPeer

	discoverAccounts bool // Protected by atomicCatchUpTryLock

	persistantPeers []string

	connectingRemotes map[string]struct{}
	remotes           map[string]*p2p.RemotePeer
	remotesMu         sync.Mutex

	// Data filters
	//
	// TODO: Replace precise rescan filter with wallet db accesses to avoid
	// needing to keep all relevant data in memory.
	rescanFilter *wallet.RescanFilter
	filterData   blockcf.Entries
	filterMu     sync.Mutex

	// seenTxs records hashes of received inventoried transactions.  Once a
	// transaction is fetched and processed from one peer, the hash is added to
	// this cache to avoid fetching it again from other peers that announce the
	// transaction.
	seenTxs lru.Cache

	// Sidechain management
	sidechains  wallet.SidechainForest
	sidechainMu sync.Mutex

	currentLocators   []*chainhash.Hash
	locatorGeneration uint
	locatorMu         sync.Mutex
}

// NewSyncer creates a Syncer that will sync the wallet using SPV.
func NewSyncer(w *wallet.Wallet, lp *p2p.LocalPeer) *Syncer {
	return &Syncer{
		wallet:            w,
		discoverAccounts:  !w.Locked(),
		connectingRemotes: make(map[string]struct{}),
		remotes:           make(map[string]*p2p.RemotePeer),
		rescanFilter:      wallet.NewRescanFilter(nil, nil),
		seenTxs:           lru.NewCache(2000),
		lp:                lp,
	}
}

// SetPersistantPeers sets each peer as a persistant peer and disables DNS
// seeding and peer discovery.
func (s *Syncer) SetPersistantPeers(peers []string) {
	s.persistantPeers = peers
}

// Run synchronizes the wallet, returning when synchronization fails or the
// context is cancelled.
func (s *Syncer) Run(ctx context.Context) error {
	tipHash, tipHeight := s.wallet.MainChainTip()
	rescanPoint, err := s.wallet.RescanPoint()
	if err != nil {
		return err
	}
	log.Infof("Headers synced through block %v height %d", &tipHash, tipHeight)
	if rescanPoint != nil {
		h, err := s.wallet.BlockHeader(rescanPoint)
		if err != nil {
			return err
		}
		// The rescan point is the first block that does not have synced
		// transactions, so we are synced with the parent.
		log.Infof("Transactions synced through block %v height %d", &h.PrevBlock, h.Height-1)
	} else {
		log.Infof("Transactions synced through block %v height %d", &tipHash, tipHeight)
	}

	locators, err := s.wallet.BlockLocators(nil)
	if err != nil {
		return err
	}
	s.currentLocators = locators

	s.lp.AddrManager().Start()
	defer func() {
		err := s.lp.AddrManager().Stop()
		if err != nil {
			log.Errorf("Failed to cleanly stop address manager: %v", err)
		}
	}()

	// Seed peers over DNS when not disabled by persistant peers.
	if len(s.persistantPeers) == 0 {
		s.lp.DNSSeed(wire.SFNodeNetwork | wire.SFNodeCF)
	}

	// Start background handlers to read received messages from remote peers
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.receiveGetData(ctx) })
	g.Go(func() error { return s.receiveInv(ctx) })
	g.Go(func() error { return s.receiveHeadersAnnouncements(ctx) })
	s.lp.AddHandledMessages(p2p.MaskGetData | p2p.MaskInv)

	if len(s.persistantPeers) != 0 {
		for i := range s.persistantPeers {
			raddr := s.persistantPeers[i]
			g.Go(func() error { return s.connectToPersistent(ctx, raddr) })
		}
	} else {
		g.Go(func() error { return s.connectToCandidates(ctx) })
	}

	// Wait until cancellation or a handler errors.
	return g.Wait()
}

func (s *Syncer) peerCandidate(svcs wire.ServiceFlag) (*wire.NetAddress, error) {
	// Try to obtain peer candidates at random, decreasing the requirements
	// as more tries are performed.
	for tries := 0; tries < 100; tries++ {
		kaddr := s.lp.AddrManager().GetAddress()
		if kaddr == nil {
			break
		}
		na := kaddr.NetAddress()

		// Skip peer if already connected
		// TODO: this should work with network blocks, not exact addresses.
		k := addrmgr.NetAddressKey(na)
		s.remotesMu.Lock()
		_, isConnecting := s.connectingRemotes[k]
		_, isRemote := s.remotes[k]
		s.remotesMu.Unlock()
		if isConnecting || isRemote {
			continue
		}

		// Only allow recent nodes (10mins) after we failed 30 times
		if tries < 30 && time.Since(kaddr.LastAttempt()) < 10*time.Minute {
			continue
		}

		// Skip peers without matching service flags for the first 50 tries.
		if tries < 50 && kaddr.NetAddress().Services&svcs != svcs {
			continue
		}

		return na, nil
	}
	return nil, errors.New("no addresses")
}

func (s *Syncer) connectToPersistent(ctx context.Context, raddr string) error {
	for {
		func() {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			rp, err := s.lp.ConnectOutbound(ctx, raddr, reqSvcs)
			if err != nil {
				if ctx.Err() == nil {
					log.Errorf("Peering attempt failed: %v", err)
				}
				return
			}
			log.Infof("New peer %v %v %v", raddr, rp.UA(), rp.Services())

			k := addrmgr.NetAddressKey(rp.NA())
			s.remotesMu.Lock()
			s.remotes[k] = rp
			s.remotesMu.Unlock()

			wait := make(chan struct{})
			go func() {
				err := s.startupSync(ctx, rp)
				if err != nil {
					rp.Disconnect(err)
				}
				wait <- struct{}{}
			}()

			err = rp.Err()
			s.remotesMu.Lock()
			delete(s.remotes, k)
			s.remotesMu.Unlock()
			<-wait
			if ctx.Err() != nil {
				return
			}
			log.Warnf("Lost peer %v: %v", raddr, err)
		}()

		if err := ctx.Err(); err != nil {
			return err
		}

		time.Sleep(5 * time.Second)
	}
}

func (s *Syncer) connectToCandidates(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	sem := make(chan struct{}, 8)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		na, err := s.peerCandidate(reqSvcs)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				<-sem
				continue
			}
		}

		wg.Add(1)
		go func() {
			ctx, cancel := context.WithCancel(ctx)
			defer func() {
				cancel()
				wg.Done()
				<-sem
			}()

			// Make outbound connections to remote peers.
			port := strconv.FormatUint(uint64(na.Port), 10)
			raddr := net.JoinHostPort(na.IP.String(), port)
			k := addrmgr.NetAddressKey(na)

			s.remotesMu.Lock()
			s.connectingRemotes[k] = struct{}{}
			s.remotesMu.Unlock()

			rp, err := s.lp.ConnectOutbound(ctx, raddr, reqSvcs)
			if err != nil {
				if ctx.Err() == nil {
					log.Warnf("Peering attempt failed: %v", err)
				}
				return
			}
			log.Infof("New peer %v %v %v", raddr, rp.UA(), rp.Services())

			s.remotesMu.Lock()
			delete(s.connectingRemotes, k)
			s.remotes[k] = rp
			s.remotesMu.Unlock()

			wait := make(chan struct{})
			go func() {
				err := s.startupSync(ctx, rp)
				if err != nil {
					rp.Disconnect(err)
				}
				wait <- struct{}{}
			}()

			err = rp.Err()
			if ctx.Err() != context.Canceled {
				log.Warnf("Lost peer %v: %v", raddr, err)
			}

			<-wait
			s.remotesMu.Lock()
			delete(s.remotes, k)
			s.remotesMu.Unlock()
		}()
	}
}

func (s *Syncer) forRemotes(f func(rp *p2p.RemotePeer) error) error {
	defer s.remotesMu.Unlock()
	s.remotesMu.Lock()
	if len(s.remotes) == 0 {
		return errors.E(errors.NoPeers)
	}
	for _, rp := range s.remotes {
		err := f(rp)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Syncer) pickRemote(pick func(*p2p.RemotePeer) bool) (*p2p.RemotePeer, error) {
	defer s.remotesMu.Unlock()
	s.remotesMu.Lock()

	for _, rp := range s.remotes {
		if pick(rp) {
			return rp, nil
		}
	}
	return nil, errors.E(errors.NoPeers)
}

// receiveGetData handles all received getdata requests from peers.  An inv
// message declaring knowledge of the data must have been previously sent to the
// peer, or a notfound message reports the data as missing.  Only transactions
// may be queried by a peer.
func (s *Syncer) receiveGetData(ctx context.Context) error {
	var wg sync.WaitGroup
	for {
		rp, msg, err := s.lp.ReceiveGetData(ctx)
		if err != nil {
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Ensure that the data was (recently) announced using an inv.
			var txHashes []*chainhash.Hash
			var notFound []*wire.InvVect
			for _, inv := range msg.InvList {
				if !rp.InvsSent().Contains(inv.Hash) {
					notFound = append(notFound, inv)
					continue
				}
				switch inv.Type {
				case wire.InvTypeTx:
					txHashes = append(txHashes, &inv.Hash)
				default:
					notFound = append(notFound, inv)
				}
			}

			// Search for requested transactions
			var foundTxs []*wire.MsgTx
			if len(txHashes) != 0 {
				var missing []*wire.InvVect
				var err error
				foundTxs, missing, err = s.wallet.GetTransactionsByHashes(txHashes)
				if err != nil && !errors.Is(errors.NotExist, err) {
					log.Warnf("Failed to look up transactions for getdata reply to peer %v: %v",
						rp.RemoteAddr(), err)
					return
				}
				if len(missing) != 0 {
					notFound = append(notFound, missing...)
				}
			}

			// Send all found transactions
			for _, tx := range foundTxs {
				err := rp.SendMessage(ctx, tx)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					log.Warnf("Failed to send getdata reply to peer %v: %v",
						rp.RemoteAddr(), err)
				}
			}

			// Send notfound message for all missing or unannounced data.
			if len(notFound) != 0 {
				err := rp.SendMessage(ctx, &wire.MsgNotFound{InvList: notFound})
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					log.Warnf("Failed to send notfound reply to peer %v: %v",
						rp.RemoteAddr(), err)
				}
			}
		}()
	}
}

// receiveInv receives all inv messages from peers and starts goroutines to
// handle block and tx announcements.
func (s *Syncer) receiveInv(ctx context.Context) error {
	var wg sync.WaitGroup
	for {
		rp, msg, err := s.lp.ReceiveInv(ctx)
		if err != nil {
			wg.Wait()
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			var blocks []*chainhash.Hash
			var txs []*chainhash.Hash

			for _, inv := range msg.InvList {
				switch inv.Type {
				case wire.InvTypeBlock:
					blocks = append(blocks, &inv.Hash)
				case wire.InvTypeTx:
					txs = append(txs, &inv.Hash)
				}
			}

			if len(blocks) != 0 {
				wg.Add(1)
				go func() {
					defer wg.Done()

					err := s.handleBlockInvs(ctx, rp, blocks)
					if ctx.Err() != nil {
						return
					}
					if errors.Is(errors.Protocol, err) || errors.Is(errors.Consensus, err) {
						log.Warnf("Disconnecting peer %v: %v", rp, err)
						rp.Disconnect(err)
						return
					}
					if err != nil {
						log.Warnf("Failed to handle blocks inventoried by %v: %v", rp, err)
					}
				}()
			}
			if len(txs) != 0 {
				wg.Add(1)
				go func() {
					s.handleTxInvs(ctx, rp, txs)
					wg.Done()
				}()
			}
		}()
	}
}

func (s *Syncer) handleBlockInvs(ctx context.Context, rp *p2p.RemotePeer, hashes []*chainhash.Hash) error {
	const opf = "spv.handleBlockInvs(%v)"

	blocks, err := rp.GetBlocks(ctx, hashes)
	if err != nil {
		op := errors.Opf(opf, rp)
		return errors.E(op, err)
	}
	headers := make([]*wire.BlockHeader, len(blocks))
	bmap := make(map[chainhash.Hash]*wire.MsgBlock)
	for i, block := range blocks {
		bmap[block.BlockHash()] = block
		h := block.Header
		headers[i] = &h
	}

	return s.handleBlockAnnouncements(ctx, rp, headers, bmap)
}

// handleTxInvs responds to the inv message created by rp by fetching
// all unseen transactions announced by the peer.  Any transactions
// that are relevant to the wallet are saved as unconfirmed
// transactions.  Transaction invs are ignored when a rescan is
// necessary or ongoing.
func (s *Syncer) handleTxInvs(ctx context.Context, rp *p2p.RemotePeer, hashes []*chainhash.Hash) {
	const opf = "spv.handleTxInvs(%v)"

	rpt, err := s.wallet.RescanPoint()
	if err != nil {
		op := errors.Opf(opf, rp.RemoteAddr())
		log.Warn(errors.E(op, err))
		return
	}
	if rpt != nil {
		return
	}

	// Ignore already-processed transactions
	for i := 0; i < len(hashes); {
		if s.seenTxs.Contains(*hashes[i]) {
			hashes[i], hashes[len(hashes)-1] = hashes[len(hashes)-1], hashes[i]
			hashes[len(hashes)-1] = nil
			hashes = hashes[:len(hashes)-1]
			continue
		}
		i++
	}
	if len(hashes) == 0 {
		return
	}

	txs, err := rp.GetTransactions(ctx, hashes)
	if errors.Is(errors.NotExist, err) {
		err = nil
		for i := 0; i < len(txs); {
			if txs[i] == nil {
				// Update hashes and txs to remove notfound tx.
				hashes[i], hashes[len(hashes)-1] = hashes[len(hashes)-1], nil
				txs[i], txs[len(txs)-1] = txs[len(txs)-1], nil
				continue
			}
			i++
		}
	}
	if err != nil {
		if ctx.Err() == nil {
			op := errors.Opf(opf, rp.RemoteAddr())
			err := errors.E(op, err)
			log.Warn(err)
		}
		return
	}

	// Mark transactions as processed so they are not queried from other nodes
	// who announce them in the future.
	for _, h := range hashes {
		s.seenTxs.Add(*h)
	}

	// Save any relevant transaction.
	relevantTxs := s.relevantInventoriedTx(txs)
	for _, tx := range relevantTxs {
		err := s.wallet.AcceptMempoolTx(tx)
		if err != nil {
			if ctx.Err() == nil {
				op := errors.Opf(opf, rp.RemoteAddr())
				err := errors.E(op, err)
				log.Warn(err)
			}
		}
	}
}

// receiveHeaderAnnouncements receives all block announcements through pushed
// headers messages messages from peers and starts goroutines to handle the
// announced header.
func (s *Syncer) receiveHeadersAnnouncements(ctx context.Context) error {
	for {
		rp, headers, err := s.lp.ReceiveHeadersAnnouncement(ctx)
		if err != nil {
			return err
		}

		go func() {
			err := s.handleBlockAnnouncements(ctx, rp, headers, nil)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				if errors.Is(errors.Protocol, err) || errors.Is(errors.Consensus, err) {
					log.Warnf("Disconnecting peer %v: %v", rp, err)
					rp.Disconnect(err)
					return
				}

				log.Warnf("Failed to handle headers announced by %v: %v", rp, err)
			}
		}()
	}
}

// fetchMatchingTxs checks full blocks for any matching cfilter of a
// recently-announced block and returns a map of relevant wallet transactions
// keyed by block hash.  bmap is queried for the block first with fallback to
// querying rp using getdata.
func (s *Syncer) fetchMatchingTxs(ctx context.Context, rp *p2p.RemotePeer, chain []*wallet.BlockNode,
	bmap map[chainhash.Hash]*wire.MsgBlock) (map[chainhash.Hash][]*wire.MsgTx, error) {
	// Discover which blocks may possibly hold relevant transactions
	matchingBlocks := make([]*chainhash.Hash, 0, len(chain))
	matchingIndexes := make([]int, 0, len(chain))
	s.filterMu.Lock()
	for i, n := range chain {
		if n.Filter.N() != 0 && n.Filter.MatchAny(blockcf.Key(n.Hash), s.filterData) {
			matchingBlocks = append(matchingBlocks, n.Hash)
			matchingIndexes = append(matchingIndexes, i)
		}
	}
	s.filterMu.Unlock()

	fetchedBlocks := make([]*wire.MsgBlock, len(matchingBlocks))

	g, gctx := errgroup.WithContext(ctx)
	for i := range matchingBlocks {
		i := i
		hash := matchingBlocks[i]
		g.Go(func() error {
			b, ok := bmap[*hash]
			if !ok {
				var err error
				b, err = rp.GetBlock(gctx, hash)
				if err != nil {
					return err
				}
			}

			// Perform context-free validation on the block.  Disconnect
			// peer if this validation fails.
			err := validate.MerkleRoots(b)
			if err != nil {
				rp.Disconnect(err)
				return err
			}
			err = validate.RegularCFilter(b, chain[matchingIndexes[i]].Filter)
			if err != nil {
				rp.Disconnect(err)
				return err
			}

			// Record the fetched block
			fetchedBlocks[i] = b
			return nil
		})
	}
	err := g.Wait()
	if err != nil {
		return nil, err
	}

	matchingTxs := make(map[chainhash.Hash][]*wire.MsgTx)
	for i, hash := range matchingBlocks {
		b := fetchedBlocks[i]
		matchingTxs[*hash], _ = s.rescanBlock(b)
	}

	return matchingTxs, nil
}

// handleBlockAnnouncements handles blocks announced through block invs or
// headers messages by rp.  bmap should contain the full blocks of any
// inventoried blocks, but may be nil in case the blocks were announced through
// headers.
func (s *Syncer) handleBlockAnnouncements(ctx context.Context, rp *p2p.RemotePeer, headers []*wire.BlockHeader,
	bmap map[chainhash.Hash]*wire.MsgBlock) (err error) {

	const opf = "spv.handleBlockAnnouncements(%v)"
	defer func() {
		if err != nil && ctx.Err() == nil {
			op := errors.Opf(opf, rp.RemoteAddr())
			err = errors.E(op, err)
		}
	}()

	if len(headers) == 0 {
		return nil
	}

	blockHashes := make([]*chainhash.Hash, 0, len(headers))
	for _, h := range headers {
		hash := h.BlockHash()
		blockHashes = append(blockHashes, &hash)
	}
	filters, err := rp.GetCFilters(ctx, blockHashes)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	newBlocks := make([]*wallet.BlockNode, 0, len(headers))
	var bestChain []*wallet.BlockNode
	var matchingTxs map[chainhash.Hash][]*wire.MsgTx
	err = func() error {
		defer s.sidechainMu.Unlock()
		s.sidechainMu.Lock()

		for i := range headers {
			haveBlock, _, err := s.wallet.BlockInMainChain(blockHashes[i])
			if err != nil {
				return err
			}
			if haveBlock {
				continue
			}
			n := wallet.NewBlockNode(headers[i], blockHashes[i], filters[i])
			if s.sidechains.AddBlockNode(n) {
				newBlocks = append(newBlocks, n)
			}
		}

		bestChain, err = s.wallet.EvaluateBestChain(&s.sidechains)
		if err != nil {
			return err
		}

		if len(bestChain) == 0 {
			return nil
		}

		_, err = s.wallet.ValidateHeaderChainDifficulties(bestChain, 0)
		if err != nil {
			return err
		}

		rpt, err := s.wallet.RescanPoint()
		if err != nil {
			return err
		}
		if rpt == nil {
			matchingTxs, err = s.fetchMatchingTxs(ctx, rp, bestChain, bmap)
			if err != nil {
				return err
			}
		}

		prevChain, err := s.wallet.ChainSwitch(&s.sidechains, bestChain, matchingTxs)
		if err != nil {
			return err
		}
		if len(prevChain) != 0 {
			log.Infof("Reorganize from %v to %v (total %d block(s) reorged)",
				prevChain[len(prevChain)-1].Hash, bestChain[len(bestChain)-1].Hash, len(prevChain))
			for _, n := range prevChain {
				s.sidechains.AddBlockNode(n)
			}
		}

		return nil
	}()
	if err != nil {
		return err
	}

	if len(bestChain) != 0 {
		s.locatorMu.Lock()
		s.currentLocators = nil
		s.locatorGeneration++
		s.locatorMu.Unlock()
	}

	// Log connected blocks.
	for _, n := range bestChain {
		log.Infof("Connected block %v, height %d, %d wallet transaction(s)",
			n.Hash, n.Header.Height, len(matchingTxs[*n.Hash]))
	}
	// Announced blocks not in the main chain are logged as sidechain or orphan
	// blocks.
	for _, n := range newBlocks {
		haveBlock, _, err := s.wallet.BlockInMainChain(n.Hash)
		if err != nil {
			return err
		}
		if haveBlock {
			continue
		}
		log.Infof("Received sidechain or orphan block %v, height %v", n.Hash, n.Header.Height)
	}

	return nil
}

// hashStop is a zero value stop hash for fetching all possible data using
// locators.
var hashStop chainhash.Hash

// getHeaders iteratively fetches headers from rp using the latest locators.
// Returns when no more headers are available.  A sendheaders message is pushed
// to the peer when there are no more headers to fetch.
func (s *Syncer) getHeaders(ctx context.Context, rp *p2p.RemotePeer) error {
	var locators []*chainhash.Hash
	var generation uint
	var err error
	s.locatorMu.Lock()
	locators = s.currentLocators
	generation = s.locatorGeneration
	if locators == nil {
		locators, err = s.wallet.BlockLocators(nil)
		if err != nil {
			s.locatorMu.Unlock()
			return err
		}
		s.currentLocators = locators
		s.locatorGeneration++
	}
	s.locatorMu.Unlock()

	var lastHeight int32

	for {
		headers, err := rp.GetHeaders(ctx, locators, &hashStop)
		if err != nil {
			return err
		}

		if len(headers) == 0 {
			// Ensure that the peer provided headers through the height
			// advertised during handshake.
			if lastHeight < rp.InitialHeight() {
				// Peer may not have provided any headers if our own locators
				// were up to date.  Compare the best locator hash with the
				// advertised height.
				h, err := s.wallet.BlockHeader(locators[0])
				if err == nil && int32(h.Height) < rp.InitialHeight() {
					return errors.E(errors.Protocol, "peer did not provide "+
						"headers through advertised height")
				}
			}

			rp.SendHeaders(ctx)
			return nil
		}

		lastHeight = int32(headers[len(headers)-1].Height)

		nodes := make([]*wallet.BlockNode, len(headers))
		g, gctx := errgroup.WithContext(ctx)
		for i := range headers {
			i := i
			g.Go(func() error {
				header := headers[i]
				hash := header.BlockHash()
				filter, err := rp.GetCFilter(gctx, &hash)
				if err != nil {
					return err
				}
				nodes[i] = wallet.NewBlockNode(header, &hash, filter)
				return nil
			})
		}
		err = g.Wait()
		if err != nil {
			return err
		}

		var added int
		s.sidechainMu.Lock()
		for _, n := range nodes {
			haveBlock, _, _ := s.wallet.BlockInMainChain(n.Hash)
			if haveBlock {
				continue
			}
			if s.sidechains.AddBlockNode(n) {
				added++
			}
		}
		if added == 0 {
			s.sidechainMu.Unlock()

			s.locatorMu.Lock()
			if s.locatorGeneration > generation {
				locators = s.currentLocators
			} else {
				locators, err = s.wallet.BlockLocators(nil)
				if err != nil {
					s.locatorMu.Unlock()
					return err
				}
				s.currentLocators = locators
				s.locatorGeneration++
				generation = s.locatorGeneration
			}
			s.locatorMu.Unlock()
			continue
		}

		log.Debugf("Fetched %d new header(s) ending at height %d from %v",
			added, nodes[len(nodes)-1].Header.Height, rp)

		bestChain, err := s.wallet.EvaluateBestChain(&s.sidechains)
		if err != nil {
			s.sidechainMu.Unlock()
			return err
		}
		if len(bestChain) == 0 {
			s.sidechainMu.Unlock()
			continue
		}

		_, err = s.wallet.ValidateHeaderChainDifficulties(bestChain, 0)
		if err != nil {
			s.sidechainMu.Unlock()
			return err
		}

		prevChain, err := s.wallet.ChainSwitch(&s.sidechains, bestChain, nil)
		if err != nil {
			s.sidechainMu.Unlock()
			return err
		}

		if len(prevChain) != 0 {
			log.Infof("Reorganize from %v to %v (total %d block(s) reorged)",
				prevChain[len(prevChain)-1].Hash, bestChain[len(bestChain)-1].Hash, len(prevChain))
			for _, n := range prevChain {
				s.sidechains.AddBlockNode(n)
			}
		}
		tip := bestChain[len(bestChain)-1]
		if len(bestChain) == 1 {
			log.Infof("Connected block %v, height %d", tip.Hash, tip.Header.Height)
		} else {
			log.Infof("Connected %d blocks, new tip %v, height %d, date %v",
				len(bestChain), tip.Hash, tip.Header.Height, tip.Header.Timestamp)
		}

		s.sidechainMu.Unlock()

		// Generate new locators
		s.locatorMu.Lock()
		locators, err = s.wallet.BlockLocators(nil)
		if err != nil {
			s.locatorMu.Unlock()
			return err
		}
		s.currentLocators = locators
		s.locatorGeneration++
		s.locatorMu.Unlock()
	}
}

// startupSync syncs the wallet with rp, first by
func (s *Syncer) startupSync(ctx context.Context, rp *p2p.RemotePeer) error {
	// Disconnect from the peer if their advertised block height is
	// significantly behind the wallet's.
	_, tipHeight := s.wallet.MainChainTip()
	if rp.InitialHeight() < tipHeight-6 {
		return errors.E("peer is not synced")
	}

	// Fetch any missing main chain compact filters.
	err := s.wallet.FetchMissingCFilters(ctx, s)
	if err != nil {
		return err
	}

	// Fetch any unseen headers from the peer.
	log.Debugf("Fetching headers from %v", rp.RemoteAddr())
	err = s.getHeaders(ctx, rp)
	if err != nil {
		return err
	}

	if atomic.CompareAndSwapUint32(&s.atomicCatchUpTryLock, 0, 1) {
		err = func() error {
			rescanPoint, err := s.wallet.RescanPoint()
			if err != nil {
				return err
			}
			if rescanPoint == nil {
				return nil
			}
			err = s.wallet.DiscoverActiveAddresses(ctx, rp, rescanPoint, s.discoverAccounts)
			if err != nil {
				return err
			}
			err = s.wallet.LoadActiveDataFilters(ctx, s, true)
			if err != nil {
				return err
			}
			return s.wallet.Rescan(ctx, s, rescanPoint)
		}()
		atomic.StoreUint32(&s.atomicCatchUpTryLock, 0)
		if err != nil {
			return err
		}
	}

	unminedTxs, err := s.wallet.UnminedTransactions()
	if err != nil {
		log.Errorf("Cannot load unmined transactions for resending: %v", err)
		return nil
	}
	if len(unminedTxs) == 0 {
		return nil
	}
	err = rp.PublishTransactions(ctx, unminedTxs...)
	if err != nil {
		// TODO: Transactions should be removed if this is a double spend.
		log.Errorf("Failed to resent one or more unmined transactions: %v", err)
	}
	return nil
}