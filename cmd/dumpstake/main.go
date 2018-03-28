// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrd/dcrutil"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	connectFlag    = flag.String("c", "localhost:9111", "host:ip of dcrwallet gRPC server")
	voteFlag       = flag.Bool("votes", false, "dump hashes for vote transactions")
	revocationFlag = flag.Bool("revocations", false, "dump hashes for revocation transactions")
)

func dieOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var certificateFile = filepath.Join(dcrutil.AppDataDir("dcrwallet", false), "rpc.cert")

func main() {
	flag.Parse()

	if !*voteFlag && !*revocationFlag {
		fmt.Fprintln(os.Stderr, "Please set -votes or -revocations")
		os.Exit(1)
	}

	ctx := context.Background()
	creds, err := credentials.NewClientTLSFromFile(certificateFile, "localhost")
	dieOn(err)
	conn, err := grpc.Dial(*connectFlag, grpc.WithTransportCredentials(creds))
	dieOn(err)
	defer conn.Close()
	c := pb.NewWalletServiceClient(conn)

	// TODO: api needs better way to get current block height than grabbing accounts.
	ar, err := c.Accounts(ctx, &pb.AccountsRequest{})
	dieOn(err)
	latestBlock := ar.CurrentBlockHeight

	type ticketInfo struct {
		tx        *wire.MsgTx
		blockTime int64
		fee       dcrutil.Amount
	}
	tickets := make(map[chainhash.Hash]*ticketInfo)

	for i := int32(0); ; i++ {
		blockStart := i * 100
		blockEnd := (i+1)*100 - 1
		gtx, err := c.GetTransactions(ctx, &pb.GetTransactionsRequest{
			StartingBlockHeight: blockStart,
			EndingBlockHeight:   blockEnd,
		})
		dieOn(err)
		for {
			r, err := gtx.Recv()
			if err == io.EOF {
				break
			}
			dieOn(err)
			for _, tx := range r.MinedTransactions.Transactions {
				var outIdx int
				switch {
				case tx.TransactionType == pb.TransactionDetails_TICKET_PURCHASE:
				case *voteFlag && tx.TransactionType == pb.TransactionDetails_VOTE:
					outIdx = 2
				case *revocationFlag && tx.TransactionType == pb.TransactionDetails_REVOCATION:
					outIdx = 0
				default:
					continue
				}

				txHash, err := chainhash.NewHash(tx.Hash)
				dieOn(err)

				var msgTx wire.MsgTx
				dieOn(msgTx.Deserialize(bytes.NewReader(tx.Transaction)))

				if tx.TransactionType == pb.TransactionDetails_TICKET_PURCHASE {
					tickets[*txHash] = &ticketInfo{
						tx:        &msgTx,
						blockTime: r.MinedTransactions.Timestamp,
						fee:       dcrutil.Amount(tx.Fee),
					}
					continue
				}

				ticketHash := &msgTx.TxIn[len(msgTx.TxIn)-1].PreviousOutPoint.Hash
				ticket := tickets[*ticketHash]
				delete(tickets, *ticketHash)

				// ticket purchase hash, ticket purchase unix time, ticket price+fee,
				// vote/revocation hash, unix time of vote/revocation, txout 2 (votes) or 0 (revocations) amount
				fmt.Println(
					ticketHash,
					ticket.blockTime,
					(dcrutil.Amount(ticket.tx.TxOut[0].Value) + ticket.fee).ToCoin(),
					txHash,
					r.MinedTransactions.Timestamp,
					dcrutil.Amount(msgTx.TxOut[outIdx].Value).ToCoin(),
				)
			}
		}
		if blockEnd >= latestBlock {
			return
		}
	}
}
