package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"os"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/blockchain/stake"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	connectFlag = flag.String("c", "localhost:9111", "host:ip of dcrwallet gRPC server")
	testnetFlag = flag.Bool("testnet", false, "use the testnet network")
)

var certificateFile = filepath.Join(dcrutil.AppDataDir("dcrwallet", false), "rpc.cert")
var params = &chaincfg.MainNetParams

func dieOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func main() {
	flag.Parse()

	if *testnetFlag {
		params = &chaincfg.TestNet2Params
	}

	ctx := context.Background()
	creds, err := credentials.NewClientTLSFromFile(certificateFile, "localhost")
	dieOn(err)

	conn, err := grpc.Dial(*connectFlag, grpc.WithTransportCredentials(creds))
	dieOn(err)

	defer conn.Close()
	c := pb.NewWalletServiceClient(conn)

	accts := make(map[uint32]string)

	ar, err := c.Accounts(ctx, &pb.AccountsRequest{})
	dieOn(err)
	
	for _, a := range ar.Accounts {
		accts[a.AccountNumber] = a.AccountName
	}
	latestBlock := ar.CurrentBlockHeight

	for i := int32(0); ; i++ {
		blockStart := i * 100
		blockEnd := (i+1)*100 - 1
		if blockEnd >= latestBlock {
			blockEnd = 0
		}
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
				printTx(accts, tx, r.MinedTransactions.Timestamp)
			}
			for _, tx := range r.UnminedTransactions {
				printTx(accts, tx, tx.Timestamp)
			}
		}

		if blockEnd == 0 {
			return
		}
	}
}

type detail struct {
	account   string
	direction string
	txHash    *chainhash.Hash
	date      time.Time
	addr      dcrutil.Address
	amount    dcrutil.Amount
}

func printTx(accts map[uint32]string, tx *pb.TransactionDetails, date int64) {
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(bytes.NewReader(tx.Transaction))
	if err != nil {
		log.Fatal(err)
	}

	isTicket, _ := stake.IsSStx(&msgTx); if isTicket {
		fmt.Printf("found ticket %s skipping\n", msgTx.TxHash())
		return
	}
	isVote, _ := stake.IsSSGen(&msgTx); if isVote {
		fmt.Printf("found vote %s skipping\n", msgTx.TxHash())
		return
	} 
	isRevoke, _ := stake.IsSSRtx(&msgTx); if isRevoke {
		fmt.Printf("found revoke %s skipping\n", msgTx.TxHash())
		return
	}

	hash := msgTx.TxHash()
	debits := make(map[int]*pb.TransactionDetails_Input)
	credits := make(map[int]*pb.TransactionDetails_Output)
	for _, d := range tx.Debits {
		debits[int(d.Index)] = d
	}
	for _, c := range tx.Credits {
		credits[int(c.Index)] = c
	}
	var inbound bool
	for _, c := range tx.Credits {
		if !c.Internal {
			inbound = true
			break
		}
	}

	var d []detail

	if len(tx.Debits) != 0 && inbound { // outbound + inbound
		debitAcct := tx.Debits[0].PreviousAccount
		for _, d := range debits {
			if d.PreviousAccount != debitAcct {
				log.Fatalf("found multiple debit accounts for inbound+outbound tx %v", &hash)
			}
		}
		var creditAcct uint32
		var creditAddr dcrutil.Address
		var amount dcrutil.Amount
		for _, c := range credits {
			if c.Account != debitAcct && !c.Internal {
				if creditAddr != nil {
					log.Fatalf("found multiple nonchange credits for inbound+outbound tx %v", &hash)
				}
				creditAcct = c.Account
				amount = dcrutil.Amount(msgTx.TxOut[c.Index].Value)
				_, creditAddrs, _, err := txscript.ExtractPkScriptAddrs(txscript.DefaultScriptVersion, msgTx.TxOut[c.Index].PkScript, params)
				if err != nil {
					log.Fatalf("failed to decode credit address for inbound+outbound tx %v", &hash)
				}
				creditAddr = creditAddrs[0]
			}
		}
		d = []detail{{
			account:   accts[debitAcct],
			direction: "outbound",
			txHash:    &hash,
			date:      time.Unix(date, 0),
			addr:      creditAddr,
			amount:    -amount,
		}, {
			account:   accts[creditAcct],
			direction: "inbound",
			txHash:    &hash,
			date:      time.Unix(date, 0),
			addr:      creditAddr,
			amount:    amount,
		}}
	} else {
		if len(tx.Debits) != 0 { // outbound
			for i, out := range msgTx.TxOut {
				if _, ok := credits[i]; ok {
					continue
				}
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(txscript.DefaultScriptVersion, out.PkScript, params)
				fmt.Println("outbound", addrs, out.Value);
				if err != nil {
					log.Fatal(err)
				}
				d = append(d, detail{
					account:   accts[debits[0].PreviousAccount],
					direction: "outbound",
					txHash:    &hash,
					date:      time.Unix(date, 0),
					addr:      addrs[0],
					amount:    -dcrutil.Amount(out.Value),
				})
			}
		}

		if inbound {
			for i, out := range msgTx.TxOut {
				if _, ok := credits[i]; ok {
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(txscript.DefaultScriptVersion, out.PkScript, params)
					fmt.Println("inbound", addrs, out.Value);
					if err != nil {
						log.Fatal(err)
					}
					d = append(d, detail{
						account:   accts[credits[i].Account],
						direction: "inbound",
						txHash:    &hash,
						date:      time.Unix(date, 0),
						addr:      addrs[0],
						amount:    dcrutil.Amount(out.Value),
					})
				}
			}
		}
	}
/*
	for i := range d {
		//print(&d[i])
	}
	*/
}

func print(d *detail) {
	fmt.Printf("%v,%v,%v,%v,%v,%0.8f\n", d.account, d.direction, d.txHash, d.date.Format("2006-01-02"), d.addr, d.amount.ToCoin())
}
