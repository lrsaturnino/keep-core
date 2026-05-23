package libp2p

import (
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	ma "github.com/multiformats/go-multiaddr"
)

func TestMultipleAddrsPerPeer(t *testing.T) {
	var bsps []peer.AddrInfo
	for i := 0; i < 10; i++ {
		pid, err := test.RandPeerID()
		if err != nil {
			t.Fatal(err)
		}

		addr1, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/5001/p2p/%s", pid.String()))
		if err != nil {
			t.Fatal(err)
		}
		addr2, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/udp/5002/quic-v1/p2p/%s", pid.String()))
		if err != nil {
			t.Fatal(err)
		}

		bsp1Addr, err := peer.AddrInfoFromP2pAddr(addr1)
		if err != nil {
			t.Fatal(err)
		}

		bsp2Addr, err := peer.AddrInfoFromP2pAddr(addr2)
		if err != nil {
			t.Fatal(err)
		}

		bsps = append(bsps, *bsp1Addr, *bsp2Addr)
	}

	pinfos := peers.toPeerInfos(bsps)
	if len(pinfos) != len(bsps)/2 {
		t.Fatal("expected fewer peers")
	}
}
