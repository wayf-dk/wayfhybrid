package wayfhybrid

import (
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/lmdq"
	"x.config"
)

var (
	_ = log.Println
)

func TestMain(m *testing.M) {
	md.Hub = &lmdq.MDQ{MdDb: config.MdDb{Dsn: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_HUB"}}
	md.Internal = &lmdq.MDQ{MdDb: config.MdDb{Dsn: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_INTERNAL"}}
	md.ExternalSP = &lmdq.MDQ{MdDb: config.MdDb{Dsn: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_SP"}}

	for _, md := range []gosaml.Md{md.Hub, md.Internal, md.ExternalSP} {
		err := md.(*lmdq.MDQ).Open()
		if err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func TestCleanUpClaimsMap(t *testing.T) {
	const ttl = 100 * time.Millisecond
	const waitForTick = 150 * time.Millisecond

	t.Run("deletes expired claimsInfo entries", func(t *testing.T) {
		sm := &sync.Map{}
		sm.Store("expired", claimsInfo{Eol: time.Now().Add(-time.Second)})
		sm.Store("valid", claimsInfo{Eol: time.Now().Add(time.Hour)})

		cleanUpClaimsMap(sm, ttl)
		time.Sleep(waitForTick)

		if _, ok := sm.Load("expired"); ok {
			t.Error("expected expired claimsInfo to be deleted")
		}
		if _, ok := sm.Load("valid"); !ok {
			t.Error("expected valid claimsInfo to remain")
		}
	})

	t.Run("deletes expired credentialOfferInfo entries", func(t *testing.T) {
		sm := &sync.Map{}
		sm.Store("expired", credentialOfferInfo{Eol: time.Now().Add(-time.Second)})
		sm.Store("valid", credentialOfferInfo{Eol: time.Now().Add(time.Hour)})

		cleanUpClaimsMap(sm, ttl)
		time.Sleep(waitForTick)

		if _, ok := sm.Load("expired"); ok {
			t.Error("expected expired credentialOfferInfo to be deleted")
		}
		if _, ok := sm.Load("valid"); !ok {
			t.Error("expected valid credentialOfferInfo to remain")
		}
	})

	t.Run("handles mixed types, deletes only expired", func(t *testing.T) {
		sm := &sync.Map{}
		sm.Store("expired-claim", claimsInfo{Eol: time.Now().Add(-time.Second)})
		sm.Store("valid-claim", claimsInfo{Eol: time.Now().Add(time.Hour)})
		sm.Store("expired-offer", credentialOfferInfo{Eol: time.Now().Add(-time.Second)})
		sm.Store("valid-offer", credentialOfferInfo{Eol: time.Now().Add(time.Hour)})

		cleanUpClaimsMap(sm, ttl)
		time.Sleep(waitForTick)

		for _, key := range []string{"expired-claim", "expired-offer"} {
			if _, ok := sm.Load(key); ok {
				t.Errorf("expected %q to be deleted", key)
			}
		}
		for _, key := range []string{"valid-claim", "valid-offer"} {
			if _, ok := sm.Load(key); !ok {
				t.Errorf("expected %q to remain", key)
			}
		}
	})

	t.Run("ignores unknown types", func(t *testing.T) {
		sm := &sync.Map{}
		sm.Store("unknown", "some-random-string")

		cleanUpClaimsMap(sm, ttl)
		time.Sleep(waitForTick)

		if _, ok := sm.Load("unknown"); !ok {
			t.Error("expected unknown type entry to be left untouched")
		}
	})

	t.Run("entry expires between ticks", func(t *testing.T) {
		sm := &sync.Map{}
		// Expires after the first tick but before the second
		sm.Store("claim", claimsInfo{Eol: time.Now().Add(120 * time.Millisecond)})
		sm.Store("offer", credentialOfferInfo{Eol: time.Now().Add(120 * time.Millisecond)})

		cleanUpClaimsMap(sm, ttl)

		// First tick: entries not yet expired, should still be present
		time.Sleep(waitForTick)
		if _, ok := sm.Load("claim"); !ok {
			t.Error("expected claim to still exist after first tick")
		}
		if _, ok := sm.Load("offer"); !ok {
			t.Error("expected offer to still exist after first tick")
		}

		// Second tick: entries have now expired, should be gone
		time.Sleep(waitForTick)
		if _, ok := sm.Load("claim"); ok {
			t.Error("expected claim to be deleted after second tick")
		}
		if _, ok := sm.Load("offer"); ok {
			t.Error("expected offer to be deleted after second tick")
		}
	})
}
